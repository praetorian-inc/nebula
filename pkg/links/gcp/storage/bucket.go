package storage

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/utils"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/storage/v1"
)

// FILE INFO:
// GcpStorageBucketInfoLink - get info of a single storage bucket, Process(bucketName string); needs project
// GcpStorageBucketListLink - list all storage buckets in a project, Process(resource tab.GCPResource); needs project
// GcpStorageObjectListLink - list all objects in a storage bucket, Process(resource tab.GCPResource); needs project
// GcpStorageObjectSecretsLink - extract and scan objects for secrets, Process(object *GcpStorageObjectRef); needs project

type GcpStorageBucketInfoLink struct {
	*base.GcpBaseLink
	storageService *storage.Service
	ProjectId      string
}

// creates a link to get info of a single storage bucket
func NewGcpStorageBucketInfoLink(configs ...cfg.Config) chain.Link {
	g := &GcpStorageBucketInfoLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpStorageBucketInfoLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpProject(),
	)
	return params
}

func (g *GcpStorageBucketInfoLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.storageService, err = storage.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create storage service: %w", err)
	}
	projectId, err := cfg.As[string](g.Arg("project"))
	if err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}
	g.ProjectId = projectId
	return nil
}

func (g *GcpStorageBucketInfoLink) Process(bucketName string) error {
	bucket, err := g.storageService.Buckets.Get(bucketName).Do()
	if err != nil {
		return utils.HandleGcpError(err, "failed to get bucket")
	}
	gcpBucket, err := tab.NewGCPResource(
		bucket.Name,                   // resource name (bucket name)
		g.ProjectId,                   // accountRef (project ID)
		tab.GCPResourceBucket,         // resource type
		linkPostProcessBucket(bucket), // properties
	)
	if err != nil {
		slog.Error("Failed to create GCP bucket resource", "error", err, "bucket", bucket.Name)
		return err
	}
	g.Send(gcpBucket)
	return nil
}

type GcpStorageBucketListLink struct {
	*base.GcpBaseLink
	storageService *storage.Service
	iamService     *iam.Service
}

// creates a link to list all storage buckets in a project
func NewGcpStorageBucketListLink(configs ...cfg.Config) chain.Link {
	g := &GcpStorageBucketListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpStorageBucketListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.storageService, err = storage.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create storage service: %w", err)
	}
	g.iamService, err = iam.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create iam service: %w", err)
	}
	return nil
}

func (g *GcpStorageBucketListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	listReq := g.storageService.Buckets.List(projectId)
	buckets, err := listReq.Do()
	if err != nil {
		return utils.HandleGcpError(err, "failed to list buckets in project")
	}
	for _, bucket := range buckets.Items {
		properties := linkPostProcessBucket(bucket)

		// Check IAM policy for anonymous access
		policy, policyErr := g.storageService.Buckets.GetIamPolicy(bucket.Name).Do()
		if policyErr == nil && policy != nil {
			anonymousInfo := checkStorageAnonymousAccess(policy)

			// Also check ACL for legacy public access
			acl, aclErr := g.storageService.BucketAccessControls.List(bucket.Name).Do()
			if aclErr == nil {
				checkStorageACLForPublicAccess(&anonymousInfo, acl)
			} else {
				slog.Debug("Failed to get ACL for bucket", "bucket", bucket.Name, "error", aclErr)
			}

			if anonymousInfo.TotalPublicBindings > 0 {
				properties["anonymousAccessInfo"] = anonymousInfo
				properties["riskLevel"] = calculateRiskLevel(anonymousInfo)
			}
		} else {
			slog.Debug("Failed to get IAM policy for bucket", "bucket", bucket.Name, "error", policyErr)
		}

		gcpBucket, err := tab.NewGCPResource(
			bucket.Name,           // resource name (bucket name)
			projectId,             // accountRef (project ID)
			tab.GCPResourceBucket, // resource type
			properties,            // properties (with anonymous access info)
		)
		if err != nil {
			slog.Error("Failed to create GCP bucket resource", "error", err, "bucket", bucket.Name)
			continue
		}
		g.Send(gcpBucket)
	}
	return nil
}

type GcpStorageObjectRef struct {
	BucketName string
	ObjectName string
	ProjectId  string
	Object     *storage.Object
}

type GcpStorageObjectListLink struct {
	*base.GcpBaseLink
	storageService *storage.Service
}

// creates a link to list all objects in a storage bucket
func NewGcpStorageObjectListLink(configs ...cfg.Config) chain.Link {
	g := &GcpStorageObjectListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpStorageObjectListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.storageService, err = storage.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create storage service: %w", err)
	}
	return nil
}

func (g *GcpStorageObjectListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceBucket {
		return nil
	}
	bucketName := resource.Name
	projectId := resource.AccountRef
	listReq := g.storageService.Objects.List(bucketName)
	for {
		objects, err := listReq.Do()
		if err != nil {
			return utils.HandleGcpError(err, fmt.Sprintf("failed to list objects in bucket %s", bucketName))
		}
		for _, obj := range objects.Items {
			objRef := &GcpStorageObjectRef{
				BucketName: bucketName,
				ObjectName: obj.Name,
				ProjectId:  projectId,
				Object:     obj,
			}
			if err := g.Send(objRef); err != nil {
				slog.Error("Failed to send object reference", "error", err, "bucket", bucketName, "object", obj.Name)
				continue
			}
		}
		if objects.NextPageToken == "" {
			break
		}
		listReq.PageToken(objects.NextPageToken)
	}
	return nil
}

type GcpStorageObjectSecretsLink struct {
	*base.GcpBaseLink
	storageService *storage.Service
	maxFileSize    int64
}

// creates a link to extract and scan storage objects for secrets
func NewGcpStorageObjectSecretsLink(configs ...cfg.Config) chain.Link {
	g := &GcpStorageObjectSecretsLink{
		maxFileSize: 10 * 1024 * 1024, // 10MB default limit
	}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpStorageObjectSecretsLink) Params() []cfg.Param {
	return append(g.GcpBaseLink.Params(),
		cfg.NewParam[int64]("max-file-size", "Maximum file size to scan for secrets (bytes)").WithDefault(10*1024*1024),
	)
}

func (g *GcpStorageObjectSecretsLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.storageService, err = storage.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create storage service: %w", err)
	}
	if maxSize, err := cfg.As[int64](g.Arg("max-file-size")); err == nil {
		g.maxFileSize = maxSize
	}
	return nil
}

func (g *GcpStorageObjectSecretsLink) Process(objRef *GcpStorageObjectRef) error {
	if objRef.Object.Size > uint64(g.maxFileSize) {
		slog.Debug("Skipping large object", "bucket", objRef.BucketName, "object", objRef.ObjectName, "size", objRef.Object.Size)
		return nil
	}
	if g.isSkippableFile(objRef.ObjectName) {
		slog.Debug("Skipping binary file", "bucket", objRef.BucketName, "object", objRef.ObjectName)
		return nil
	}
	getReq := g.storageService.Objects.Get(objRef.BucketName, objRef.ObjectName)
	resp, err := getReq.Download()
	if err != nil {
		return utils.HandleGcpError(err, fmt.Sprintf("failed to download object %s from bucket %s", objRef.ObjectName, objRef.BucketName))
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read object content: %w", err)
	}
	var npInput types.NPInput
	if g.isBinaryContent(content) {
		npInput = types.NPInput{
			ContentBase64: base64.StdEncoding.EncodeToString(content),
			Provenance: types.NPProvenance{
				Kind:         "file",
				Platform:     "gcp",
				ResourceType: "storage.googleapis.com/Object",
				ResourceID:   fmt.Sprintf("%s/%s", objRef.BucketName, objRef.ObjectName),
				Region:       objRef.Object.Bucket, // GCS doesn't have regional buckets like this, but we'll use bucket name
				AccountID:    objRef.ProjectId,
				RepoPath:     fmt.Sprintf("gs://%s/%s", objRef.BucketName, objRef.ObjectName),
			},
		}
	} else {
		npInput = types.NPInput{
			Content: string(content),
			Provenance: types.NPProvenance{
				Kind:         "file",
				Platform:     "gcp",
				ResourceType: "storage.googleapis.com/Object",
				ResourceID:   fmt.Sprintf("%s/%s", objRef.BucketName, objRef.ObjectName),
				Region:       objRef.Object.Bucket,
				AccountID:    objRef.ProjectId,
				RepoPath:     fmt.Sprintf("gs://%s/%s", objRef.BucketName, objRef.ObjectName),
			},
		}
	}
	return g.Send(npInput)
}

// ---------------------------------------------------------------------------------------------------------------------
// helper functions

// AnonymousAccessInfo represents anonymous access configuration for a resource
type AnonymousAccessInfo struct {
	HasAllUsers                bool     `json:"hasAllUsers"`
	HasAllAuthenticatedUsers   bool     `json:"hasAllAuthenticatedUsers"`
	AllUsersRoles             []string `json:"allUsersRoles"`
	AllAuthenticatedUsersRoles []string `json:"allAuthenticatedUsersRoles"`
	TotalPublicBindings       int      `json:"totalPublicBindings"`
	AccessMethods             []string `json:"accessMethods"`
}

// checkStorageAnonymousAccess checks if a storage bucket has anonymous access via IAM
func checkStorageAnonymousAccess(policy *storage.Policy) AnonymousAccessInfo {
	info := AnonymousAccessInfo{
		AllUsersRoles:             []string{},
		AllAuthenticatedUsersRoles: []string{},
		AccessMethods:             []string{},
	}

	if policy == nil || len(policy.Bindings) == 0 {
		return info
	}

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if member == "allUsers" {
				info.HasAllUsers = true
				info.AllUsersRoles = append(info.AllUsersRoles, binding.Role)
				info.TotalPublicBindings++
			} else if member == "allAuthenticatedUsers" {
				info.HasAllAuthenticatedUsers = true
				info.AllAuthenticatedUsersRoles = append(info.AllAuthenticatedUsersRoles, binding.Role)
				info.TotalPublicBindings++
			}
		}
	}

	if info.TotalPublicBindings > 0 {
		info.AccessMethods = append(info.AccessMethods, "IAM")
	}

	return info
}

// checkStorageACLForPublicAccess checks bucket ACLs for public access
func checkStorageACLForPublicAccess(info *AnonymousAccessInfo, acl *storage.BucketAccessControls) {
	if acl == nil || len(acl.Items) == 0 {
		return
	}

	for _, aclEntry := range acl.Items {
		if aclEntry.Entity == "allUsers" {
			info.HasAllUsers = true
			// Convert ACL role to IAM-style role name for consistency
			role := fmt.Sprintf("roles/storage.%s", aclEntry.Role)
			if !contains(info.AllUsersRoles, role) {
				info.AllUsersRoles = append(info.AllUsersRoles, role)
				info.TotalPublicBindings++
			}
		} else if aclEntry.Entity == "allAuthenticatedUsers" {
			info.HasAllAuthenticatedUsers = true
			role := fmt.Sprintf("roles/storage.%s", aclEntry.Role)
			if !contains(info.AllAuthenticatedUsersRoles, role) {
				info.AllAuthenticatedUsersRoles = append(info.AllAuthenticatedUsersRoles, role)
				info.TotalPublicBindings++
			}
		}
	}

	// Update access methods if ACL access found
	if info.TotalPublicBindings > 0 && !contains(info.AccessMethods, "ACL") {
		info.AccessMethods = append(info.AccessMethods, "ACL")
	}
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// calculateRiskLevel determines risk level based on anonymous access info
func calculateRiskLevel(info AnonymousAccessInfo) string {
	if info.HasAllUsers {
		return "critical"
	} else if info.HasAllAuthenticatedUsers {
		return "high"
	}
	return "low"
}

func linkPostProcessBucket(bucket *storage.Bucket) map[string]any {
	properties := map[string]any{
		"name":                   bucket.Name,
		"id":                     bucket.Id,
		"location":               bucket.Location,
		"selfLink":               bucket.SelfLink,
		"gsUtilURL":              fmt.Sprintf("gs://%s", bucket.Name),
		"publicURL":              fmt.Sprintf("https://storage.googleapis.com/%s", bucket.Name), // also <bucket-name>.storage.googleapis.com
		"labels":                 bucket.Labels,
		"publicAccessPrevention": bucket.IamConfiguration.PublicAccessPrevention,
	}
	if bucket.IamConfiguration != nil && bucket.IamConfiguration.PublicAccessPrevention == "inherited" {
		properties["publicAccessPrevention"] = false
	} else {
		properties["publicAccessPrevention"] = true
	}
	return properties
}

// doing this for heurestic purposes, np might already be removing
func (g *GcpStorageObjectSecretsLink) isSkippableFile(filename string) bool {
	binaryExtensions := []string{
		".exe", ".dll", ".so", ".dylib", ".bin", ".jar", ".war", ".ear",
		".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp",
		".mp3", ".wav", ".mp4", ".avi", ".mov", ".mkv",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".iso", ".dmg", ".img",
	}

	lowerFilename := strings.ToLower(filename)
	for _, ext := range binaryExtensions {
		if strings.HasSuffix(lowerFilename, ext) {
			return true
		}
	}
	return false
}

func (g *GcpStorageObjectSecretsLink) isBinaryContent(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	for i := 0; i < len(content) && i < 512; i++ {
		if content[i] == 0 {
			return true
		}
	}
	return false
}
