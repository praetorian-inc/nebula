package s3

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	nebulatypes "github.com/praetorian-inc/nebula/pkg/types"
)

// S3SecretsConfig configures secrets scanning for S3 objects
type S3SecretsConfig struct {
	MaxObjectSize   int64         // Maximum object size to scan (bytes)
	SkipExtensions  []string      // File extensions to skip
	ExcludePatterns []string      // Path patterns to exclude
	MaxAge          time.Duration // Only scan objects modified within this duration (0 = no limit)
}

// AWSS3BucketSecrets scans S3 objects for secrets
type AWSS3BucketSecrets struct {
	*base.AwsReconLink
	config S3SecretsConfig
}

// Default configuration values
var (
	defaultSkipExtensions = []string{
		// Archives
		".zip", ".tar", ".tar.gz", ".gz", ".7z", ".rar", ".bz2",
		// Binaries
		".exe", ".dll", ".so", ".dylib", ".jar",
		// Images
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp",
		// Video
		".mp4", ".mkv", ".avi", ".mov", ".flv", ".wmv",
		// Audio
		".mp3", ".flac", ".wav", ".ogg", ".aac",
		// Fonts
		".ttf", ".otf", ".woff", ".woff2",
		// Lock files
		".lock",
	}

	defaultExcludePatterns = []string{
		"/node_modules/",
		"/vendor/",
		"/.git/",
		"/test-data/",
		"/tmp/",
		"/__pycache__/",
	}
)

// NewAWSS3BucketSecrets creates a new S3 secrets scanner link
func NewAWSS3BucketSecrets(configs ...cfg.Config) chain.Link {
	link := &AWSS3BucketSecrets{
		config: S3SecretsConfig{
			MaxObjectSize:   100 * 1024 * 1024, // 100MB default
			SkipExtensions:  defaultSkipExtensions,
			ExcludePatterns: defaultExcludePatterns,
			MaxAge:          0, // No age limit by default
		},
	}
	link.AwsReconLink = base.NewAwsReconLink(link, configs...)
	return link
}

// getBucketRegion determines the actual region of an S3 bucket using GetBucketLocation API.
// CloudControl may report incorrect regions for S3 buckets, causing 301 redirects.
// Returns "us-east-1" if LocationConstraint is empty (which indicates us-east-1).
func (s *AWSS3BucketSecrets) getBucketRegion(ctx context.Context, client *s3.Client, bucketName string) (string, error) {
	resp, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get bucket location: %w", err)
	}

	// LocationConstraint is empty for us-east-1 buckets (AWS quirk)
	if resp.LocationConstraint == "" {
		return "us-east-1", nil
	}

	return string(resp.LocationConstraint), nil
}

// Process implements the Link interface
func (s *AWSS3BucketSecrets) Process(resource *nebulatypes.EnrichedResourceDescription) error {
	if resource.TypeName != "AWS::S3::Bucket" {
		slog.Debug("Skipping non-S3 bucket resource", "resource", resource.TypeName)
		return nil
	}

	// Extract bucket name from resource (use Identifier which contains the bucket name)
	bucketName := resource.Identifier
	if bucketName == "" {
		return fmt.Errorf("bucket name is empty")
	}

	ctx := context.Background()

	// Get initial AWS config with CloudControl-reported region
	// This is needed to call GetBucketLocation API
	initialRegion := resource.Region
	if initialRegion == "" {
		initialRegion = "us-east-1" // Default fallback
	}

	awsConfig, err := s.GetConfigWithRuntimeArgs(initialRegion)
	if err != nil {
		return fmt.Errorf("failed to get AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsConfig)

	// Determine actual bucket region (CloudControl may report wrong region for S3)
	actualRegion, err := s.getBucketRegion(ctx, client, bucketName)
	if err != nil {
		return fmt.Errorf("failed to determine bucket region: %w", err)
	}

	slog.Debug("Determined bucket region",
		"bucket", bucketName,
		"cloudcontrol_region", resource.Region,
		"actual_region", actualRegion)

	// If region differs, recreate client with correct region
	if actualRegion != initialRegion {
		awsConfig, err = s.GetConfigWithRuntimeArgs(actualRegion)
		if err != nil {
			return fmt.Errorf("failed to get AWS config for region %s: %w", actualRegion, err)
		}
		client = s3.NewFromConfig(awsConfig)
	}

	// Update resource region for accurate provenance in scan results
	resource.Region = actualRegion

	// Log bucket scan start with actual region
	slog.Debug("Starting S3 bucket scan",
		"bucket", bucketName,
		"region", actualRegion,
		"account", resource.AccountId)

	// Create paginator for listing objects
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})

	// Track scan progress
	var scannedCount, skippedCount int64

	// Iterate through pages
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("failed to list objects: %w", err)
		}

		// Process objects in page
		for _, obj := range page.Contents {
			scanned, err := s.processObject(ctx, client, bucketName, obj, resource)
			if err != nil {
				slog.Warn("Failed to process object", "error", err, "key", aws.ToString(obj.Key))
				skippedCount++
				continue
			}

			if scanned {
				scannedCount++
			} else {
				skippedCount++
			}

			// Log progress every 100 objects
			totalProcessed := scannedCount + skippedCount
			if totalProcessed > 0 && totalProcessed%100 == 0 {
				slog.Debug("S3 scan progress",
					"bucket", bucketName,
					"processed", totalProcessed,
					"scanned", scannedCount,
					"skipped", skippedCount)
			}
		}
	}

	// Log completion with statistics
	totalProcessed := scannedCount + skippedCount
	skipPercentage := 0.0
	if totalProcessed > 0 {
		skipPercentage = float64(skippedCount) / float64(totalProcessed) * 100
	}

	slog.Info("S3 bucket scan complete",
		"bucket", bucketName,
		"total_objects", totalProcessed,
		"scanned", scannedCount,
		"skipped", skippedCount,
		"skip_percentage", fmt.Sprintf("%.1f%%", skipPercentage))

	return nil
}

func (s *AWSS3BucketSecrets) processObject(
	ctx context.Context,
	client *s3.Client,
	bucket string,
	obj s3types.Object,
	resource *nebulatypes.EnrichedResourceDescription,
) (bool, error) {
	// Tier 2: Metadata filtering
	if !s.shouldScanObject(obj) {
		return false, nil
	}

	// Tier 3: Binary detection (download first 512 bytes)
	if s.isBinaryObject(ctx, client, bucket, obj) {
		if obj.Key != nil {
			slog.Debug("Skipping object", "key", *obj.Key, "reason", "binary content detected")
		}
		return false, nil
	}

	// Tier 4: Full download
	content, err := s.downloadObject(ctx, client, bucket, obj)
	if err != nil {
		return false, fmt.Errorf("failed to download object: %w", err)
	}

	// Generate NPInput and send to NoseyParker
	if err := s.sendToNoseyParker(bucket, obj, content, resource); err != nil {
		return false, fmt.Errorf("failed to scan with NoseyParker: %w", err)
	}

	return true, nil
}

// shouldScanObject checks if an object should be scanned based on metadata
func (s *AWSS3BucketSecrets) shouldScanObject(obj s3types.Object) bool {
	// Check size
	if obj.Size == nil {
		slog.Debug("Skipping object", "key", aws.ToString(obj.Key), "reason", "nil size")
		return false
	}
	if *obj.Size > s.config.MaxObjectSize {
		slog.Debug("Skipping object", "key", aws.ToString(obj.Key), "reason", "exceeds size limit", "size", *obj.Size)
		return false
	}
	if *obj.Size == 0 {
		slog.Debug("Skipping object", "key", aws.ToString(obj.Key), "reason", "empty file", "size", 0)
		return false
	}

	// Check age (if configured)
	if s.config.MaxAge > 0 && obj.LastModified != nil {
		if time.Since(*obj.LastModified) > s.config.MaxAge {
			slog.Debug("Skipping object", "key", aws.ToString(obj.Key), "reason", "exceeds max age", "age", time.Since(*obj.LastModified))
			return false
		}
	}

	// Check extension
	if obj.Key != nil {
		ext := strings.ToLower(filepath.Ext(*obj.Key))
		for _, skipExt := range s.config.SkipExtensions {
			if ext == skipExt {
				slog.Debug("Skipping object", "key", *obj.Key, "reason", "binary extension", "ext", ext)
				return false
			}
		}

		// Check path exclusions
		for _, pattern := range s.config.ExcludePatterns {
			if strings.Contains(*obj.Key, pattern) {
				slog.Debug("Skipping object", "key", *obj.Key, "reason", "excluded path", "pattern", pattern)
				return false
			}
		}

		// Skip directory markers
		if strings.HasSuffix(*obj.Key, "/") {
			slog.Debug("Skipping object", "key", *obj.Key, "reason", "directory marker")
			return false
		}
	}

	return true
}

func (s *AWSS3BucketSecrets) isBinaryObject(ctx context.Context, client *s3.Client, bucket string, obj s3types.Object) bool {
	if obj.Key == nil {
		return false
	}

	// Download first 512 bytes for magic number check
	rangeResp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    obj.Key,
		Range:  aws.String("bytes=0-511"),
	})
	if err != nil {
		slog.Warn("Failed to check binary status", "error", err, "key", *obj.Key)
		return false // Assume not binary if check fails
	}
	defer rangeResp.Body.Close()

	header := make([]byte, 512)
	n, _ := io.ReadFull(rangeResp.Body, header)
	if n == 0 {
		return false
	}

	return isBinaryFile(header[:n])
}

func (s *AWSS3BucketSecrets) downloadObject(ctx context.Context, client *s3.Client, bucket string, obj s3types.Object) ([]byte, error) {
	if obj.Key == nil {
		return nil, fmt.Errorf("object key is nil")
	}

	resp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    obj.Key,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func (s *AWSS3BucketSecrets) sendToNoseyParker(
	bucket string,
	obj s3types.Object,
	content []byte,
	resource *nebulatypes.EnrichedResourceDescription,
) error {
	if obj.Key == nil {
		return fmt.Errorf("object key is nil")
	}

	// Check if content is binary
	var npInput jtypes.NPInput
	if isBinaryFile(content) {
		npInput = jtypes.NPInput{
			ContentBase64: base64.StdEncoding.EncodeToString(content),
			Provenance: jtypes.NPProvenance{
				Kind:         "file",
				Platform:     "aws",
				ResourceType: "AWS::S3::Object",
				ResourceID:   fmt.Sprintf("%s/%s", bucket, *obj.Key),
				Region:       resource.Region,
				AccountID:    resource.AccountId,
				RepoPath:     fmt.Sprintf("s3://%s/%s", bucket, *obj.Key),
			},
		}
	} else {
		npInput = jtypes.NPInput{
			Content: string(content),
			Provenance: jtypes.NPProvenance{
				Kind:         "file",
				Platform:     "aws",
				ResourceType: "AWS::S3::Object",
				ResourceID:   fmt.Sprintf("%s/%s", bucket, *obj.Key),
				Region:       resource.Region,
				AccountID:    resource.AccountId,
				RepoPath:     fmt.Sprintf("s3://%s/%s", bucket, *obj.Key),
			},
		}
	}

	return s.Send(npInput)
}

// isBinaryFile checks if content is binary based on magic numbers
func isBinaryFile(header []byte) bool {
	// Check for null bytes (simple heuristic)
	for _, b := range header {
		if b == 0x00 {
			return true
		}
	}

	// Check common binary magic numbers
	magicNumbers := [][]byte{
		{0xFF, 0xD8, 0xFF},       // JPEG
		{0x50, 0x4B, 0x03, 0x04}, // ZIP
		{0x7F, 0x45, 0x4C, 0x46}, // ELF
		{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, // PNG
		{0x47, 0x49, 0x46, 0x38}, // GIF
		{0x25, 0x50, 0x44, 0x46}, // PDF
		{0x1F, 0x8B, 0x08},       // GZIP
	}

	for _, magic := range magicNumbers {
		if len(header) >= len(magic) && bytes.HasPrefix(header, magic) {
			return true
		}
	}

	return false
}
