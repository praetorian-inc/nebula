package hierarchy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/cloudresourcemanager/v1"
	cloudresourcemanagerv2 "google.golang.org/api/cloudresourcemanager/v2"
)

// FILE INFO:
// GcpOrganizationLister - list all organizations
// GcpOrgInfoLink - get info of a single organization, Process(orgName string)
// GcpOrgFolderListLink - list all folders in an organization, Process(resource tab.GCPResource); needs organization
// GcpOrgProjectListLink - list all projects in an organization, Process(resource tab.GCPResource); needs organization

type GcpOrganizationLister struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanager.Service
}

// creates a link to list all organizations
func NewGcpOrganizationLister(configs ...cfg.Config) chain.Link {
	g := &GcpOrganizationLister{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpOrganizationLister) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}
	return nil
}

func (g *GcpOrganizationLister) Process() error {
	// no resource input (meant to be non-contextual)
	searchReq := g.resourceManagerService.Organizations.Search(&cloudresourcemanager.SearchOrganizationsRequest{})
	resp, err := searchReq.Do()
	if err != nil {
		return fmt.Errorf("failed to search organizations: %w", err)
	}
	if len(resp.Organizations) == 0 {
		return nil
	}
	for _, org := range resp.Organizations {
		gcpOrg, err := createGcpOrgResource(org)
		if err != nil {
			slog.Error("Failed to create GCP organization resource", "error", err, "org", org.Name)
			continue
		}
		g.Send(gcpOrg)
	}
	return nil
}

type GcpOrgInfoLink struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanager.Service
}

// creates a link to get info of a single organization
func NewGcpOrgInfoLink(configs ...cfg.Config) chain.Link {
	g := &GcpOrgInfoLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpOrgInfoLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpOrg(),
	)
	return params
}

func (g *GcpOrgInfoLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}
	return nil
}

func (g *GcpOrgInfoLink) Process(orgName string) error {
	if !strings.HasPrefix(orgName, "organizations/") {
		orgName = "organizations/" + orgName
	}
	org, err := g.resourceManagerService.Organizations.Get(orgName).Do()
	if err != nil {
		return fmt.Errorf("failed to get organization %s: %w", orgName, err)
	}
	gcpOrg, err := createGcpOrgResource(org)
	if err != nil {
		return err
	}
	g.Send(gcpOrg)
	return nil
}

type GcpOrgFolderListLink struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanager.Service
}

// creates a link to list all folders in an organization
func NewGcpOrgFolderListLink(configs ...cfg.Config) chain.Link {
	g := &GcpOrgFolderListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpOrgFolderListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}
	return nil
}

func (g *GcpOrgFolderListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceOrganization {
		return nil
	}
	orgName := "organizations/" + resource.Name
	v2Service, err := cloudresourcemanagerv2.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create v2 resource manager service: %w", err)
	}
	err = traverseFolders(orgName, v2Service, func(folder *cloudresourcemanagerv2.Folder) error {
		gcpFolder, err := createGcpFolderResource(folder)
		if err != nil {
			slog.Error("Failed to create GCP folder resource", "error", err, "folder", folder.Name)
			return nil // continue processing other folders
		}
		g.Send(gcpFolder)
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list folders in organization %s: %w", orgName, err)
	}
	return nil
}

type GcpOrgProjectListLink struct {
	*base.GcpBaseLink
	resourceManagerService *cloudresourcemanager.Service
	IncludeSysProjects     bool
}

// creates a link to list all projects in an organization
func NewGcpOrgProjectListLink(configs ...cfg.Config) chain.Link {
	g := &GcpOrgProjectListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpOrgProjectListLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpIncludeSysProjects(),
	)
	return params
}

func (g *GcpOrgProjectListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.resourceManagerService, err = cloudresourcemanager.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create resource manager service: %w", err)
	}
	includeSysProjects, err := cfg.As[bool](g.Arg("include-sys-projects"))
	if err != nil {
		return fmt.Errorf("failed to get include-sys-projects: %w", err)
	}
	g.IncludeSysProjects = includeSysProjects
	return nil
}

func (g *GcpOrgProjectListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceOrganization {
		return nil
	}
	orgID := resource.Name
	listReq := g.resourceManagerService.Projects.List() // .Filter(fmt.Sprintf("parent.id:%s", orgID))

	// list all projects under any parent
	err := listReq.Pages(context.Background(), func(page *cloudresourcemanager.ListProjectsResponse) error {
		for _, project := range page.Projects {
			if !g.IncludeSysProjects && isSysProject(project) {
				continue
			}
			gcpProject, err := createGcpProjectResource(project)
			if err != nil {
				slog.Error("Failed to create GCP project resource", "error", err, "projectId", project.ProjectId)
				continue
			}
			g.Send(gcpProject)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to list projects in organization %s: %w", orgID, err)
	}
	return nil

	// TODO: check the need for this recursion (probably not needed)

	// // list only projects directly under organization
	// err = listReq.Pages(context.Background(), func(page *cloudresourcemanager.ListProjectsResponse) error {
	// 	for _, project := range page.Projects {
	// 		if g.FilterSysProjects && isSysProject(project) {
	// 			continue
	// 		}
	// 		gcpProject, err := createGcpProjectResource(project)
	// 		if err != nil {
	// 			slog.Error("Failed to create GCP project resource", "error", err, "projectId", project.ProjectId)
	// 			continue
	// 		}
	// 		g.Send(gcpProject)
	// 	}
	// 	return nil
	// })
	// if err != nil {
	// 	slog.Warn("Failed to list projects directly under organization", "orgID", orgID, "error", err)
	// }

	// // list projects in all folders under organization
	// v2Service, err := cloudresourcemanagerv2.NewService(context.Background(), g.ClientOptions...)
	// if err != nil {
	// 	return fmt.Errorf("failed to create v2 resource manager service: %w", err)
	// }
	// folders, err := listAllFolders("organizations/"+orgID, v2Service)
	// if err != nil {
	// 	slog.Warn("Error during folder traversal", "orgID", orgID, "error", err)
	// }
	// for _, folderPath := range folders {
	// 	folderID := strings.TrimPrefix(folderPath, "folders/") // strip "folders/" to get folder ID
	// 	folderListReq := g.resourceManagerService.Projects.List().Filter(fmt.Sprintf("parent.id:%s", folderID))
	// 	err := folderListReq.Pages(context.Background(), func(page *cloudresourcemanager.ListProjectsResponse) error {
	// 		for _, project := range page.Projects {
	// 			if g.FilterSysProjects && isSysProject(project) {
	// 				continue
	// 			}
	// 			gcpProject, err := createGcpProjectResource(project)
	// 			if err != nil {
	// 				slog.Error("Failed to create GCP project resource", "error", err, "projectId", project.ProjectId)
	// 				continue
	// 			}
	// 			g.Send(gcpProject)
	// 		}
	// 		return nil
	// 	})
	// 	if err != nil {
	// 		slog.Warn("Failed to list projects in folder", "folder", folderPath, "error", err)
	// 	}
	// }

	// return nil
}

// ---------------------------------------------------------------------------------------------------------------------
// helper functions

func createGcpOrgResource(org *cloudresourcemanager.Organization) (*tab.GCPResource, error) {
	gcpOrg, err := tab.NewGCPResource(
		strings.Split(org.Name, "/")[1], // resource name
		org.Name,                        // accountRef (self)
		tab.GCPResourceOrganization,     // resource type
		linkPostProcessOrg(org),         // properties
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP organization resource: %w", err)
	}
	gcpOrg.DisplayName = org.DisplayName
	return &gcpOrg, nil
}

func linkPostProcessFolder(folder *cloudresourcemanagerv2.Folder) map[string]any {
	properties := map[string]any{
		"resourceName":   folder.ManagementProject,
		"lifecycleState": folder.LifecycleState,
	}
	return properties
}

func linkPostProcessOrg(org *cloudresourcemanager.Organization) map[string]any {
	properties := map[string]any{
		"lifecycleState": org.LifecycleState,
		"owner":          org.Owner.DirectoryCustomerId,
	}
	return properties
}

func isSysProject(project *cloudresourcemanager.Project) bool {
	sysPatterns := []string{
		"sys-",
		"script-editor-",
		"apps-script-",
		"system-",      // potentially worth removing
		"firebase-",    // potentially worth removing
		"cloud-build-", // potentially worth removing
		"gcf-",         // potentially worth removing
		"gae-",         // potentially worth removing
	}
	projectId := strings.ToLower(project.ProjectId)
	projectName := strings.ToLower(project.Name)
	for _, pattern := range sysPatterns {
		if strings.HasPrefix(projectId, pattern) || strings.HasPrefix(projectName, pattern) {
			return true
		}
	}
	return false
}

// generic helper to traverse folders with a callback function
func traverseFolders(parent string, v2Service *cloudresourcemanagerv2.Service, callback func(*cloudresourcemanagerv2.Folder) error) error {
	listReq := v2Service.Folders.List().Parent(parent)
	err := listReq.Pages(context.Background(), func(page *cloudresourcemanagerv2.ListFoldersResponse) error {
		for _, folder := range page.Folders {
			if err := callback(folder); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

// TODO: remove this function (probably not needed)
// list all folders recursively under a parent
func listAllFolders(parent string, v2Service *cloudresourcemanagerv2.Service) ([]string, error) {
	var allFolders []string
	err := traverseFolders(parent, v2Service, func(folder *cloudresourcemanagerv2.Folder) error {
		allFolders = append(allFolders, folder.Name)
		subfolders, err := listAllFolders(folder.Name, v2Service)
		if err != nil {
			slog.Warn("Failed to list subfolders", "parent", folder.Name, "error", err)
		} else {
			allFolders = append(allFolders, subfolders...)
		}
		return nil
	})
	return allFolders, err
}
