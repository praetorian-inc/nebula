package recongcp

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"github.com/praetorian-inc/nebula/internal/helpers"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
	"google.golang.org/api/cloudresourcemanager/v1"
)

type GetProjects struct {
	modules.BaseModule
}

var GetProjectsOptions = []*o.Option{
	o.SetDefaultValue(
		*o.SetRequired(
			o.FileNameOpt, false),
		op.DefaultFileName(GetProjectsMetadata.Id)),
}

var GetProjectsOutputProviders = []func(options []*o.Option) modules.OutputProvider{
	op.NewConsoleProvider,
	op.NewFileProvider,
}

var GetProjectsMetadata = modules.Metadata{
	Id:          "get-projects",
	Name:        "Get Projects",
	Description: "This module retrieves all GCP projects.",
	Platform:    modules.GCP,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

func NewGetProjects(options []*o.Option, run modules.Run) (modules.Module, error) {
	for _, option := range options {
		fmt.Println(option)
	}

	var gp = &GetProjects{
		BaseModule: modules.BaseModule{
			Metadata:        GetProjectsMetadata,
			Run:             run,
			Options:         options,
			OutputProviders: modules.RenderOutputProviders(GetProjectsOutputProviders, options),
		},
	}
	return gp, nil
}

func (m *GetProjects) Invoke() error {
	defer close(m.Run.Data)
	ctx := context.Background()
	cloudResourceManagerService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		log.Fatalf("Failed to create cloud resource manager service: %v", err)
	}

	helpers.PrintMessage(m.Id)
	projects := make([]*cloudresourcemanager.Project, 0)
	req := cloudResourceManagerService.Projects.List()
	err = req.Pages(ctx, func(page *cloudresourcemanager.ListProjectsResponse) error {
		projects = append(projects, page.Projects...)
		return nil
	})
	if err != nil {
		log.Fatalf("Failed to list projects: %v", err)
	}

	helpers.PrintMessage("Found " + strconv.Itoa(len(projects)) + " projects")
	m.Run.Data <- m.MakeResult(projects)

	return nil
}
