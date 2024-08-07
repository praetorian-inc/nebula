package recongcp

import (
	"context"
	"fmt"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"github.com/praetorian-inc/nebula/internal/helpers"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
)

type GetIAMPolicy struct {
	modules.BaseModule
}

var GetIAMPolicyOptions = []*o.Option{
	o.SetRequired(o.GcpProjectIdOpt, false),
	o.SetRequired(o.GcpFolderIdOpt, false),
	o.SetRequired(o.GcpOrganizationIdOpt, false),
	o.SetDefaultValue(
		*o.SetRequired(
			o.FileNameOpt, false),
		op.DefaultFileName(GetIAMPolicyMetadata.Id)),
}

var GetIAMPolicyMetadata = modules.Metadata{
	Id:          "get-iam-policy",
	Name:        "Get Project IAM Policy",
	Description: "This module retrieves the IAM policy for a GCP project.",
	Platform:    modules.GCP,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

var GetIAMPolicyOutputProviders = []func(options []*o.Option) modules.OutputProvider{
	op.NewFileProvider,
}

func NewGetIAMPolicy(options []*o.Option, run modules.Run) (modules.Module, error) {

	projectId := o.GetOptionByName(o.GcpProjectIdOpt.Name, options).Value
	folderId := o.GetOptionByName(o.GcpFolderIdOpt.Name, options).Value
	organizationId := o.GetOptionByName(o.GcpOrganizationIdOpt.Name, options).Value

	if projectId == "" && folderId == "" && organizationId == "" {
		return nil, fmt.Errorf("must provide a project, folder, or organization ID")
	}

	return &GetIAMPolicy{
		BaseModule: modules.BaseModule{
			Metadata:        GetIAMPolicyMetadata,
			Options:         options,
			Run:             run,
			OutputProviders: modules.RenderOutputProviders(GetIAMPolicyOutputProviders, options),
		},
	}, nil
}

func (m *GetIAMPolicy) Invoke() error {
	defer close(m.Run.Data)
	ctx := context.Background()

	// TODO - this feels like it could be refactored to be more DRY
	projectId := m.GetOptionByName(o.GcpProjectIdOpt.Name).Value
	folderId := m.GetOptionByName(o.GcpFolderIdOpt.Name).Value
	organizationId := m.GetOptionByName(o.GcpOrganizationIdOpt.Name).Value

	var resource string
	var policy *iampb.Policy
	if projectId != "" {
		rm, err := resourcemanager.NewProjectsClient(ctx)
		if err != nil {
			return err
		}

		resource = fmt.Sprintf("projects/%s", projectId)
		helpers.PrintMessage(fmt.Sprintf("Getting IAM policy for resource: %s", resource))

		policy, err = rm.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
			Resource: resource,
		})
		if err != nil {
			return err
		}
	} else if folderId != "" {
		rm, err := resourcemanager.NewFoldersClient(ctx)
		if err != nil {
			return err
		}

		resource = fmt.Sprintf("folders/%s", folderId)
		helpers.PrintMessage(fmt.Sprintf("Getting IAM policy for resource: %s", resource))

		policy, err = rm.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
			Resource: resource,
		})
		if err != nil {
			return err
		}
	} else if organizationId != "" {
		rm, err := resourcemanager.NewOrganizationsClient(ctx)
		if err != nil {
			return err
		}

		resource = fmt.Sprintf("organizations/%s", organizationId)
		helpers.PrintMessage(fmt.Sprintf("Getting IAM policy for resource: %s", resource))

		policy, err = rm.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
			Resource: resource,
		})
		if err != nil {
			return err
		}
	}

	m.Run.Data <- m.MakeResult(policy)

	return nil
}
