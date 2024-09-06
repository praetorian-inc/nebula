package recongcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	admin "cloud.google.com/go/iam/admin/apiv1"
	iampb "cloud.google.com/go/iam/admin/apiv1/adminpb"
	"github.com/praetorian-inc/nebula/internal/helpers"
	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
)

type GetServiceAccounts struct {
	modules.BaseModule
}

var GetServiceAccountsOptions = []*o.Option{
	&o.GcpProjectIdOpt,
	o.SetDefaultValue(
		*o.SetRequired(
			o.FileNameOpt, false),
		op.DefaultFileName(GetServiceAccountsMetadata.Id)),
}

var GetServiceAccountsOutputProviders = []func(options []*o.Option) modules.OutputProvider{
	op.NewFileProvider,
}

var GetServiceAccountsMetadata = modules.Metadata{
	Id:          "get-service-accounts",
	Name:        "Get Service Accounts",
	Description: "This module retrieves the service accounts for a GCP project.",
	Platform:    modules.GCP,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Moderate,
	References:  []string{},
}

func NewGetServiceAccounts(options []*o.Option, run modules.Run) (modules.Module, error) {
	return &GetServiceAccounts{
		BaseModule: modules.BaseModule{
			Metadata:        GetServiceAccountsMetadata,
			Run:             run,
			Options:         options,
			OutputProviders: modules.RenderOutputProviders(GetServiceAccountsOutputProviders, options),
		},
	}, nil
}

func (m *GetServiceAccounts) Invoke() error {
	defer close(m.Run.Data)
	ctx := context.Background()

	// Create an IAM admin client
	client, err := admin.NewIamClient(ctx)
	if err != nil {
		return fmt.Errorf("admin.NewIamClient: %v", err)
	}
	defer client.Close()

	projectId := m.GetOptionByName(o.GcpProjectIdOpt.Name).Value
	log.Default().Printf("Enumerating service accounts for project: %s", projectId)
	req := &iampb.ListServiceAccountsRequest{
		Name: "projects/" + projectId,
	}

	// Call the API
	it := client.ListServiceAccounts(ctx, req)
	var accounts []*iampb.ServiceAccount
	for {
		account, err := it.Next()
		if err != nil && err.Error() == "no more items in iterator" {
			break
		}

		accounts = append(accounts, account)
	}

	helpers.PrintMessage(fmt.Sprintf("Found %d service accounts", len(accounts)))
	// Convert to JSON
	accountsJSON, err := json.Marshal(accounts)
	if err != nil {
		return fmt.Errorf("json.Marshal: %v", err)
	}

	m.Run.Data <- m.MakeResult(accountsJSON)

	return nil
}
