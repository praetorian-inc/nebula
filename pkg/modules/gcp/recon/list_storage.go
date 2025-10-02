package recon

// NOTE: This module has been superseded by list_resources.go
// Use: nebula gcp recon list --project <project> --type bucket
// Use: nebula gcp recon list --project <project> --type sql

/*
import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/storage"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("gcp", "recon", GcpListBuckets.Metadata().Properties()["id"].(string), *GcpListBuckets)
	registry.Register("gcp", "recon", GcpListSQLInstances.Metadata().Properties()["id"].(string), *GcpListSQLInstances)
}

var GcpListBuckets = chain.NewModule(
	cfg.NewMetadata(
		"GCP List Buckets",
		"List all storage buckets in a GCP project.",
	).WithProperties(map[string]any{
		"id":          "buckets-list",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}).WithChainInputParam(options.GcpProject().Name()),
).WithLinks(
	hierarchy.NewGcpProjectInfoLink,
	storage.NewGcpStorageBucketListLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	options.GcpProject(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "buckets-list"),
)

var GcpListSQLInstances = chain.NewModule(
	cfg.NewMetadata(
		"GCP List SQL Instances",
		"List all SQL instances in a GCP project.",
	).WithProperties(map[string]any{
		"id":          "sql-instances-list",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}).WithChainInputParam(options.GcpProject().Name()),
).WithLinks(
	hierarchy.NewGcpProjectInfoLink,
	storage.NewGcpSQLInstanceListLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	options.GcpProject(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "sql-instances-list"),
)
*/
