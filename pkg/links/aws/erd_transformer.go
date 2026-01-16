package aws

import (
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// ERDToAWSResourceTransformer transforms EnrichedResourceDescription to AWSResource
// while also passing through the original ERD for outputters that need it
type ERDToAWSResourceTransformer struct {
	*base.AwsReconLink
}

func NewERDToAWSResourceTransformer(configs ...cfg.Config) chain.Link {
	t := &ERDToAWSResourceTransformer{}
	t.AwsReconLink = base.NewAwsReconLink(t, configs...)
	return t
}

func (t *ERDToAWSResourceTransformer) Process(erd *types.EnrichedResourceDescription) error {
	// Send the original ERD first for ERD-based outputters
	if err := t.Send(erd); err != nil {
		return err
	}

	// Transform to AWSResource for risk-based outputters and wrappers
	awsResource, err := TransformERDToAWSResource(erd)
	if err != nil {
		slog.Warn("Failed to transform ERD to AWSResource",
			"resource_type", erd.TypeName,
			"resource_id", erd.Identifier,
			"error", err)
		return nil // Don't fail the chain, just skip AWSResource output
	}

	// Send the transformed AWSResource
	if err := t.Send(awsResource); err != nil {
		return err
	}

	return nil
}
