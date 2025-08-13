package aws

import (
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/links/noseyparker"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudformation"
	"github.com/praetorian-inc/nebula/pkg/links/aws/ec2"
	"github.com/praetorian-inc/nebula/pkg/links/aws/lambda"
	"github.com/praetorian-inc/nebula/pkg/links/aws/stepfunctions"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSFindSecrets struct {
	*base.AwsReconLink
	clientMap   map[string]interface{} // map key is type-region
	resourceMap map[string]func() chain.Chain
}

func NewAWSFindSecrets(configs ...cfg.Config) chain.Link {
	fs := &AWSFindSecrets{}
	fs.AwsReconLink = base.NewAwsReconLink(fs, configs...)
	return fs
}

func (fs *AWSFindSecrets) Initialize() error {
	fs.AwsReconLink.Initialize()
	fs.resourceMap = fs.ResourceMap()
	return nil
}

func (fs *AWSFindSecrets) SupportedResourceTypes() []string {
	resources := fs.ResourceMap()
	types := make([]string, 0, len(resources))
	for resourceType := range resources {
		types = append(types, resourceType)
	}
	return types
}

func (fs *AWSFindSecrets) ResourceMap() map[string]func() chain.Chain {
	resourceMap := make(map[string]func() chain.Chain)

	resourceMap["AWS::EC2::Instance"] = func() chain.Chain {
		return chain.NewChain(
			ec2.NewAWSEC2UserData(),
		)
	}

	resourceMap["AWS::Lambda::Function"] = func() chain.Chain {
		return chain.NewMulti(
			noseyparker.NewConvertToNPInput(),
			lambda.NewAWSLambdaFunctionCode(),
		)
	}

	resourceMap["AWS::CloudFormation::Stack"] = func() chain.Chain {
		return chain.NewChain(
			cloudformation.NewAWSCloudFormationTemplates(),
		)
	}

	// resourceMap["AWS::ECR::Repository"] = func() chain.Chain {
	// 	return chain.NewChain(
	// 		ecr.NewAWSECRListImages(),
	// 		ecr.NewAWSECRLogin(),
	// 		docker.NewDockerPull(),
	// 		docker.NewDockerSave(),
	// 		noseyparker.NewConvertToNPInput(),
	// 	)
	// }

	// resourceMap["AWS::ECR::PublicRepository"] = func() chain.Chain {
	// 	return chain.NewChain(
	// 		ecr.NewAWSECRListPublicImages(),
	// 		ecr.NewAWSECRLoginPublic(),
	// 		docker.NewDockerPull(),
	// 		docker.NewDockerSave(),
	// 		noseyparker.NewConvertToNPInput(),
	// 	)
	// }

	resourceMap["AWS::ECS::TaskDefinition"] = func() chain.Chain {
		return chain.NewChain(
			noseyparker.NewConvertToNPInput(),
		)
	}

	resourceMap["AWS::SSM::Document"] = func() chain.Chain {
		return chain.NewChain(
			noseyparker.NewConvertToNPInput(),
		)
	}

	// resourceMap["AWS::SSM::Parameter"] = func() chain.Chain {
	// 	return chain.NewChain(
	// 		ssm.NewAWSListSSMParameters(),
	// 		noseyparker.NewConvertToNPInput(),
	// 	)
	// }

	resourceMap["AWS::StepFunctions::StateMachine"] = func() chain.Chain {
		return chain.NewChain(
			stepfunctions.NewAWSListExecutions(),
			stepfunctions.NewAWSGetExecutionDetails(),
			noseyparker.NewConvertToNPInput(),
		)
	}

	return resourceMap
}

func (fs *AWSFindSecrets) Process(resource *types.EnrichedResourceDescription) error {
	constructor, ok := fs.resourceMap[resource.TypeName]
	if !ok {
		slog.Error("Unsupported resource type", "resource", resource)
		return nil
	}

	slog.Debug("Dispatching resource for processing", "resource_type", resource.TypeName, "resource_id", resource.Identifier)

	// Create pair and send to processor
	pair := &ResourceChainPair{
		Resource:         resource,
		ChainConstructor: constructor,
		Args:             fs.Args(),
	}

	return fs.Send(pair)
}

func (fs *AWSFindSecrets) Complete() error {
	// No manual coordination needed - framework handles it
	return nil
}
