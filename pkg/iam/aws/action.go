package aws

import (
	"slices"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type Action string

func (a *Action) Service() string {
	split := strings.Split(string(*a), ":")
	if len(split) != 2 {
		return ""
	}
	return split[0]
}

func isPrivEscAction(action string) bool {
	return slices.Contains(privEscActions, action)
}

var privEscActions = []string{
	"apprunner:CreateService",
	"apprunner:UpdateService",
	"bedrock-agentcore:CreateCodeInterpreter",
	"bedrock-agentcore:InvokeCodeInterpreter",
	"bedrock-agentcore:StartCodeInterpreterSession",
	"cloudformation:CreateChangeSet",
	"cloudformation:CreateStack",
	"cloudformation:CreateStackInstances",
	"cloudformation:CreateStackSet",
	"cloudformation:ExecuteChangeSet",
	"cloudformation:SetStackPolicy",
	"cloudformation:UpdateStack",
	"cloudformation:UpdateStackSet",
	"codebuild:CreateProject",
	"codebuild:StartBuild",
	"codebuild:StartBuildBatch",
	"codebuild:UpdateProject",
	"codestar:AssociateTeamMember",
	"codestar:CreateProject",
	"ec2:CreateLaunchTemplate",
	"ec2:CreateLaunchTemplateVersion",
	"ec2:ModifyInstanceAttribute",
	"ec2:ModifyLaunchTemplate",
	"ec2:RequestSpotInstances",
	"ec2:RunInstances",
	"ec2:StartInstances",
	"ec2:StopInstances",
	"ec2-instance-connect:SendSSHPublicKey",
	"ecs:CreateCluster",
	"ecs:CreateService",
	"ecs:DescribeTasks",
	"ecs:ExecuteCommand",
	"ecs:RegisterTaskDefinition",
	"ecs:RunTask",
	"ecs:StartTask",
	"glue:CreateDevEndpoint",
	"glue:CreateJob",
	"glue:CreateTrigger",
	"glue:StartJobRun",
	"glue:UpdateDevEndpoint",
	"glue:UpdateJob",
	"iam:AddUserToGroup",
	"iam:AttachGroupPolicy",
	"iam:AttachRolePolicy",
	"iam:AttachUserPolicy",
	"iam:CreateAccessKey",
	"iam:CreateLoginProfile",
	"iam:CreatePolicyVersion",
	"iam:CreateUser",
	"iam:CreateRole",
	"iam:PassRole",
	"iam:PutGroupPolicy",
	"iam:PutRolePolicy",
	"iam:PutUserPolicy",
	"iam:SetDefaultPolicyVersion",
	"iam:UpdateAssumeRolePolicy",
	"iam:UpdateLoginProfile",
	"autoscaling:CreateAutoScalingGroup",
	"autoscaling:CreateLaunchConfiguration",
	"lambda:AddPermission",
	"lambda:CreateEventSourceMapping",
	"lambda:CreateFunction",
	"lambda:InvokeFunction",
	"lambda:UpdateFunctionCode",
	"lambda:UpdateFunctionConfiguration",
	"sagemaker:CreateHyperParameterTuningJob",
	"sagemaker:CreateNotebookInstance",
	"sagemaker:CreateNotebookInstanceLifecycleConfig",
	"sagemaker:CreatePresignedNotebookInstanceUrl",
	"sagemaker:CreateProcessingJob",
	"sagemaker:CreateTrainingJob",
	"sagemaker:StartNotebookInstance",
	"sagemaker:StopNotebookInstance",
	"sagemaker:UpdateNotebookInstance",
	"ssm:SendCommand",
	"ssm:StartSession",
	"ssm:StartAutomationExecution",
	"ssm:ResumeSession",
	"sts:AssumeRole",
	"sts:AssumeRoleWithSAML",
	"sts:AssumeRoleWithWebIdentity",
	"sts:GetFederationToken",
}

// Helper function to use AwsExpandActionsStage
func expandActionsWithStage(actions types.DynaString) []string {
	expandedActions := make([]string, 0)

	// Process each action
	for _, action := range actions {
		if strings.Contains(action, "*") {
			c := chain.NewChain(NewAWSExpandActionsLink())
			c.Send(action)
			c.Close()

			for o, ok := chain.RecvAs[string](c); ok; o, ok = chain.RecvAs[string](c) {
				expandedActions = append(expandedActions, o)
			}
		} else {
			// Add non-wildcard actions directly
			expandedActions = append(expandedActions, action)
		}
	}

	return expandedActions
}

func ExtractActions(psl *types.PolicyStatementList) []string {
	actions := []string{}
	for _, statement := range *psl {
		if statement.Action != nil {
			expandedActions := expandActionsWithStage(*statement.Action)
			actions = append(actions, expandedActions...)
		}
	}
	return actions
}
