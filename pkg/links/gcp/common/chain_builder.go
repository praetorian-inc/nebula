package common

import (
	"fmt"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

type HierarchyLinkConstructor func(...cfg.Config) chain.Link

type HierarchyChainBuilder struct {
	OrgInfo           HierarchyLinkConstructor
	FolderInfo        HierarchyLinkConstructor
	ProjectInfo       HierarchyLinkConstructor
	OrgProjectList    HierarchyLinkConstructor
	FolderProjectList HierarchyLinkConstructor
}

func (b *HierarchyChainBuilder) BuildInfoChain(scope *ScopeConfig) (chain.Chain, error) {
	switch scope.Type {
	case "org":
		return chain.NewChain(b.OrgInfo()), nil
	case "folder":
		return chain.NewChain(b.FolderInfo()), nil
	case "project":
		return chain.NewChain(b.ProjectInfo()), nil
	default:
		return nil, fmt.Errorf("invalid scope type: %s", scope.Type)
	}
}

func (b *HierarchyChainBuilder) BuildProjectListChain(scope *ScopeConfig) (chain.Chain, error) {
	switch scope.Type {
	case "org":
		return chain.NewChain(b.OrgProjectList()), nil
	case "folder":
		return chain.NewChain(b.FolderProjectList()), nil
	case "project":
		return nil, nil
	default:
		return nil, fmt.Errorf("invalid scope type: %s", scope.Type)
	}
}

func ValidateResourceTypes(resourceTypes []string, validatorFunc func(string) tab.CloudResourceType) error {
	if len(resourceTypes) > 0 && resourceTypes[0] != "all" {
		for _, rt := range resourceTypes {
			if validatorFunc(rt) == tab.ResourceTypeUnknown {
				return fmt.Errorf("unsupported resource type: %s", rt)
			}
		}
	}
	return nil
}
