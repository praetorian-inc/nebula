package gcloudiam

import (
	"fmt"

	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
)

type ContainerAnalyzer struct {
	roleExpander   *RoleExpander
	normalizer     *PrincipalNormalizer
	pabEvaluator   *PABEvaluator
	effByContainer map[string]*EffectivePermissions
	isOrgLevel     bool
}

func NewContainerAnalyzer(roleExpander *RoleExpander, normalizer *PrincipalNormalizer, pabEvaluator *PABEvaluator) *ContainerAnalyzer {
	return &ContainerAnalyzer{
		roleExpander:   roleExpander,
		normalizer:     normalizer,
		pabEvaluator:   pabEvaluator,
		effByContainer: make(map[string]*EffectivePermissions),
	}
}

func (ca *ContainerAnalyzer) ProcessContainer(containerURI string, policies *gcptypes.Policies, parentEff *EffectivePermissions, isOrgLevel bool) *EffectivePermissions {
	ca.isOrgLevel = isOrgLevel
	var eff *EffectivePermissions
	if parentEff == nil {
		eff = NewEffectivePermissions()
	} else {
		eff = parentEff.DeepCopy()
	}
	if policies.Allow != nil {
		ca.processAllowPolicy(policies.Allow, eff)
	}
	if len(policies.Deny) > 0 {
		ca.processDenyPolicies(policies.Deny, eff)
	}
	if isOrgLevel && ca.pabEvaluator != nil {
		ca.pabEvaluator.ApplyPABMask(eff)
	}
	ca.effByContainer[containerURI] = eff
	return eff
}

func (ca *ContainerAnalyzer) processAllowPolicy(policy *gcptypes.AllowPolicy, eff *EffectivePermissions) {
	for _, binding := range policy.Bindings {
		perms, err := ca.roleExpander.ExpandRole(binding.Role)
		if err != nil {
			continue
		}
		for _, member := range binding.Members {
			principal := ca.normalizer.NormalizeMember(member)
			principalKey := ca.normalizer.GetPrincipalKey(principal)

			if binding.Condition == nil {
				if eff.UnconditionalAllow[principalKey] == nil {
					eff.UnconditionalAllow[principalKey] = gcptypes.NewPermissionSet()
				}
				eff.UnconditionalAllow[principalKey] = eff.UnconditionalAllow[principalKey].Union(perms)
			} else {
				for perm := range perms {
					condPerm := ConditionalPermission{
						Permission: perm,
						Condition:  binding.Condition,
						Role:       binding.Role,
					}
					eff.ConditionalAllow[principalKey] = append(eff.ConditionalAllow[principalKey], condPerm)
				}
			}
		}
	}
}

func (ca *ContainerAnalyzer) processDenyPolicies(denyPolicies []gcptypes.DenyPolicy, eff *EffectivePermissions) {
	for _, denyPolicy := range denyPolicies {
		for _, rule := range denyPolicy.Rules {
			ca.processDenyRule(&rule, eff)
		}
	}
}

func (ca *ContainerAnalyzer) processDenyRule(rule *gcptypes.DenyRule, eff *EffectivePermissions) {
	exceptionSet := make(map[string]bool)
	for _, exceptionMember := range rule.ExceptionPrincipals {
		principal := ca.normalizer.NormalizeMember(exceptionMember)
		exceptionSet[ca.normalizer.GetPrincipalKey(principal)] = true
	}
	deniedPerms := gcptypes.NewPermissionSet()
	for _, permStr := range rule.DeniedPermissions {
		deniedPerms.Add(gcptypes.Permission(permStr))
	}
	for _, deniedMember := range rule.DeniedPrincipals {
		principal := ca.normalizer.NormalizeMember(deniedMember)
		principalKey := ca.normalizer.GetPrincipalKey(principal)
		if exceptionSet[principalKey] {
			continue
		}
		if rule.Condition == nil {
			if eff.UnconditionalDeny[principalKey] == nil {
				eff.UnconditionalDeny[principalKey] = gcptypes.NewPermissionSet()
			}
			eff.UnconditionalDeny[principalKey] = eff.UnconditionalDeny[principalKey].Union(deniedPerms)
		} else {
			for perm := range deniedPerms {
				condPerm := ConditionalPermission{
					Permission: perm,
					Condition:  rule.Condition,
				}
				eff.ConditionalDeny[principalKey] = append(eff.ConditionalDeny[principalKey], condPerm)
			}
		}
	}
}

func (ca *ContainerAnalyzer) GetEffectivePermissions(containerURI string) (*EffectivePermissions, error) {
	eff, ok := ca.effByContainer[containerURI]
	if !ok {
		return nil, fmt.Errorf("effective permissions not found for container: %s", containerURI)
	}
	return eff, nil
}
