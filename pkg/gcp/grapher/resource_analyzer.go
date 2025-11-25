package gcloudiam

import (
	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
)

type ResourceAnalyzer struct {
	containerAnalyzer *ContainerAnalyzer
	selectorEvaluator *SelectorEvaluator
	ancestryBuilder   *AncestryBuilder
	roleExpander      *RoleExpander
	normalizer        *PrincipalNormalizer
}

func NewResourceAnalyzer(
	containerAnalyzer *ContainerAnalyzer,
	selectorEvaluator *SelectorEvaluator,
	ancestryBuilder *AncestryBuilder,
	roleExpander *RoleExpander,
	normalizer *PrincipalNormalizer,
) *ResourceAnalyzer {
	return &ResourceAnalyzer{
		containerAnalyzer: containerAnalyzer,
		selectorEvaluator: selectorEvaluator,
		ancestryBuilder:   ancestryBuilder,
		roleExpander:      roleExpander,
		normalizer:        normalizer,
	}
}

func (ra *ResourceAnalyzer) EvaluateResource(resource *gcptypes.Resource) []*gcptypes.PermissionTuple {
	tuples := make([]*gcptypes.PermissionTuple, 0)
	ancestors := []string{resource.ParentURI}
	ancestors = append(ancestors, ra.ancestryBuilder.GetAncestors(resource.ParentURI)...)
	eff := NewEffectivePermissions()
	for _, containerURI := range ancestors {
		containerEff, err := ra.containerAnalyzer.GetEffectivePermissions(containerURI)
		if err != nil {
			continue
		}
		eff = ra.mergeEffective(eff, containerEff)
	}
	if resource.Policies.Allow != nil {
		ra.processResourceAllowPolicy(resource.Policies.Allow, eff)
	}
	ra.evaluateConditionalPermissions(eff, resource)
	ra.applyDenies(eff, resource)
	tuples = ra.emitTuples(eff, resource, ancestors)
	return tuples
}

func (ra *ResourceAnalyzer) mergeEffective(base, additional *EffectivePermissions) *EffectivePermissions {
	merged := base.DeepCopy()
	for principalKey, perms := range additional.UnconditionalAllow {
		if merged.UnconditionalAllow[principalKey] == nil {
			merged.UnconditionalAllow[principalKey] = gcptypes.NewPermissionSet()
		}
		merged.UnconditionalAllow[principalKey] = merged.UnconditionalAllow[principalKey].Union(perms)
	}
	for principalKey, condPerms := range additional.ConditionalAllow {
		merged.ConditionalAllow[principalKey] = append(merged.ConditionalAllow[principalKey], condPerms...)
	}
	for principalKey, perms := range additional.UnconditionalDeny {
		if merged.UnconditionalDeny[principalKey] == nil {
			merged.UnconditionalDeny[principalKey] = gcptypes.NewPermissionSet()
		}
		merged.UnconditionalDeny[principalKey] = merged.UnconditionalDeny[principalKey].Union(perms)
	}
	for principalKey, condPerms := range additional.ConditionalDeny {
		merged.ConditionalDeny[principalKey] = append(merged.ConditionalDeny[principalKey], condPerms...)
	}
	return merged
}

func (ra *ResourceAnalyzer) processResourceAllowPolicy(policy *gcptypes.AllowPolicy, eff *EffectivePermissions) {
	for _, binding := range policy.Bindings {
		perms, err := ra.roleExpander.ExpandRole(binding.Role)
		if err != nil {
			continue
		}
		for _, member := range binding.Members {
			principal := ra.normalizer.NormalizeMember(member)
			principalKey := ra.normalizer.GetPrincipalKey(principal)
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

func (ra *ResourceAnalyzer) evaluateConditionalPermissions(eff *EffectivePermissions, resource *gcptypes.Resource) {
	for principalKey, condPerms := range eff.ConditionalAllow {
		for _, cp := range condPerms {
			if ra.selectorEvaluator.EvaluateCondition(cp.Condition, resource) {
				if eff.UnconditionalAllow[principalKey] == nil {
					eff.UnconditionalAllow[principalKey] = gcptypes.NewPermissionSet()
				}
				eff.UnconditionalAllow[principalKey].Add(cp.Permission)
			}
		}
	}
	for principalKey, condPerms := range eff.ConditionalDeny {
		for _, cp := range condPerms {
			if ra.selectorEvaluator.EvaluateCondition(cp.Condition, resource) {
				if eff.UnconditionalDeny[principalKey] == nil {
					eff.UnconditionalDeny[principalKey] = gcptypes.NewPermissionSet()
				}
				eff.UnconditionalDeny[principalKey].Add(cp.Permission)
			}
		}
	}
}

func (ra *ResourceAnalyzer) applyDenies(eff *EffectivePermissions, resource *gcptypes.Resource) {
	for principalKey, deniedPerms := range eff.UnconditionalDeny {
		if allowedPerms, ok := eff.UnconditionalAllow[principalKey]; ok {
			eff.UnconditionalAllow[principalKey] = allowedPerms.Subtract(deniedPerms)
		}
	}
}

func (ra *ResourceAnalyzer) emitTuples(eff *EffectivePermissions, resource *gcptypes.Resource, ancestors []string) []*gcptypes.PermissionTuple {
	tuples := make([]*gcptypes.PermissionTuple, 0)
	for principalKey, perms := range eff.UnconditionalAllow {
		principal := ra.normalizer.principalCache[principalKey]
		if principal == nil {
			principal = ra.normalizer.NormalizeMember(principalKey)
		}
		for perm := range perms {
			tuple := &gcptypes.PermissionTuple{
				Principal:  principal,
				Permission: perm,
				Resource:   resource,
				Provenance: &gcptypes.Provenance{
					ViaContainers: ancestors,
					IsConditional: false,
				},
			}
			tuples = append(tuples, tuple)
		}
	}
	return tuples
}
