package gcloudiam

import gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"

type ConditionalPermission struct {
	Permission gcptypes.Permission
	Condition  *gcptypes.Condition
	Role       string
}

type EffectivePermissions struct {
	UnconditionalAllow map[string]gcptypes.PermissionSet
	UnconditionalDeny  map[string]gcptypes.PermissionSet
	ConditionalAllow   map[string][]ConditionalPermission
	ConditionalDeny    map[string][]ConditionalPermission
}

func NewEffectivePermissions() *EffectivePermissions {
	return &EffectivePermissions{
		UnconditionalAllow: make(map[string]gcptypes.PermissionSet),
		UnconditionalDeny:  make(map[string]gcptypes.PermissionSet),
		ConditionalAllow:   make(map[string][]ConditionalPermission),
		ConditionalDeny:    make(map[string][]ConditionalPermission),
	}
}

func (ep *EffectivePermissions) DeepCopy() *EffectivePermissions {
	copied := NewEffectivePermissions()
	for principalKey, perms := range ep.UnconditionalAllow {
		copiedPerms := gcptypes.NewPermissionSet()
		for perm := range perms {
			copiedPerms.Add(perm)
		}
		copied.UnconditionalAllow[principalKey] = copiedPerms
	}
	for principalKey, perms := range ep.UnconditionalDeny {
		copiedPerms := gcptypes.NewPermissionSet()
		for perm := range perms {
			copiedPerms.Add(perm)
		}
		copied.UnconditionalDeny[principalKey] = copiedPerms
	}
	for principalKey, condPerms := range ep.ConditionalAllow {
		copiedCondPerms := make([]ConditionalPermission, len(condPerms))
		copy(copiedCondPerms, condPerms)
		copied.ConditionalAllow[principalKey] = copiedCondPerms
	}
	for principalKey, condPerms := range ep.ConditionalDeny {
		copiedCondPerms := make([]ConditionalPermission, len(condPerms))
		copy(copiedCondPerms, condPerms)
		copied.ConditionalDeny[principalKey] = copiedCondPerms
	}
	return copied
}
