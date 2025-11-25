package gcloudiam

import (
	"regexp"
	"strings"

	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
)

var ( // not too useful yet but nice llm aid
	ksaRegex = regexp.MustCompile(`^serviceAccount:([^.]+)\.svc\.id\.goog\[([^/]+)/([^\]]+)\]$`)
)

type PrincipalNormalizer struct {
	principalCache map[string]*gcptypes.Principal
}

func NewPrincipalNormalizer() *PrincipalNormalizer {
	return &PrincipalNormalizer{
		principalCache: make(map[string]*gcptypes.Principal),
	}
}

func (pn *PrincipalNormalizer) NormalizeMember(member string) *gcptypes.Principal {
	if cached, ok := pn.principalCache[member]; ok {
		return cached
	}
	principal := pn.parseMember(member)
	pn.principalCache[member] = principal
	return principal
}

func (pn *PrincipalNormalizer) parseMember(member string) *gcptypes.Principal {
	principal := &gcptypes.Principal{}
	if strings.HasPrefix(member, "deleted:") {
		principal.Deleted = true
		principal.OriginalEmail = member
		member = strings.TrimPrefix(member, "deleted:")
	}

	switch {
	case member == "allUsers":
		principal.Kind = gcptypes.PrincipalAllUsers
		principal.Email = "allUsers"
	case member == "allAuthenticatedUsers":
		principal.Kind = gcptypes.PrincipalAllAuthenticatedUsers
		principal.Email = "allAuthenticatedUsers"
	case strings.HasPrefix(member, "user:"):
		principal.Kind = gcptypes.PrincipalUser
		principal.Email = strings.TrimPrefix(member, "user:")
	case strings.HasPrefix(member, "group:"):
		principal.Kind = gcptypes.PrincipalGroup
		principal.Email = strings.TrimPrefix(member, "group:")
	case strings.HasPrefix(member, "domain:"):
		principal.Kind = gcptypes.PrincipalDomain
		principal.Domain = strings.TrimPrefix(member, "domain:")
	case strings.HasPrefix(member, "serviceAccount:"):
		if matches := ksaRegex.FindStringSubmatch(member); matches != nil {
			principal.Kind = gcptypes.PrincipalWorkloadIdentity
			principal.KSAProjectID = matches[1]
			principal.KubernetesNamespace = matches[2]
			principal.KubernetesServiceAcc = matches[3]
		} else {
			email := strings.TrimPrefix(member, "serviceAccount:")
			principal.Kind = gcptypes.PrincipalServiceAccount
			principal.Email = email
			if strings.Contains(email, ".gserviceaccount.com") && strings.HasPrefix(email, "service-") { // TODO: maybe add comparison with project id after @ also, but how to get project?
				principal.IsGoogleManaged = true
				principal.Kind = gcptypes.PrincipalServiceAgent
			}
		}
	case strings.HasPrefix(member, "principal://"):
		principal.PrincipalURI = member
		if strings.Contains(member, "workforcePools") { // TODO: llm classification; need to confirm this works
			principal.Kind = gcptypes.PrincipalWorkforceIdentity
			pn.parseWorkforcePrincipal(member, principal)
		} else if strings.Contains(member, "workloadIdentityPools") {
			principal.Kind = gcptypes.PrincipalWorkloadIdentity
			pn.parseWorkloadPrincipal(member, principal)
		}
	case strings.HasPrefix(member, "principalSet://"): // TODO: need more fine-grained extraction of groups, pools, etc.
		principal.Kind = gcptypes.PrincipalSet
		principal.PrincipalSetURI = member
	}
	return principal
}

func (pn *PrincipalNormalizer) parseWorkforcePrincipal(uri string, principal *gcptypes.Principal) {
	parts := strings.Split(uri, "/")
	for i, part := range parts {
		if part == "workforcePools" && i+1 < len(parts) {
			poolName := strings.Join(parts[:i+2], "/")
			principal.WorkforcePoolName = strings.TrimPrefix(poolName, "principal://iam.googleapis.com/")
		}
		if part == "subject" && i+1 < len(parts) {
			principal.WorkforceSubject = strings.Join(parts[i:], "/")
		}
	}
}

func (pn *PrincipalNormalizer) parseWorkloadPrincipal(uri string, principal *gcptypes.Principal) {
	parts := strings.Split(uri, "/")
	for i, part := range parts {
		if part == "workloadIdentityPools" && i+1 < len(parts) {
			poolName := strings.Join(parts[:i+2], "/")
			principal.WorkloadPoolName = strings.TrimPrefix(poolName, "principal://iam.googleapis.com/")
		}
		if part == "subject" && i+1 < len(parts) {
			principal.WorkloadSubject = strings.Join(parts[i:], "/")
		}
	}
}

func (pn *PrincipalNormalizer) GetPrincipalKey(principal *gcptypes.Principal) string {
	switch principal.Kind {
	case gcptypes.PrincipalUser, gcptypes.PrincipalGroup, gcptypes.PrincipalServiceAccount, gcptypes.PrincipalServiceAgent:
		if principal.Deleted {
			return "deleted:" + principal.OriginalEmail
		}
		return principal.Email
	case gcptypes.PrincipalDomain:
		return "domain:" + principal.Domain
	case gcptypes.PrincipalAllUsers:
		return "allUsers"
	case gcptypes.PrincipalAllAuthenticatedUsers:
		return "allAuthenticatedUsers"
	case gcptypes.PrincipalWorkforceIdentity, gcptypes.PrincipalWorkloadIdentity:
		return principal.PrincipalURI
	case gcptypes.PrincipalSet:
		return principal.PrincipalSetURI
	default:
		return principal.Email
	}
}
