package common

import (
	"log/slog"
	"slices"

	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
)

var supportedResourceMap = map[tab.CloudResourceType][]string{
	tab.GCPResourceBucket:                {"bucket"},
	tab.GCPResourceInstance:              {"vm", "instance"},
	tab.GCPResourceSQLInstance:           {"sql"},
	tab.GCPResourceFunction:              {"function", "functionv2"},
	tab.GCPResourceFunctionV1:            {"functionv1", "cloudfunction"},
	tab.GCPResourceCloudRunJob:           {"runjob", "cloudrunjob"},
	tab.GCPResourceCloudRunService:       {"runservice", "cloudrunservice"},
	tab.GCPResourceAppEngineApplication:  {"appengine"},
	tab.GCPResourceAppEngineService:      {"appengineservice"},
	tab.GCPResourceServiceAccount:        {"serviceaccount", "sa"},
	tab.GCPResourceRole:                  {"role"},
	tab.GCPResourcePolicy:                {"policy"},
	tab.GCPResourceBinding:               {"binding"},
	tab.GCPResourceMember:                {"member"},
	tab.GCPResourceProject:               {"project"},
	tab.GCPResourceProjectPolicy:         {"projectpolicy"},
	tab.GCPResourceProjectIamPolicy:      {"projectiampolicy"},
	tab.GCPResourceFolder:                {"folder"},
	tab.GCPResourceFolderPolicy:          {"folderpolicy"},
	tab.GCPResourceFolderIamPolicy:       {"folderiampolicy"},
	tab.GCPResourceOrganization:          {"organization", "org"},
	tab.GCPResourceOrganizationIamPolicy: {"orgiampolicy"},
	tab.GCPResourceOrganizationPolicy:    {"orgpolicy"},
	tab.GCPResourceForwardingRule:        {"forwardingrule"},
	tab.GCPResourceGlobalForwardingRule:  {"globalforwardingrule", "globalforwarding"},
	tab.GCPResourceDNSManagedZone:        {"dnszone", "managedzone"},
	tab.GCPResourceAddress:               {"address"},
	tab.GCRContainerImage:                {"containerimage"},
	tab.GCRArtifactRepository:            {"artifactrepo"},
	tab.GCRArtifactoryDockerImage:        {"dockerimage", "artifactoryimage"},
}

func ResrouceIdentifier(s string) tab.CloudResourceType {
	for k, v := range supportedResourceMap {
		if slices.Contains(v, s) {
			return k
		} else if s == k.String() {
			return k
		}
	}
	slog.Error("Unsupported or unknown resource type", "resource", s)
	return tab.ResourceTypeUnknown
}
