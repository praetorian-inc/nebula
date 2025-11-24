package gcloudcollectors

import "strings"

func normalizeOrgName(orgID string) string {
	if strings.HasPrefix(orgID, "organizations/") {
		return orgID
	}
	return "organizations/" + orgID
}

func normalizeFolderName(folderID string) string {
	if strings.HasPrefix(folderID, "folders/") {
		return folderID
	}
	return "folders/" + folderID
}

func normalizeProjectName(projectID string) string {
	if strings.HasPrefix(projectID, "projects/") {
		return projectID
	}
	return "projects/" + projectID
}

func extractIDFromName(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return name
}

func convertURIToDenyPolicyParent(uri string) string {
	if strings.HasPrefix(uri, "organizations/") {
		return uri + "/locations/global"
	}
	if strings.HasPrefix(uri, "folders/") {
		return uri + "/locations/global"
	}
	if strings.HasPrefix(uri, "projects/") {
		return uri + "/locations/global"
	}
	return uri
}

func isSysProject(projectID, displayName string) bool {
	sysPatterns := []string{
		"sys-",
		"script-editor-",
		"apps-script-",
		"system-",
		"firebase-",
		"cloud-build-",
		"gcf-",
		"gae-",
	}
	projectIDLower := strings.ToLower(projectID)
	displayNameLower := strings.ToLower(displayName)
	for _, pattern := range sysPatterns {
		if strings.HasPrefix(projectIDLower, pattern) || strings.HasPrefix(displayNameLower, pattern) {
			return true
		}
	}
	return false
}

func extractIDFromURI(uri string) string {
	parts := []rune(uri)
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == '/' {
			return string(parts[i+1:])
		}
	}
	return uri
}
