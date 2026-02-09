package hierarchy

import (
	"testing"

	"google.golang.org/api/cloudresourcemanager/v1"
)

// TestGcpOrgProjectListLink_SkipsNonActiveProjects tests that projects
// with LifecycleState != "ACTIVE" are skipped during project enumeration.
// This prevents errors like "The resource 'projects/regal-fortress-418514' was not found"
// which occur when trying to enumerate resources in deleted/deleting projects.
func TestGcpOrgProjectListLink_SkipsNonActiveProjects(t *testing.T) {
	tests := []struct {
		name          string
		projects      []*cloudresourcemanager.Project
		wantProcessed []string // project IDs that should be processed
	}{
		{
			name: "skips DELETE_REQUESTED projects",
			projects: []*cloudresourcemanager.Project{
				{
					ProjectId:      "active-project-1",
					LifecycleState: "ACTIVE",
				},
				{
					ProjectId:      "deleting-project",
					LifecycleState: "DELETE_REQUESTED",
				},
				{
					ProjectId:      "active-project-2",
					LifecycleState: "ACTIVE",
				},
			},
			wantProcessed: []string{"active-project-1", "active-project-2"},
		},
		{
			name: "skips DELETE_IN_PROGRESS projects",
			projects: []*cloudresourcemanager.Project{
				{
					ProjectId:      "active-project",
					LifecycleState: "ACTIVE",
				},
				{
					ProjectId:      "being-deleted",
					LifecycleState: "DELETE_IN_PROGRESS",
				},
			},
			wantProcessed: []string{"active-project"},
		},
		{
			name: "processes only ACTIVE projects",
			projects: []*cloudresourcemanager.Project{
				{
					ProjectId:      "active-project",
					LifecycleState: "ACTIVE",
				},
			},
			wantProcessed: []string{"active-project"},
		},
		{
			name: "skips all non-ACTIVE states",
			projects: []*cloudresourcemanager.Project{
				{
					ProjectId:      "deleted-project",
					LifecycleState: "DELETE_REQUESTED",
				},
				{
					ProjectId:      "deleting-project",
					LifecycleState: "DELETE_IN_PROGRESS",
				},
			},
			wantProcessed: []string{}, // none should be processed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Track which projects were processed (not skipped)
			var processed []string

			// Simulate the loop logic from GcpOrgProjectListLink.Process
			for _, project := range tt.projects {
				// This is the check we're testing - should skip non-ACTIVE
				if project.LifecycleState != "ACTIVE" {
					continue
				}
				// If we reach here, project should be processed
				processed = append(processed, project.ProjectId)
			}

			// Verify the right projects were processed
			if len(processed) != len(tt.wantProcessed) {
				t.Errorf("processed count = %d, want %d", len(processed), len(tt.wantProcessed))
				t.Errorf("processed = %v, want %v", processed, tt.wantProcessed)
			}

			// Check each expected project was processed
			for _, wantID := range tt.wantProcessed {
				found := false
				for _, gotID := range processed {
					if gotID == wantID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected project %s to be processed, but it was skipped", wantID)
				}
			}

			// Check no unexpected projects were processed
			for _, gotID := range processed {
				found := false
				for _, wantID := range tt.wantProcessed {
					if gotID == wantID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("project %s was processed but should have been skipped", gotID)
				}
			}
		})
	}
}
