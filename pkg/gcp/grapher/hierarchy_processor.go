package gcloudiam

import (
	"context"
	"fmt"
	"strings"

	gcloudcollectors "github.com/praetorian-inc/nebula/pkg/gcp/collectors"
	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
	"google.golang.org/api/option"
)

type HierarchyProcessor struct {
	ctx                context.Context
	hierarchyCollector *gcloudcollectors.HierarchyCollector
	roleCollector      *gcloudcollectors.RoleCollector
	resourceCollector  *gcloudcollectors.ResourceCollector
	pabCollector       *gcloudcollectors.PABCollector
	ancestryBuilder    *AncestryBuilder
	roleExpander       *RoleExpander
	normalizer         *PrincipalNormalizer
	containerAnalyzer  *ContainerAnalyzer
	resourceAnalyzer   *ResourceAnalyzer
	selectorEvaluator  *SelectorEvaluator
	pabEvaluator       *PABEvaluator
	hierarchy          *gcptypes.Hierarchy
	allResources       []*gcptypes.Resource
}

func NewHierarchyProcessor(ctx context.Context, clientOptions ...option.ClientOption) (*HierarchyProcessor, error) {
	hp := &HierarchyProcessor{
		ctx:       ctx,
		hierarchy: &gcptypes.Hierarchy{},
	}
	var err error
	hp.hierarchyCollector, err = gcloudcollectors.NewHierarchyCollector(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create hierarchy collector: %w", err)
	}
	hp.roleCollector, err = gcloudcollectors.NewRoleCollector(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create role collector: %w", err)
	}
	hp.resourceCollector, err = gcloudcollectors.NewResourceCollector(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource collector: %w", err)
	}
	hp.pabCollector, err = gcloudcollectors.NewPABCollector(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create PAB collector: %w", err)
	}
	hp.selectorEvaluator, err = NewSelectorEvaluator()
	if err != nil {
		return nil, fmt.Errorf("failed to create selector evaluator: %w", err)
	}
	hp.ancestryBuilder = NewAncestryBuilder()
	hp.roleExpander = NewRoleExpander()
	hp.normalizer = NewPrincipalNormalizer()
	return hp, nil
}

func (hp *HierarchyProcessor) Close() error {
	var errs []error
	if hp.hierarchyCollector != nil {
		if err := hp.hierarchyCollector.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if hp.roleCollector != nil {
		if err := hp.roleCollector.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if hp.resourceCollector != nil {
		if err := hp.resourceCollector.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if hp.pabCollector != nil {
		if err := hp.pabCollector.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors closing collectors: %v", errs)
	}
	return nil
}

func (hp *HierarchyProcessor) Process(orgID string, assetTypes []string) error {
	fmt.Println("[1/6] Collecting roles...")
	if err := hp.collectRoles(orgID); err != nil {
		return fmt.Errorf("failed to collect roles: %w", err)
	}
	fmt.Println("[2/6] Collecting hierarchy...")
	if err := hp.collectHierarchy(orgID); err != nil {
		return fmt.Errorf("failed to collect hierarchy: %w", err)
	}
	fmt.Println("[3/6] Collecting PAB policies...")
	if err := hp.collectPABPolicies(orgID); err != nil {
		fmt.Printf("Warning: failed to collect PAB policies: %v\n", err)
	}
	fmt.Println("[4/6] Running container pass...")
	if err := hp.runContainerPass(); err != nil {
		return fmt.Errorf("failed to run container pass: %w", err)
	}
	fmt.Println("[5/6] Collecting resources...")
	if err := hp.collectResources(assetTypes); err != nil {
		return fmt.Errorf("failed to collect resources: %w", err)
	}
	fmt.Println("[6/6] Running resource pass...")
	tuples := hp.runResourcePass()
	fmt.Printf("Generated %d permission tuples\n", len(tuples))
	return nil
}

func (hp *HierarchyProcessor) collectRoles(orgID string) error {
	predefinedRoles, err := hp.roleCollector.CollectPredefinedRoles()
	if err != nil {
		return err
	}
	hp.roleExpander.AddRoles(predefinedRoles)
	customOrgRoles, err := hp.roleCollector.CollectCustomRolesInOrg(orgID)
	if err != nil {
		fmt.Printf("Warning: failed to collect org custom roles: %v\n", err)
	} else {
		hp.roleExpander.AddRoles(customOrgRoles)
	}
	return nil
}

func (hp *HierarchyProcessor) collectHierarchy(orgID string) error {
	org := &gcptypes.Organization{}
	if err := hp.hierarchyCollector.CollectOrganization(orgID, org); err != nil {
		return err
	}
	if err := hp.hierarchyCollector.CollectAllowPolicy(org.URI, &org.Policies); err != nil {
		fmt.Printf("Warning: failed to collect org allow policy: %v\n", err)
	}
	if err := hp.hierarchyCollector.CollectDenyPolicies(org.URI, &org.Policies); err != nil {
		fmt.Printf("Warning: failed to collect org deny policies: %v\n", err)
	}
	if err := hp.collectFoldersRecursive(org.URI, org); err != nil {
		return err
	}
	if err := hp.collectProjectsInParent(org.URI, org); err != nil {
		return err
	}
	hp.hierarchy.Organizations = append(hp.hierarchy.Organizations, org)
	hp.ancestryBuilder.AddOrganization(org)
	return nil
}

func (hp *HierarchyProcessor) collectFoldersRecursive(parentURI string, parent any) error {
	folders, err := hp.hierarchyCollector.CollectFoldersInParent(parentURI)
	if err != nil {
		return err
	}
	for _, folder := range folders {
		if err := hp.hierarchyCollector.CollectAllowPolicy(folder.URI, &folder.Policies); err != nil {
			fmt.Printf("Warning: failed to collect folder %s allow policy: %v\n", folder.URI, err)
		}
		if err := hp.hierarchyCollector.CollectDenyPolicies(folder.URI, &folder.Policies); err != nil {
			fmt.Printf("Warning: failed to collect folder %s deny policies: %v\n", folder.URI, err)
		}
		if err := hp.collectFoldersRecursive(folder.URI, folder); err != nil {
			return err
		}
		if err := hp.collectProjectsInParent(folder.URI, folder); err != nil {
			return err
		}
		hp.ancestryBuilder.AddFolder(folder)
		switch p := parent.(type) {
		case *gcptypes.Organization:
			p.Folders = append(p.Folders, folder)
		case *gcptypes.Folder:
			p.Folders = append(p.Folders, folder)
		}
	}
	return nil
}

func (hp *HierarchyProcessor) collectProjectsInParent(parentURI string, parent any) error {
	projects, err := hp.hierarchyCollector.CollectProjectsInParent(parentURI)
	if err != nil {
		return err
	}
	for _, project := range projects {
		if err := hp.hierarchyCollector.CollectAllowPolicy(project.URI, &project.Policies); err != nil {
			fmt.Printf("Warning: failed to collect project %s allow policy: %v\n", project.URI, err)
		}
		if err := hp.hierarchyCollector.CollectDenyPolicies(project.URI, &project.Policies); err != nil {
			fmt.Printf("Warning: failed to collect project %s deny policies: %v\n", project.URI, err)
		}
		customProjectRoles, err := hp.roleCollector.CollectCustomRolesInProject(project.ProjectID)
		if err != nil {
			fmt.Printf("Warning: failed to collect project %s custom roles: %v\n", project.ProjectID, err)
		} else {
			hp.roleExpander.AddRoles(customProjectRoles)
		}
		hp.ancestryBuilder.AddProject(project)
		switch p := parent.(type) {
		case *gcptypes.Organization:
			p.Projects = append(p.Projects, project)
		case *gcptypes.Folder:
			p.Projects = append(p.Projects, project)
		}
	}
	return nil
}

func (hp *HierarchyProcessor) collectPABPolicies(orgID string) error {
	pabPolicies, err := hp.pabCollector.CollectPABPolicies(orgID)
	if err != nil {
		return err
	}
	var pabBindings []gcptypes.PABBinding
	for _, org := range hp.hierarchy.Organizations {
		bindings, err := hp.pabCollector.CollectPABBindings(org.URI)
		if err != nil {
			fmt.Printf("Warning: failed to collect PAB bindings for org: %v\n", err)
		} else {
			pabBindings = append(pabBindings, bindings...)
		}
		org.PABPolicies = pabPolicies
	}
	hp.pabEvaluator = NewPABEvaluator(pabPolicies, pabBindings, hp.normalizer)
	hp.pabEvaluator.BuildPABMasks()
	return nil
}

func (hp *HierarchyProcessor) runContainerPass() error {
	hp.containerAnalyzer = NewContainerAnalyzer(hp.roleExpander, hp.normalizer, hp.pabEvaluator)
	for _, org := range hp.hierarchy.Organizations {
		hp.processOrgContainer(org)
		hp.processFoldersInContainer(org.Folders, org.URI)
		hp.processProjectsInContainer(org.Projects, org.URI)
	}
	return nil
}

func (hp *HierarchyProcessor) processOrgContainer(org *gcptypes.Organization) {
	hp.containerAnalyzer.ProcessContainer(org.URI, &org.Policies, nil, true)
}

func (hp *HierarchyProcessor) processFoldersInContainer(folders []*gcptypes.Folder, parentURI string) {
	for _, folder := range folders {
		parentEff, _ := hp.containerAnalyzer.GetEffectivePermissions(parentURI)
		hp.containerAnalyzer.ProcessContainer(folder.URI, &folder.Policies, parentEff, false)
		hp.processFoldersInContainer(folder.Folders, folder.URI)
		hp.processProjectsInContainer(folder.Projects, folder.URI)
	}
}

func (hp *HierarchyProcessor) processProjectsInContainer(projects []*gcptypes.Project, parentURI string) {
	for _, project := range projects {
		parentEff, _ := hp.containerAnalyzer.GetEffectivePermissions(parentURI)
		hp.containerAnalyzer.ProcessContainer(project.URI, &project.Policies, parentEff, false)
	}
}

func (hp *HierarchyProcessor) collectResources(assetTypes []string) error {
	for _, org := range hp.hierarchy.Organizations {
		if err := hp.collectResourcesInContainer(org.URI, assetTypes); err != nil {
			return err
		}
	}
	return nil
}

func (hp *HierarchyProcessor) collectResourcesInContainer(containerURI string, assetTypes []string) error {
	if strings.HasPrefix(containerURI, "projects/") {
		resources, err := hp.resourceCollector.ListResourcesWithPolicies(containerURI, assetTypes)
		if err != nil {
			fmt.Printf("Warning: failed to collect resources in %s: %v\n", containerURI, err)
			return nil
		}
		hp.allResources = append(hp.allResources, resources...)
	}
	node := hp.ancestryBuilder.GetNode(containerURI)
	switch n := node.(type) {
	case *gcptypes.Organization:
		for _, folder := range n.Folders {
			if err := hp.collectResourcesInContainer(folder.URI, assetTypes); err != nil {
				return err
			}
		}
		for _, project := range n.Projects {
			if err := hp.collectResourcesInContainer(project.URI, assetTypes); err != nil {
				return err
			}
		}
	case *gcptypes.Folder:
		for _, folder := range n.Folders {
			if err := hp.collectResourcesInContainer(folder.URI, assetTypes); err != nil {
				return err
			}
		}
		for _, project := range n.Projects {
			if err := hp.collectResourcesInContainer(project.URI, assetTypes); err != nil {
				return err
			}
		}
	}
	return nil
}

func (hp *HierarchyProcessor) runResourcePass() []*gcptypes.PermissionTuple {
	hp.resourceAnalyzer = NewResourceAnalyzer(
		hp.containerAnalyzer,
		hp.selectorEvaluator,
		hp.ancestryBuilder,
		hp.roleExpander,
		hp.normalizer,
	)
	allTuples := make([]*gcptypes.PermissionTuple, 0)
	for _, resource := range hp.allResources {
		tuples := hp.resourceAnalyzer.EvaluateResource(resource)
		allTuples = append(allTuples, tuples...)
	}
	return allTuples
}

func (hp *HierarchyProcessor) GetTuples() []*gcptypes.PermissionTuple {
	if hp.resourceAnalyzer == nil {
		return nil
	}
	return hp.runResourcePass()
}

func (hp *HierarchyProcessor) GetHierarchy() *gcptypes.Hierarchy {
	return hp.hierarchy
}
