package enricher

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// VirtualMachineEnricher implements enrichment for virtual machines
type VirtualMachineEnricher struct{}

func (v *VirtualMachineEnricher) CanEnrich(templateID string) bool {
	return templateID == "virtual_machines_public_access" || templateID == "vm_privileged_managed_identity"
}

func (v *VirtualMachineEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	// Get template ID to determine which enrichment to perform
	templateID, _ := resource.Properties["templateID"].(string)

	// Route to appropriate enrichment logic
	switch templateID {
	case "vm_privileged_managed_identity":
		return v.checkPrivilegedManagedIdentity(ctx, resource)
	case "virtual_machines_public_access":
		return v.checkPublicAccess(ctx, resource)
	default:
		return []Command{}
	}
}

func (v *VirtualMachineEnricher) checkPublicAccess(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Get public IPs from the resource
	ips := make([]string, 0)
	if publicIPs, ok := resource.Properties["publicIPs"].([]any); ok {
		for _, ip := range publicIPs {
			if ipStr, ok := ip.(string); ok && ipStr != "" {
				ips = append(ips, ipStr)
			}
		}
	}
	if len(ips) == 0 {
		return commands
	}

	// Filter out empty IPs and create target list
	var targetIPs []string
	for _, ip := range ips {
		if ip != "" {
			targetIPs = append(targetIPs, ip)
		}
	}

	if len(targetIPs) == 0 {
		return commands
	}

	// Get open ports from ARG scan results
	openPorts := []string{}
	if ports, ok := resource.Properties["openPorts"].([]any); ok {
		for _, port := range ports {
			if portStr, ok := port.(string); ok && portStr != "" {
				openPorts = append(openPorts, portStr)
			}
		}
	}

	// Only add nmap command if there are open ports to scan
	if len(openPorts) == 0 {
		return commands
	}

	// Create port list for nmap (comma-separated)
	portList := strings.Join(openPorts, ",")

	// Create target IP list for nmap (space-separated)
	targetIPList := strings.Join(targetIPs, " ")

	// Add nmap command for network scanning using specific ports
	nmapCommand := Command{
		Command:                   fmt.Sprintf("nmap -sS -Pn -p %s -T5 %s", portList, targetIPList),
		Description:               "Network scan of the virtual machine on discovered open ports",
		ExpectedOutputDescription: "Detailed service information for open ports on the VM",
		ActualOutput:              "Manual execution required",
	}
	commands = append(commands, nmapCommand)

	return commands
}

// checkPrivilegedManagedIdentity checks if a VM's managed identity has privileged role assignments
func (v *VirtualMachineEnricher) checkPrivilegedManagedIdentity(ctx context.Context, resource *model.AzureResource) []Command {
	vmName := resource.Name
	subscriptionID := resource.AccountRef
	principalID, _ := resource.Properties["principalId"].(string)

	if vmName == "" || subscriptionID == "" || principalID == "" {
		return []Command{{
			Command:      "",
			Description:  "Check VM managed identity role assignments",
			ActualOutput: "Error: VM name, subscription ID, or principal ID is missing",
			ExitCode:     1,
		}}
	}

	// Query role assignments for this principal ID
	command := fmt.Sprintf("az role assignment list --assignee %s --subscription %s --query \"[?scope=='\\/subscriptions\\/%s'].{role:roleDefinitionName, scope:scope}\" -o json",
		principalID, subscriptionID, subscriptionID)

	// List of privileged roles to check for
	privilegedRoles := []string{"Owner", "Contributor", "User Access Administrator"}

	return []Command{
		{
			Command:                   command,
			Description:               "Check managed identity role assignments for privileged roles",
			ExpectedOutputDescription: fmt.Sprintf("Should not have privileged roles: %s", strings.Join(privilegedRoles, ", ")),
			ActualOutput:              fmt.Sprintf("Manual verification required - check if managed identity has any of these privileged roles: %s", strings.Join(privilegedRoles, ", ")),
			ExitCode:                  0,
		},
	}
}
