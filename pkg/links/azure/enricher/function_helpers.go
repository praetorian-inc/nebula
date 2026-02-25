package enricher

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
)

// HTTPTriggerInfo holds parsed HTTP trigger metadata from the Management API.
// Shared between FunctionAppEnricher and AppServiceEnricher.
type HTTPTriggerInfo struct {
	FunctionName string
	AuthLevel    string
	InvokeURL    string
	Route        string
	Methods      []string
	IsDisabled   bool
	SlotName     string // empty for production slot
}

// ListHTTPTriggers enumerates functions in a Function App via the Management API and
// parses HTTP trigger metadata from the bindings configuration.
// slotName should be empty for the production slot.
func ListHTTPTriggers(ctx context.Context, client *armappservice.WebAppsClient, resourceGroupName, functionAppName, slotName string) ([]HTTPTriggerInfo, int, error) {
	var allFunctions []*armappservice.FunctionEnvelope

	if slotName == "" {
		pager := client.NewListFunctionsPager(resourceGroupName, functionAppName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, 0, fmt.Errorf("listing functions: %w", err)
			}
			allFunctions = append(allFunctions, page.Value...)
		}
	} else {
		pager := client.NewListInstanceFunctionsSlotPager(resourceGroupName, functionAppName, slotName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, 0, fmt.Errorf("listing functions for slot %s: %w", slotName, err)
			}
			allFunctions = append(allFunctions, page.Value...)
		}
	}

	var triggers []HTTPTriggerInfo
	totalFunctions := len(allFunctions)

	for _, function := range allFunctions {
		if function.Properties == nil || function.Properties.Config == nil {
			continue
		}

		configMap, ok := function.Properties.Config.(map[string]interface{})
		if !ok {
			continue
		}

		bindingsRaw, exists := configMap["bindings"]
		if !exists {
			continue
		}

		bindings, ok := bindingsRaw.([]interface{})
		if !ok {
			continue
		}

		for _, binding := range bindings {
			bindingMap, ok := binding.(map[string]interface{})
			if !ok {
				continue
			}

			bindingType, _ := bindingMap["type"].(string)
			if bindingType != "httpTrigger" {
				continue
			}

			authLevel, _ := bindingMap["authLevel"].(string)
			route, _ := bindingMap["route"].(string)

			var methods []string
			if methodsRaw, exists := bindingMap["methods"]; exists {
				if methodsArr, ok := methodsRaw.([]interface{}); ok {
					for _, m := range methodsArr {
						if method, ok := m.(string); ok {
							methods = append(methods, method)
						}
					}
				}
			}

			functionName := ""
			invokeURL := ""
			isDisabled := false

			if function.Name != nil {
				functionName = *function.Name
				// Strip "appname/" prefix if present (API returns "appname/funcname")
				if idx := strings.LastIndex(functionName, "/"); idx >= 0 {
					functionName = functionName[idx+1:]
				}
			}
			if function.Properties.InvokeURLTemplate != nil {
				invokeURL = *function.Properties.InvokeURLTemplate
			}
			if function.Properties.IsDisabled != nil {
				isDisabled = *function.Properties.IsDisabled
			}

			triggers = append(triggers, HTTPTriggerInfo{
				FunctionName: functionName,
				AuthLevel:    authLevel,
				InvokeURL:    invokeURL,
				Route:        route,
				Methods:      methods,
				IsDisabled:   isDisabled,
				SlotName:     slotName,
			})
		}
	}

	return triggers, totalFunctions, nil
}

// EasyAuthStatus represents the result of an EasyAuth check.
type EasyAuthStatus struct {
	Enabled bool
	Err     error
}

// CheckEasyAuth queries the App Service Authentication V2 settings to determine
// whether platform-level authentication (EasyAuth / Entra ID) is enabled.
func CheckEasyAuth(ctx context.Context, client *armappservice.WebAppsClient, resourceGroupName, appName string) EasyAuthStatus {
	authSettings, err := client.GetAuthSettingsV2(ctx, resourceGroupName, appName, nil)
	if err != nil {
		return EasyAuthStatus{Err: fmt.Errorf("getting auth settings: %w", err)}
	}

	enabled := false
	if authSettings.Properties != nil && authSettings.Properties.Platform != nil && authSettings.Properties.Platform.Enabled != nil {
		enabled = *authSettings.Properties.Platform.Enabled
	}

	return EasyAuthStatus{Enabled: enabled}
}
