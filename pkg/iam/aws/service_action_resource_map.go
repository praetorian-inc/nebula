package aws

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// ServiceResourceMap defines valid actions for resource types within a service
type ServiceResourceMap struct {
	// Maps resource type to regex pattern for ARN matching
	ResourcePatterns map[string]*regexp.Regexp
	// Maps actions to valid resource types
	ActionResourceMap map[string][]string
}

// IsValidActionForResource checks if an action is valid for a given resource ARN
func IsValidActionForResource(action, resource string) bool {

	// Parse service and action name
	parts := strings.Split(action, ":")
	if len(parts) != 2 {
		slog.Debug("Invalid action format", slog.String("action", action))
		return false
	}
	service := strings.ToLower(parts[0])
	actionName := strings.ToLower(parts[1])

	// Get service map
	// assume true if we don't have a map for the service
	serviceMap, exists := serviceResourceMaps[service]
	if !exists {
		slog.Debug("Service not found in serviceResourceMaps, assuming valid", slog.String("service", service))
		return true
	}

	// Get valid resource types for action
	validResourceTypes, exists := serviceMap.ActionResourceMap[actionName]
	if !exists {
		slog.Debug("Action not found in service map", slog.String("action", actionName), slog.String("service", service))
		return false
	}
	
	// Check each valid resource type
	for _, resourceType := range validResourceTypes {
		// Get pattern for resource type
		pattern, exists := serviceMap.ResourcePatterns[resourceType]
		if !exists {
			slog.Debug("Pattern not found for resource type", slog.String("resourceType", resourceType))
			continue
		}

		// Check if resource ARN matches pattern
		if pattern.MatchString(resource) {
			return true
		}
	}

	return false
}

func getResourcePatternsFromAction(action Action) []*regexp.Regexp {
	patterns := []*regexp.Regexp{}
	service := action.Service()
	act := strings.ToLower(strings.Split(string(action), ":")[1])

	serviceMap, exists := serviceResourceMaps[service]
	if exists {
		for _, resourceType := range serviceMap.ActionResourceMap[act] {
			if serviceMap.ResourcePatterns[resourceType] != nil {
				patterns = append(patterns, serviceMap.ResourcePatterns[resourceType])
			}
		}
		slog.Debug("Resource patterns", slog.String("action", string(action)), slog.String("patterns", fmt.Sprintf("%v", patterns)))
		return patterns

	} else {
		slog.Debug("Service not found in serviceResourceMaps", "service", service)
	}

	return []*regexp.Regexp{regexp.MustCompile(fmt.Sprintf("arn:aws:%s:*:*:*", service))}

}

// serviceResourceMaps contains the mappings for each AWS service
var serviceResourceMaps = map[string]ServiceResourceMap{
	"iam": {
		ResourcePatterns: map[string]*regexp.Regexp{
			"user":               regexp.MustCompile(`^arn:aws:iam::\d{12}:user/.*`),
			"group":              regexp.MustCompile(`^arn:aws:iam::\d{12}:group/.*`),
			"role":               regexp.MustCompile(`^arn:aws:iam::\d{12}:role/.*`),
			"policy":             regexp.MustCompile(`^arn:aws:iam::(\d{12}|aws):policy/.*`),
			"custom-policy":      regexp.MustCompile(`^arn:aws:iam::(\d{12}):policy/.*`),
			"instance-profile":   regexp.MustCompile(`^arn:aws:iam::\d{12}:instance-profile/.*`),
			"mfa":                regexp.MustCompile(`^arn:aws:iam::\d{12}:mfa/.*`),
			"oidc-provider":      regexp.MustCompile(`^arn:aws:iam::\d{12}:oidc-provider/.*`),
			"saml-provider":      regexp.MustCompile(`^arn:aws:iam::\d{12}:saml-provider/.*`),
			"server-certificate": regexp.MustCompile(`^arn:aws:iam::\d{12}:server-certificate/.*`),
			"service":            regexp.MustCompile(`^iam.amazonaws.com$`),
		},
		ActionResourceMap: map[string][]string{
			"addclientidtoopenidconnectprovider":      {"oidc-provider"},
			"addroletoinstanceprofile":                {"instance-profile"},
			"addusertogroup":                          {"group"},
			"attachgrouppolicy":                       {"group"},
			"attachrolepolicy":                        {"role"},
			"attachuserpolicy":                        {"user"},
			"changepassword":                          {"user"},
			"createaccesskey":                         {"user"},
			"creategroup":                             {"service"},
			"createinstanceprofile":                   {"instance-profile"},
			"createloginprofile":                      {"user"},
			"createopenidconnectprovider":             {"oidc-provider"},
			"createpolicy":                            {"policy"},
			"createpolicyversion":                     {"custom-policy"},
			"createrole":                              {"service"},
			"createsamlprovider":                      {"saml-provider"},
			"createservicelinkedrole":                 {"role"},
			"createservicespecificcredential":         {"user"},
			"createuser":                              {"service"},
			"createvirtualmfadevice":                  {"mfa"},
			"deactivatemfadevice":                     {"user"},
			"deleteaccesskey":                         {"user"},
			"deletegroup":                             {"group"},
			"deletegrouppolicy":                       {"group"},
			"deleteinstanceprofile":                   {"instance-profile"},
			"deleteloginprofile":                      {"user"},
			"deleteopenidconnectprovider":             {"oidc-provider"},
			"deletepolicy":                            {"policy"},
			"deletepolicyversion":                     {"policy"},
			"deleterole":                              {"role"},
			"deleterolepermissionsboundary":           {"role"},
			"deleterolepolicy":                        {"role"},
			"deletesamlprovider":                      {"saml-provider"},
			"deletesshpublickey":                      {"user"},
			"deleteservercertificate":                 {"server-certificate"},
			"deleteservicelinkedrole":                 {"role"},
			"deleteservicespecificcredential":         {"user"},
			"deletesigningcertificate":                {"user"},
			"deleteuser":                              {"user"},
			"deleteuserpermissionsboundary":           {"user"},
			"deleteuserpolicy":                        {"user"},
			"deletevirtualmfadevice":                  {"mfa"},
			"detachgrouppolicy":                       {"group"},
			"detachrolepolicy":                        {"role"},
			"detachuserpolicy":                        {"user"},
			"enablemfadevice":                         {"user"},
			"generateservicelastaccesseddetails":      {"group", "role", "user", "policy"},
			"getaccesskeylastused":                    {"user"},
			"getgroup":                                {"group"},
			"getgrouppolicy":                          {"group"},
			"getinstanceprofile":                      {"instance-profile"},
			"getloginprofile":                         {"user"},
			"getmfadevice":                            {"user"},
			"getopenidconnectprovider":                {"oidc-provider"},
			"getpolicy":                               {"policy"},
			"getpolicyversion":                        {"policy"},
			"getrole":                                 {"role"},
			"getrolepolicy":                           {"role"},
			"getsamlprovider":                         {"saml-provider"},
			"getsshpublickey":                         {"user"},
			"getservercertificate":                    {"server-certificate"},
			"getservicelinkedroledeletionstatus":      {"role"},
			"getuser":                                 {"user"},
			"getuserpolicy":                           {"user"},
			"listaccesskeys":                          {"user"},
			"listattachedgrouppolicies":               {"group"},
			"listattachedrolepolicies":                {"role"},
			"listattachuserpolicies":                  {"user"},
			"listgrouppolicies":                       {"group"},
			"listgroupsforuser":                       {"user"},
			"listinstanceprofiletags":                 {"instance-profile"},
			"listinstanceprofilesforrole":             {"role"},
			"listmfadevicetags":                       {"mfa"},
			"listmfadevices":                          {"user"},
			"listopenidconnectprovidertags":           {"oidc-provider"},
			"listpolicytags":                          {"policy"},
			"listpolicyversions":                      {"policy"},
			"listrolepolicies":                        {"role"},
			"listroletags":                            {"role"},
			"listsamlprovidertags":                    {"saml-provider"},
			"listsshpublickeys":                       {"user"},
			"listservercertificatetags":               {"server-certificate"},
			"listservicespecificcredentials":          {"user"},
			"listsigningcertificates":                 {"user"},
			"listuserpolicies":                        {"user"},
			"listusertags":                            {"user"},
			"passrole":                                {"role"},
			"putgrouppolicy":                          {"group"},
			"putrolepermissionsboundary":              {"role"},
			"putrolepolicy":                           {"role"},
			"putuserpermissionsboundary":              {"user"},
			"putuserpolicy":                           {"user"},
			"removeclientidfromopenidconnectprovider": {"oidc-provider"},
			"removerolefrominstanceprofile":           {"instance-profile"},
			"removeuserfromgroup":                     {"group"},
			"resetservicespecificcredential":          {"user"},
			"resyncmfadevice":                         {"user"},
			"setdefaultpolicyversion":                 {"policy"},
			"taginstanceprofile":                      {"instance-profile"},
			"tagmfadevice":                            {"mfa"},
			"tagopenidconnectprovider":                {"oidc-provider"},
			"tagpolicy":                               {"policy"},
			"tagrole":                                 {"role"},
			"tagsamlprovider":                         {"saml-provider"},
			"tagservercertificate":                    {"server-certificate"},
			"taguser":                                 {"user"},
			"untaginstanceprofile":                    {"instance-profile"},
			"untagmfadevice":                          {"mfa"},
			"untagopenidconnectprovider":              {"oidc-provider"},
			"untagpolicy":                             {"policy"},
			"untagrole":                               {"role"},
			"untagsamlprovider":                       {"saml-provider"},
			"untagservercertificate":                  {"server-certificate"},
			"untaguser":                               {"user"},
			"updateaccesskey":                         {"user"},
			"updateassumerolepolicy":                  {"role"},
			"updategroup":                             {"group"},
			"updateloginprofile":                      {"user"},
			"updateopenidconnectproviderthumbprint":   {"oidc-provider"},
			"updaterole":                              {"role"},
			"updateroledescription":                   {"role"},
			"updatesamlprovider":                      {"saml-provider"},
			"updatesshpublickey":                      {"user"},
			"updateservercertificate":                 {"server-certificate"},
			"updateservicespecificcredential":         {"user"},
			"updatesigningcertificate":                {"user"},
			"updateuser":                              {"user"},
			"uploadsshpublickey":                      {"user"},
			"uploadservercertificate":                 {"server-certificate"},
			"uploadsigningcertificate":                {"user"},
		},
	},
	"ec2": {
		ResourcePatterns: map[string]*regexp.Regexp{
			"service":  regexp.MustCompile(`^ec2.amazonaws.com$`),
			"instance": regexp.MustCompile(`^arn:aws:ec2:[a-z-0-9]+:\d{12}:instance/.*`),
			"volume":   regexp.MustCompile(`^arn:aws:ec2:[a-z-0-9]+:\d{12}:volume/.*`),
			"snapshot": regexp.MustCompile(`^arn:aws:ec2:[a-z-0-9]+:\d{12}:snapshot/.*`),
			"image":    regexp.MustCompile(`^arn:aws:ec2:[a-z-0-9]+:\d{12}:image/.*`),
		},
		ActionResourceMap: map[string][]string{
			"runinstances": {"service"},
		},
	},
	"cloudformation": {
		ResourcePatterns: map[string]*regexp.Regexp{
			"service":  regexp.MustCompile(`^cloudformation.amazonaws.com$`),
			"stack":    regexp.MustCompile(`^arn:aws:cloudformation:[a-z-0-9]+:\d{12}:stack/.*`),
			"stackset": regexp.MustCompile(`^arn:aws:cloudformation:[a-z-0-9]+:\d{12}:stackset/.*`),
		},
		ActionResourceMap: map[string][]string{
			"createstack":      {"service"},
			"updatestack":      {"stack"},
			"setstackpolicy":   {"stack"},
			"createchangeset":  {"stack"},
			"executechangeset": {"stack"},
			"createstackset":   {"stackset"},
			"updatestackset":   {"stackset"},
		},
	},
	"sts": {
		ResourcePatterns: map[string]*regexp.Regexp{
			"role":   regexp.MustCompile(`^arn:aws:iam::\d{12}:role/.*`),
			"policy": regexp.MustCompile(`^arn:aws:iam::(\d{12}|aws):policy/.*`),
		},
		ActionResourceMap: map[string][]string{
			"assumerole": {"role"},
			// TODO: populate resources with federated users
			//"getfederationtoken": {"federated-user"},
		},
	},
	"lambda": {
		ResourcePatterns: map[string]*regexp.Regexp{
			"function":    regexp.MustCompile(`^arn:aws:lambda:[a-z-0-9]+:\d{12}:function:.*$`),
			"layer":       regexp.MustCompile(`^arn:aws:lambda:[a-z-0-9]+:\d{12}:layer:.*$`),
			"eventconfig": regexp.MustCompile(`^arn:aws:lambda:[a-z-0-9]+:\d{12}:event-source-mapping:.*$`),
			"service":     regexp.MustCompile(`^lambda.amazonaws.com$`),
		},
		ActionResourceMap: map[string][]string{
			"addlayerversionpermission":          {"layer"},
			"addpermission":                      {"function"},
			"createalias":                        {"function"},
			"createcodeSigningconfig":            {"function"},
			"createeventSourcemapping":           {"function", "eventconfig"},
			"createfunction":                     {"service"},
			"deletealias":                        {"function"},
			"deletecodesigningconfig":            {"function"},
			"deleteeventsourcemapping":           {"eventconfig"},
			"deletefunction":                     {"function"},
			"deletefunctionconcurrency":          {"function"},
			"deletefunctioneventinvokeconfig":    {"function"},
			"deletelayerversion":                 {"layer"},
			"deleteprovisionedconcurrencyconfig": {"function"},
			"enablereplication":                  {"function"},
			"getaccountsettings":                 {"function"},
			"getalias":                           {"function"},
			"getcodesigningconfig":               {"function"},
			"geteventSourcemapping":              {"eventconfig"},
			"getfunction":                        {"function"},
			"getfunctioncodeSigningconfig":       {"function"},
			"getfunctionconcurrency":             {"function"},
			"getfunctionconfiguration":           {"function"},
			"getfunctioneventinvokeconfig":       {"function"},
			"getlayerversion":                    {"layer"},
			"getlayerversionpolicy":              {"layer"},
			"getpolicy":                          {"function"},
			"getprovisionedconcurrencyconfig":    {"function"},
			"invokefunction":                     {"function", "service"},
			"invokefunctionurl":                  {"function"},
			"invokeAsync":                        {"function"},
			"listaliases":                        {"function"},
			"listcodesigningconfigs":             {"function"},
			"listeventsourcemappings":            {"function", "eventconfig"},
			"listfunctioneventinvokeconfigs":     {"function"},
			"listfunctions":                      {"function"},
			"listlayerversions":                  {"layer"},
			"listlayers":                         {"layer"},
			"listprovisionedconcurrencyconfigs":  {"function"},
			"listtags":                           {"function", "layer", "eventconfig"},
			"listversionsbyfunction":             {"function"},
			"publishlayerversion":                {"layer"},
			"publishversion":                     {"function"},
			"putfunctionconcurrency":             {"function"},
			"putfunctioneventinvokeconfig":       {"function"},
			"putprovisionedconcurrencyconfig":    {"function"},
			"removelayerversionpermission":       {"layer"},
			"removepermission":                   {"function"},
			"tagresource":                        {"function", "layer", "eventconfig"},
			"untagresource":                      {"function", "layer", "eventconfig"},
			"updatealias":                        {"function"},
			"updatecodesigningconfig":            {"function"},
			"updateeventSourcemapping":           {"eventconfig"},
			"updatefunctioncode":                 {"function"},
			"updatefunctionconfiguration":        {"function"},
			"updatefunctioneventinvokeconfig":    {"function"},
		},
	},
	"ecs": {
		ResourcePatterns: map[string]*regexp.Regexp{
			"service":        regexp.MustCompile(`^ecs.amazonaws.com$`),
			"cluster":        regexp.MustCompile(`^arn:aws:ecs:[a-z0-9-]+:\d{12}:cluster/.*$`),
			"task":           regexp.MustCompile(`^arn:aws:ecs:[a-z0-9-]+:\d{12}:task/.*$`),
			"task-def":       regexp.MustCompile(`^arn:aws:ecs:[a-z0-9-]+:\d{12}:task-definition/.*$`),
			"container-inst": regexp.MustCompile(`^arn:aws:ecs:[a-z0-9-]+:\d{12}:container-instance/.*$`),
		},
		ActionResourceMap: map[string][]string{
			"runtask":                {"cluster", "task-def", "service"},
			"registertaskdefinition": {"service"},
			"starttask":              {"cluster", "task-def", "service"},
			"updateservice":          {"service"},
		},
	},
	"ssm": {
		ResourcePatterns: map[string]*regexp.Regexp{
			"instance":         regexp.MustCompile(`^arn:aws:ec2:[a-z0-9-]+:\d{12}:instance/.*$`),
			"managed-instance": regexp.MustCompile(`^arn:aws:ssm:[a-z0-9-]+:\d{12}:managed-instance/.*$`),
			"document":         regexp.MustCompile(`^arn:aws:ssm:[a-z0-9-]+:(\d{12}|aws):document/.*$`),
			"automation":       regexp.MustCompile(`^arn:aws:ssm:[a-z0-9-]+:\d{12}:automation-definition/.*$`),
			"service":          regexp.MustCompile(`^ssm.amazonaws.com$`),
		},
		ActionResourceMap: map[string][]string{
			"sendcommand":             {"instance", "managed-instance", "document"},
			"startsession":            {"instance", "managed-instance"},
			"resumesession":           {"instance", "managed-instance"},
			"startautomationexecution": {"automation", "document"},
		},
	},
	"glue": {
		ResourcePatterns: map[string]*regexp.Regexp{
			"devEndpoint": regexp.MustCompile(`^arn:aws:glue:[a-z0-9-]+:\d{12}:devEndpoint/.*$`),
			"service":     regexp.MustCompile(`^glue.amazonaws.com$`),
		},
		ActionResourceMap: map[string][]string{
			"createdevendpoint": {"service"},
			"updatedevendpoint": {"devEndpoint"},
		},
	},
	"datapipeline": {
		ResourcePatterns: map[string]*regexp.Regexp{
			"pipeline": regexp.MustCompile(`^arn:aws:datapipeline:[a-z0-9-]+:\d{12}:pipeline/.*$`),
			"service":  regexp.MustCompile(`^datapipeline.amazonaws.com$`),
		},
		ActionResourceMap: map[string][]string{
			"createpipeline":        {"service"},
			"putpipelinedefinition": {"pipeline"},
		},
	},
}
