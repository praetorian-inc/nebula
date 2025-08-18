package cloudcontrol

import (
	"fmt"
	"log/slog"
	"math/rand"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSCloudControl struct {
	*base.AwsReconLink
	semaphores            map[string]chan struct{}           // per-region semaphores
	serviceRegionSemaphores map[string]chan struct{}         // per (service+region) semaphores
	globalSemaphore       chan struct{}                      // global connection limit
	serviceSemaphore      chan struct{}
	regionWorkSemaphore   chan struct{}                      // limit concurrent listResourcesInRegion goroutines
	wg                    sync.WaitGroup
	serviceWg             sync.WaitGroup
	cloudControlClients   map[string]*cloudcontrol.Client
	maxConcurrentServices int
	maxGlobalConnections  int                                // limit total concurrent connections
	maxConcurrentRegionWork int                              // limit concurrent region work goroutines
	resourceQueue         chan string                        // queue of individual resource types
	processedResources    sync.Map                          // concurrent map to track processed resource types
	startOnce             sync.Once
	workerStarted         bool
	workerMu              sync.Mutex                         // protects workerStarted
	pendingResources      []string                          // buffer for resource types before processing
	mu                    sync.Mutex                         // protects pendingResources and serviceRegionSemaphores
}

func (a *AWSCloudControl) Metadata() *cfg.Metadata {
	return &cfg.Metadata{Name: "AWS CloudControl"}
}

func (a *AWSCloudControl) Params() []cfg.Param {
	params := a.AwsReconLink.Params()
	params = append(params, options.AwsCommonReconOptions()...)
	params = append(params, options.AwsRegions(), options.AwsResourceType())
	params = append(params, cfg.NewParam[int]("max-concurrent-services", "Maximum number of AWS services to process concurrently").
		WithDefault(1000))
	params = append(params, cfg.NewParam[int]("max-global-connections", "Maximum total concurrent connections (to avoid port exhaustion)").
		WithDefault(13000))
	params = append(params, cfg.NewParam[int]("max-concurrent-region-work", "Maximum concurrent goroutines for region work (to avoid goroutine explosion)").
		WithDefault(2000))

	return params
}

func NewAWSCloudControl(configs ...cfg.Config) chain.Link {
	cc := &AWSCloudControl{
		wg:                      sync.WaitGroup{},
		serviceWg:               sync.WaitGroup{},
		maxConcurrentServices:   1000, // Default to 1000 concurrent services
		maxGlobalConnections:    13000, // Default to 13000 total connections (~80% of macOS default 16383)
		maxConcurrentRegionWork: 2000, // Default to 2000 concurrent region work goroutines
	}
	cc.AwsReconLink = base.NewAwsReconLink(cc, configs...)

	return cc
}

func (a *AWSCloudControl) Initialize() error {
	if err := a.AwsReconLink.Initialize(); err != nil {
		return err
	}

	// Configure max concurrent services from parameters
	if maxServices, err := cfg.As[int](a.Arg("max-concurrent-services")); err == nil {
		if maxServices > 0 && maxServices <= 10000 { // Reasonable bounds
			a.maxConcurrentServices = maxServices
		}
	}

	// Configure max global connections from parameters
	if maxConnections, err := cfg.As[int](a.Arg("max-global-connections")); err == nil {
		if maxConnections > 0 && maxConnections <= 30000 { // Keep well below port limit
			a.maxGlobalConnections = maxConnections
		}
	}

	// Configure max concurrent region work from parameters
	if maxRegionWork, err := cfg.As[int](a.Arg("max-concurrent-region-work")); err == nil {
		if maxRegionWork > 0 && maxRegionWork <= 50000 { // Reasonable bounds for goroutines
			a.maxConcurrentRegionWork = maxRegionWork
		}
	}

	a.initializeClients()
	a.initializeSemaphores()
	a.initializeServiceSemaphore()
	a.initializeRegionWorkSemaphore()
	a.resourceQueue = make(chan string, 1000) // Buffer for individual resource types
	a.pendingResources = make([]string, 0)
	return nil
}

func (a *AWSCloudControl) initializeSemaphores() {
	a.semaphores = make(map[string]chan struct{})
	a.serviceRegionSemaphores = make(map[string]chan struct{})
	
	// Dynamically check ephemeral port range and adjust global limit
	availablePorts := a.getAvailableEphemeralPorts()
	if a.maxGlobalConnections > availablePorts {
		slog.Warn("Reducing maxGlobalConnections to available ephemeral ports", 
			"requested", a.maxGlobalConnections, 
			"available", availablePorts)
		a.maxGlobalConnections = availablePorts
	}
	
	a.globalSemaphore = make(chan struct{}, a.maxGlobalConnections)
	
	// Region semaphores are only for result sending, not API rate limiting
	// Keep a small limit for result processing
	resultSendLimit := 10
	
	slog.Info("Initializing semaphores", 
		"globalLimit", a.maxGlobalConnections,
		"resultSendLimit", resultSendLimit,
		"availablePorts", availablePorts)
	
	for _, region := range a.Regions {
		a.semaphores[region] = make(chan struct{}, resultSendLimit)
	}
}

func (a *AWSCloudControl) getAvailableEphemeralPorts() int {
	switch runtime.GOOS {
	case "darwin":
		return a.getMacOSEphemeralPorts()
	case "linux":
		return a.getLinuxEphemeralPorts()
	default:
		slog.Warn("Unknown OS, using conservative port limit", "os", runtime.GOOS)
		return 1000 // Conservative default
	}
}

func (a *AWSCloudControl) getMacOSEphemeralPorts() int {
	first, err := exec.Command("sysctl", "-n", "net.inet.ip.portrange.first").Output()
	if err != nil {
		slog.Error("Failed to get portrange.first", "error", err)
		return 1000
	}
	
	last, err := exec.Command("sysctl", "-n", "net.inet.ip.portrange.last").Output()
	if err != nil {
		slog.Error("Failed to get portrange.last", "error", err)
		return 1000
	}
	
	firstPort, err := strconv.Atoi(strings.TrimSpace(string(first)))
	if err != nil {
		return 1000
	}
	
	lastPort, err := strconv.Atoi(strings.TrimSpace(string(last)))
	if err != nil {
		return 1000
	}
	
	// Reserve 20% for other applications and OS
	available := int(float64(lastPort-firstPort+1) * 0.8)
	slog.Debug("macOS ephemeral port range", "first", firstPort, "last", lastPort, "available", available)
	return available
}

func (a *AWSCloudControl) getLinuxEphemeralPorts() int {
	output, err := exec.Command("cat", "/proc/sys/net/ipv4/ip_local_port_range").Output()
	if err != nil {
		slog.Error("Failed to read Linux port range", "error", err)
		return 1000
	}
	
	parts := strings.Fields(strings.TrimSpace(string(output)))
	if len(parts) != 2 {
		return 1000
	}
	
	first, err := strconv.Atoi(parts[0])
	if err != nil {
		return 1000
	}
	
	last, err := strconv.Atoi(parts[1])
	if err != nil {
		return 1000
	}
	
	// Reserve 20% for other applications and OS
	available := int(float64(last-first+1) * 0.8)
	slog.Debug("Linux ephemeral port range", "first", first, "last", last, "available", available)
	return available
}

func (a *AWSCloudControl) initializeServiceSemaphore() {
	a.serviceSemaphore = make(chan struct{}, a.maxConcurrentServices)
}

func (a *AWSCloudControl) initializeRegionWorkSemaphore() {
	a.regionWorkSemaphore = make(chan struct{}, a.maxConcurrentRegionWork)
}

func (a *AWSCloudControl) extractServiceName(resourceType string) string {
	// Extract service name from AWS::ServiceName::ResourceType
	parts := strings.Split(resourceType, ":")
	if len(parts) >= 3 {
		return parts[2] // Return the service name part
	}
	return "Unknown"
}

func (a *AWSCloudControl) getServiceRegionKey(serviceName, region string) string {
	return fmt.Sprintf("%s:%s", serviceName, region)
}

func (a *AWSCloudControl) ensureServiceRegionSemaphore(serviceName, region string) chan struct{} {
	key := a.getServiceRegionKey(serviceName, region)
	
	a.mu.Lock()
	defer a.mu.Unlock()
	
	if sem, exists := a.serviceRegionSemaphores[key]; exists {
		return sem
	}
	
	// Create semaphore with limit based on service type
	// AWS CloudControl rate limits vary by service, defaulting to 5 per service+region
	limit := 5
	a.serviceRegionSemaphores[key] = make(chan struct{}, limit)
	return a.serviceRegionSemaphores[key]
}

func (a *AWSCloudControl) addResourceType(resourceType string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pendingResources = append(a.pendingResources, resourceType)
}

func (a *AWSCloudControl) sendResourcesRandomly() {
	// Copy pending resources under mutex protection
	a.mu.Lock()
	resourcesCopy := make([]string, len(a.pendingResources))
	copy(resourcesCopy, a.pendingResources)
	totalResourceTypes := len(resourcesCopy)
	a.mu.Unlock()
	
	slog.Info("Sending resources for parallel processing", "totalResourceTypes", totalResourceTypes, "maxConcurrentServices", a.maxConcurrentServices)
	
	// Shuffle resources randomly to avoid processing hotspots
	rand.Shuffle(len(resourcesCopy), func(i, j int) {
		resourcesCopy[i], resourcesCopy[j] = resourcesCopy[j], resourcesCopy[i]
	})
	
	// Send randomized resources to queue
	for _, resourceType := range resourcesCopy {
		slog.Debug("Queuing resource type", "type", resourceType)
		a.resourceQueue <- resourceType
	}
}

func (a *AWSCloudControl) startWorkerPool() {
	// Start worker goroutines to process individual resource types
	for i := 0; i < a.maxConcurrentServices; i++ {
		a.serviceWg.Add(1)
		go a.resourceWorker()
	}
	
	// Set workerStarted flag with mutex protection
	a.workerMu.Lock()
	a.workerStarted = true
	a.workerMu.Unlock()
}

func (a *AWSCloudControl) resourceWorker() {
	defer a.serviceWg.Done()

	for resourceType := range a.resourceQueue {
		a.processResourceTypeWithDedupe(resourceType)
	}
}

func (a *AWSCloudControl) processResourceTypeWithDedupe(resourceType string) {
	// Check if already processed using compare-and-swap
	if _, loaded := a.processedResources.LoadOrStore(resourceType, true); loaded {
		slog.Debug("Skipping already processed resource type", "type", resourceType)
		return
	}
	
	slog.Debug("Processing resource type", "type", resourceType)

	for _, region := range a.Regions {
		if a.isGlobalService(resourceType, region) {
			slog.Debug("Skipping global service", "type", resourceType, "region", region)
			continue
		}

		a.wg.Add(1)
		go func(rt, r string) {
			// Acquire semaphore to limit concurrent goroutines
			a.regionWorkSemaphore <- struct{}{}
			defer func() { <-a.regionWorkSemaphore }()
			
			a.listResourcesInRegion(rt, r)
		}(resourceType, region)
	}

	slog.Debug("cloudcontrol queued for processing", "resourceType", resourceType)
}

func (a *AWSCloudControl) processResourceType(resourceType string) {
	a.processResourceTypeWithDedupe(resourceType)
}

func (a *AWSCloudControl) initializeClients() error {
	a.cloudControlClients = make(map[string]*cloudcontrol.Client)

	for _, region := range a.Regions {
		config, err := a.GetConfigWithRuntimeArgs(region)
		if err != nil {
			return fmt.Errorf("failed to create AWS config: %w", err)
		}

		a.cloudControlClients[region] = cloudcontrol.NewFromConfig(config)
	}

	return nil
}

func (a *AWSCloudControl) Process(resourceType string) error {
	// Start worker pool on first call
	a.startOnce.Do(func() {
		a.startWorkerPool()
	})

	// Add resource type to pending list
	a.addResourceType(resourceType)

	return nil
}

func (a *AWSCloudControl) isGlobalService(resourceType, region string) bool {
	return helpers.IsGlobalService(resourceType) && region != "us-east-1"
}

func (a *AWSCloudControl) listResourcesInRegion(resourceType, region string) {
	defer a.wg.Done()

	// Apply global connection limit first
	a.globalSemaphore <- struct{}{}
	defer func() { <-a.globalSemaphore }()

	serviceName := a.extractServiceName(resourceType)
	
	// Apply service+region specific limit
	serviceRegionSem := a.ensureServiceRegionSemaphore(serviceName, region)
	serviceRegionSem <- struct{}{}
	defer func() { <-serviceRegionSem }()

	message.Info("Listing %s resources in %s (profile: %s)", resourceType, region, a.Profile)
	slog.Debug("Listing resources in region", "type", resourceType, "region", region, "profile", a.Profile)

	config, err := a.GetConfigWithRuntimeArgs(region)

	if err != nil {
		slog.Error("Failed to create AWS config", "error", err)
		return
	}

	accountId, err := helpers.GetAccountId(config)
	if err != nil {
		slog.Error("Failed to get account ID", "error", err, "region", region)
		return
	}

	cc := a.cloudControlClients[region]

	paginator := cloudcontrol.NewListResourcesPaginator(cc, &cloudcontrol.ListResourcesInput{
		TypeName:   &resourceType,
		MaxResults: aws.Int32(100),
	})

	for paginator.HasMorePages() {
		res, err := paginator.NextPage(a.Context())

		if err != nil {
			err, shouldBreak := a.processError(resourceType, region, err)
			if err != nil {
				slog.Error("Failed to list resources", "error", err)
				return
			}

			if shouldBreak {
				break
			}
		}

		for _, resource := range res.ResourceDescriptions {
			erd := a.resourceDescriptionToERD(resource, resourceType, accountId, region)
			a.sendResource(region, erd)
		}

	}
}

func (a *AWSCloudControl) processError(resourceType, region string, err error) (error, bool) {
	errMsg := err.Error()
	switch {
	case strings.Contains(errMsg, "TypeNotFoundException"):
		return fmt.Errorf("%s is not available in region %s", resourceType, region), true

	case strings.Contains(errMsg, "is not authorized to perform") || strings.Contains(errMsg, "AccessDeniedException"):
		return fmt.Errorf("access denied to list resources of type %s in region %s: %s", resourceType, region, errMsg), true

	case strings.Contains(errMsg, "UnsupportedActionException"):
		return fmt.Errorf("the type %s is not supported in region %s", resourceType, region), true

	case strings.Contains(errMsg, "ThrottlingException"):
		// Log throttling but don't terminate - let AWS SDK retry with backoff
		return fmt.Errorf("rate limited: %s", errMsg), false

	default:
		return fmt.Errorf("failed to ListResources of type %s in region %s: %w", resourceType, region, err), false
	}
}

func (a *AWSCloudControl) resourceDescriptionToERD(resource cctypes.ResourceDescription, rType, accountId, region string) *types.EnrichedResourceDescription {
	var erdRegion string
	if helpers.IsGlobalService(rType) {
		erdRegion = ""
	} else {
		erdRegion = region
	}

	erd := types.NewEnrichedResourceDescription(
		*resource.Identifier,
		rType,
		erdRegion,
		accountId,
		*resource.Properties,
	)

	return &erd

}

func (a *AWSCloudControl) sendResource(region string, resource *types.EnrichedResourceDescription) {
	// Apply region-specific limit for sending resources
	sem := a.semaphores[region]
	sem <- struct{}{}
	defer func() { <-sem }()

	a.Send(resource)
}

func (a *AWSCloudControl) Complete() error {
	// Check if workers were started with mutex protection
	a.workerMu.Lock()
	started := a.workerStarted
	a.workerMu.Unlock()
	
	if started {
		// Send all resources to the queue with random distribution
		a.sendResourcesRandomly()
		// Close the queue to signal workers to finish
		close(a.resourceQueue)
		// Wait for all resource workers to complete
		a.serviceWg.Wait()
	}
	// Wait for any remaining region workers
	a.wg.Wait()
	return nil
}

func (a *AWSCloudControl) SupportedResourceTypes() []string {
	return []string{
		"AWS::AccessAnalyzer::Analyzer",
		"AWS::ACMPCA::CertificateAuthority",
		"AWS::Amplify::App",
		"AWS::ApiGateway::ApiKey",
		"AWS::ApiGateway::ClientCertificate",
		"AWS::ApiGateway::DomainName",
		"AWS::ApiGateway::RestApi",
		"AWS::ApiGateway::UsagePlan",
		"AWS::ApiGateway::VpcLink",
		"AWS::ApiGatewayV2::Api",
		"AWS::ApiGatewayV2::DomainName",
		"AWS::ApiGatewayV2::VpcLink",
		"AWS::AppConfig::Application",
		"AWS::AppConfig::DeploymentStrategy",
		"AWS::AppConfig::Extension",
		"AWS::AppConfig::ExtensionAssociation",
		"AWS::AppFlow::Connector",
		"AWS::AppFlow::ConnectorProfile",
		"AWS::AppFlow::Flow",
		"AWS::AppIntegrations::Application",
		"AWS::AppIntegrations::DataIntegration",
		"AWS::AppIntegrations::EventIntegration",
		"AWS::ApplicationInsights::Application",
		"AWS::ApplicationSignals::ServiceLevelObjective",
		"AWS::AppRunner::AutoScalingConfiguration",
		"AWS::AppRunner::ObservabilityConfiguration",
		"AWS::AppRunner::Service",
		"AWS::AppRunner::VpcConnector",
		"AWS::AppRunner::VpcIngressConnection",
		"AWS::AppStream::AppBlockBuilder",
		"AWS::AppSync::Api",
		"AWS::AppSync::DomainName",
		"AWS::AppTest::TestCase",
		"AWS::APS::Scraper",
		"AWS::APS::Workspace",
		"AWS::ARCZonalShift::AutoshiftObserverNotificationStatus",
		"AWS::ARCZonalShift::ZonalAutoshiftConfiguration",
		"AWS::Athena::CapacityReservation",
		"AWS::Athena::DataCatalog",
		"AWS::Athena::NamedQuery",
		"AWS::Athena::WorkGroup",
		"AWS::AutoScaling::AutoScalingGroup",
		"AWS::AutoScaling::LaunchConfiguration",
		"AWS::AutoScaling::ScalingPolicy",
		"AWS::AutoScaling::ScheduledAction",
		"AWS::B2BI::Capability",
		"AWS::B2BI::Partnership",
		"AWS::B2BI::Profile",
		"AWS::B2BI::Transformer",
		"AWS::Backup::BackupPlan",
		"AWS::Backup::BackupSelection",
		"AWS::Backup::BackupVault",
		"AWS::Backup::Framework",
		"AWS::Backup::LogicallyAirGappedBackupVault",
		"AWS::Backup::ReportPlan",
		"AWS::Backup::RestoreTestingPlan",
		"AWS::Backup::RestoreTestingSelection",
		"AWS::BackupGateway::Hypervisor",
		"AWS::Batch::ComputeEnvironment",
		"AWS::Batch::JobQueue",
		"AWS::Batch::SchedulingPolicy",
		"AWS::BCMDataExports::Export",
		"AWS::Bedrock::Agent",
		"AWS::Bedrock::ApplicationInferenceProfile",
		"AWS::Bedrock::Flow",
		"AWS::Bedrock::Guardrail",
		"AWS::Bedrock::KnowledgeBase",
		"AWS::Bedrock::Prompt",
		"AWS::Budgets::BudgetsAction",
		"AWS::Cassandra::Keyspace",
		"AWS::Cassandra::Table",
		"AWS::CE::AnomalyMonitor",
		"AWS::CE::AnomalySubscription",
		"AWS::Chatbot::MicrosoftTeamsChannelConfiguration",
		"AWS::Chatbot::SlackChannelConfiguration",
		"AWS::CleanRooms::Collaboration",
		"AWS::CleanRooms::ConfiguredTable",
		"AWS::CleanRooms::Membership",
		"AWS::CleanRoomsML::TrainingDataset",
		"AWS::CloudFormation::GuardHook",
		"AWS::CloudFormation::HookDefaultVersion",
		"AWS::CloudFormation::HookTypeConfig",
		"AWS::CloudFormation::HookVersion",
		"AWS::CloudFormation::LambdaHook",
		"AWS::CloudFormation::ModuleDefaultVersion",
		"AWS::CloudFormation::PublicTypeVersion",
		"AWS::CloudFormation::Stack",
		"AWS::CloudFormation::StackSet",
		"AWS::CloudFormation::TypeActivation",
		"AWS::CloudFront::CachePolicy",
		"AWS::CloudFront::CloudFrontOriginAccessIdentity",
		"AWS::CloudFront::ContinuousDeploymentPolicy",
		"AWS::CloudFront::Distribution",
		"AWS::CloudFront::Function",
		"AWS::CloudFront::KeyGroup",
		"AWS::CloudFront::KeyValueStore",
		"AWS::CloudFront::OriginAccessControl",
		"AWS::CloudFront::OriginRequestPolicy",
		"AWS::CloudFront::PublicKey",
		"AWS::CloudFront::RealtimeLogConfig",
		"AWS::CloudFront::ResponseHeadersPolicy",
		"AWS::CloudTrail::Channel",
		"AWS::CloudTrail::EventDataStore",
		"AWS::CloudTrail::Trail",
		"AWS::CloudWatch::Alarm",
		"AWS::CloudWatch::CompositeAlarm",
		"AWS::CloudWatch::Dashboard",
		"AWS::CloudWatch::MetricStream",
		"AWS::CodeArtifact::Domain",
		"AWS::CodeArtifact::Repository",
		"AWS::CodeBuild::Fleet",
		"AWS::CodeConnections::Connection",
		"AWS::CodeDeploy::Application",
		"AWS::CodeDeploy::DeploymentConfig",
		"AWS::CodeGuruProfiler::ProfilingGroup",
		"AWS::CodeGuruReviewer::RepositoryAssociation",
		"AWS::CodePipeline::CustomActionType",
		"AWS::CodePipeline::Pipeline",
		"AWS::CodeStarConnections::Connection",
		"AWS::CodeStarConnections::RepositoryLink",
		"AWS::CodeStarConnections::SyncConfiguration",
		"AWS::CodeStarNotifications::NotificationRule",
		"AWS::Cognito::IdentityPool",
		"AWS::Cognito::UserPool",
		"AWS::Comprehend::DocumentClassifier",
		"AWS::Comprehend::Flywheel",
		"AWS::Config::AggregationAuthorization",
		"AWS::Config::ConfigRule",
		"AWS::Config::ConfigurationAggregator",
		"AWS::Config::ConformancePack",
		"AWS::Config::OrganizationConformancePack",
		"AWS::Config::StoredQuery",
		"AWS::Connect::Instance",
		"AWS::Connect::TrafficDistributionGroup",
		"AWS::ConnectCampaigns::Campaign",
		"AWS::ControlTower::LandingZone",
		"AWS::CUR::ReportDefinition",
		"AWS::DataBrew::Dataset",
		"AWS::DataBrew::Job",
		"AWS::DataBrew::Project",
		"AWS::DataBrew::Recipe",
		"AWS::DataBrew::Ruleset",
		"AWS::DataBrew::Schedule",
		"AWS::DataSync::Agent",
		"AWS::DataSync::LocationAzureBlob",
		"AWS::DataSync::LocationEFS",
		"AWS::DataSync::LocationFSxLustre",
		"AWS::DataSync::LocationFSxONTAP",
		"AWS::DataSync::LocationFSxOpenZFS",
		"AWS::DataSync::LocationFSxWindows",
		"AWS::DataSync::LocationHDFS",
		"AWS::DataSync::LocationNFS",
		"AWS::DataSync::LocationObjectStorage",
		"AWS::DataSync::LocationS3",
		"AWS::DataSync::LocationSMB",
		"AWS::DataSync::StorageSystem",
		"AWS::DataSync::Task",
		"AWS::DataZone::Domain",
		"AWS::Deadline::Farm",
		"AWS::Deadline::LicenseEndpoint",
		"AWS::Deadline::Monitor",
		"AWS::Detective::Graph",
		"AWS::Detective::MemberInvitation",
		"AWS::DeviceFarm::InstanceProfile",
		"AWS::DeviceFarm::Project",
		"AWS::DeviceFarm::TestGridProject",
		"AWS::DevOpsGuru::LogAnomalyDetectionIntegration",
		"AWS::DevOpsGuru::NotificationChannel",
		"AWS::DevOpsGuru::ResourceCollection",
		"AWS::DMS::DataMigration",
		"AWS::DMS::DataProvider",
		"AWS::DMS::InstanceProfile",
		"AWS::DMS::MigrationProject",
		"AWS::DMS::ReplicationConfig",
		"AWS::DocDBElastic::Cluster",
		"AWS::DynamoDB::GlobalTable",
		"AWS::DynamoDB::Table",
		"AWS::EC2::CapacityReservation",
		"AWS::EC2::CapacityReservationFleet",
		"AWS::EC2::CarrierGateway",
		"AWS::EC2::CustomerGateway",
		"AWS::EC2::DHCPOptions",
		"AWS::EC2::EC2Fleet",
		"AWS::EC2::EgressOnlyInternetGateway",
		"AWS::EC2::EIP",
		"AWS::EC2::EIPAssociation",
		"AWS::EC2::FlowLog",
		"AWS::EC2::Host",
		"AWS::EC2::Instance",
		"AWS::EC2::InstanceConnectEndpoint",
		"AWS::EC2::InternetGateway",
		"AWS::EC2::IPAM",
		"AWS::EC2::IPAMPool",
		"AWS::EC2::IPAMResourceDiscovery",
		"AWS::EC2::IPAMResourceDiscoveryAssociation",
		"AWS::EC2::IPAMScope",
		"AWS::EC2::KeyPair",
		"AWS::EC2::LaunchTemplate",
		"AWS::EC2::LocalGatewayRoute",
		"AWS::EC2::LocalGatewayRouteTable",
		"AWS::EC2::LocalGatewayRouteTableVirtualInterfaceGroupAssociation",
		"AWS::EC2::LocalGatewayRouteTableVPCAssociation",
		"AWS::EC2::NatGateway",
		"AWS::EC2::NetworkAcl",
		"AWS::EC2::NetworkInsightsAccessScope",
		"AWS::EC2::NetworkInsightsAccessScopeAnalysis",
		"AWS::EC2::NetworkInsightsAnalysis",
		"AWS::EC2::NetworkInsightsPath",
		"AWS::EC2::NetworkInterface",
		"AWS::EC2::NetworkInterfaceAttachment",
		"AWS::EC2::NetworkPerformanceMetricSubscription",
		"AWS::EC2::PlacementGroup",
		"AWS::EC2::PrefixList",
		"AWS::EC2::RouteTable",
		"AWS::EC2::SecurityGroup",
		"AWS::EC2::SecurityGroupEgress",
		"AWS::EC2::SecurityGroupIngress",
		"AWS::EC2::SecurityGroupVpcAssociation",
		"AWS::EC2::SnapshotBlockPublicAccess",
		"AWS::EC2::SpotFleet",
		"AWS::EC2::Subnet",
		"AWS::EC2::SubnetCidrBlock",
		"AWS::EC2::SubnetNetworkAclAssociation",
		"AWS::EC2::SubnetRouteTableAssociation",
		"AWS::EC2::TransitGateway",
		"AWS::EC2::TransitGatewayAttachment",
		"AWS::EC2::TransitGatewayConnect",
		"AWS::EC2::TransitGatewayMulticastDomain",
		"AWS::EC2::TransitGatewayPeeringAttachment",
		"AWS::EC2::TransitGatewayRouteTable",
		"AWS::EC2::TransitGatewayVpcAttachment",
		"AWS::EC2::VerifiedAccessEndpoint",
		"AWS::EC2::VerifiedAccessGroup",
		"AWS::EC2::VerifiedAccessInstance",
		"AWS::EC2::VerifiedAccessTrustProvider",
		"AWS::EC2::Volume",
		"AWS::EC2::VolumeAttachment",
		"AWS::EC2::VPC",
		"AWS::EC2::VPCDHCPOptionsAssociation",
		"AWS::EC2::VPCEndpoint",
		"AWS::EC2::VPCEndpointConnectionNotification",
		"AWS::EC2::VPCEndpointService",
		"AWS::EC2::VPCEndpointServicePermissions",
		"AWS::EC2::VPCGatewayAttachment",
		"AWS::EC2::VPCPeeringConnection",
		"AWS::EC2::VPNConnection",
		"AWS::EC2::VPNConnectionRoute",
		"AWS::EC2::VPNGateway",
		"AWS::ECR::PublicRepository",
		"AWS::ECR::PullThroughCacheRule",
		"AWS::ECR::RegistryPolicy",
		"AWS::ECR::ReplicationConfiguration",
		"AWS::ECR::Repository",
		"AWS::ECR::RepositoryCreationTemplate",
		"AWS::ECS::CapacityProvider",
		"AWS::ECS::Cluster",
		"AWS::ECS::ClusterCapacityProviderAssociations",
		"AWS::ECS::Service",
		"AWS::ECS::TaskDefinition",
		"AWS::EFS::AccessPoint",
		"AWS::EFS::FileSystem",
		"AWS::EKS::Cluster",
		"AWS::ElastiCache::GlobalReplicationGroup",
		"AWS::ElastiCache::ParameterGroup",
		"AWS::ElastiCache::ServerlessCache",
		"AWS::ElastiCache::SubnetGroup",
		"AWS::ElastiCache::User",
		"AWS::ElastiCache::UserGroup",
		"AWS::ElasticBeanstalk::Application",
		"AWS::ElasticBeanstalk::ApplicationVersion",
		"AWS::ElasticBeanstalk::ConfigurationTemplate",
		"AWS::ElasticBeanstalk::Environment",
		"AWS::ElasticLoadBalancingV2::LoadBalancer",
		"AWS::ElasticLoadBalancingV2::TargetGroup",
		"AWS::ElasticLoadBalancingV2::TrustStore",
		"AWS::EMR::SecurityConfiguration",
		"AWS::EMR::Studio",
		"AWS::EMR::StudioSessionMapping",
		"AWS::EMR::WALWorkspace",
		"AWS::EMRContainers::VirtualCluster",
		"AWS::EMRServerless::Application",
		"AWS::EntityResolution::IdMappingWorkflow",
		"AWS::EntityResolution::IdNamespace",
		"AWS::EntityResolution::MatchingWorkflow",
		"AWS::EntityResolution::SchemaMapping",
		"AWS::Events::ApiDestination",
		"AWS::Events::Archive",
		"AWS::Events::Connection",
		"AWS::Events::Endpoint",
		"AWS::Events::EventBus",
		"AWS::Events::Rule",
		"AWS::EventSchemas::Discoverer",
		"AWS::EventSchemas::Registry",
		"AWS::FinSpace::Environment",
		"AWS::FIS::ExperimentTemplate",
		"AWS::Forecast::Dataset",
		"AWS::Forecast::DatasetGroup",
		"AWS::FraudDetector::Detector",
		"AWS::FraudDetector::EntityType",
		"AWS::FraudDetector::EventType",
		"AWS::FraudDetector::Label",
		"AWS::FraudDetector::List",
		"AWS::FraudDetector::Outcome",
		"AWS::FraudDetector::Variable",
		"AWS::FSx::DataRepositoryAssociation",
		"AWS::GameLift::Alias",
		"AWS::GameLift::Build",
		"AWS::GameLift::ContainerFleet",
		"AWS::GameLift::ContainerGroupDefinition",
		"AWS::GameLift::Fleet",
		"AWS::GameLift::GameServerGroup",
		"AWS::GameLift::GameSessionQueue",
		"AWS::GameLift::Location",
		"AWS::GameLift::Script",
		"AWS::GlobalAccelerator::Accelerator",
		"AWS::GlobalAccelerator::CrossAccountAttachment",
		"AWS::Glue::Crawler",
		"AWS::Glue::Database",
		"AWS::Glue::Job",
		"AWS::Glue::Registry",
		"AWS::Glue::Schema",
		"AWS::Glue::Trigger",
		"AWS::Glue::UsageProfile",
		"AWS::Grafana::Workspace",
		"AWS::GreengrassV2::Deployment",
		"AWS::GroundStation::Config",
		"AWS::GroundStation::DataflowEndpointGroup",
		"AWS::GroundStation::MissionProfile",
		"AWS::GuardDuty::Detector",
		"AWS::GuardDuty::MalwareProtectionPlan",
		"AWS::HealthImaging::Datastore",
		"AWS::HealthLake::FHIRDatastore",
		"AWS::IAM::Group",
		"AWS::IAM::InstanceProfile",
		"AWS::IAM::ManagedPolicy",
		"AWS::IAM::OIDCProvider",
		"AWS::IAM::Role",
		"AWS::IAM::SAMLProvider",
		"AWS::IAM::ServerCertificate",
		"AWS::IAM::User",
		"AWS::IAM::VirtualMFADevice",
		"AWS::ImageBuilder::ContainerRecipe",
		"AWS::ImageBuilder::DistributionConfiguration",
		"AWS::ImageBuilder::ImagePipeline",
		"AWS::ImageBuilder::ImageRecipe",
		"AWS::ImageBuilder::InfrastructureConfiguration",
		"AWS::ImageBuilder::LifecyclePolicy",
		"AWS::Inspector::AssessmentTarget",
		"AWS::Inspector::AssessmentTemplate",
		"AWS::InspectorV2::Filter",
		"AWS::InternetMonitor::Monitor",
		"AWS::IoT::AccountAuditConfiguration",
		"AWS::IoT::Authorizer",
		"AWS::IoT::BillingGroup",
		"AWS::IoT::CACertificate",
		"AWS::IoT::Certificate",
		"AWS::IoT::CertificateProvider",
		"AWS::IoT::CustomMetric",
		"AWS::IoT::Dimension",
		"AWS::IoT::DomainConfiguration",
		"AWS::IoT::FleetMetric",
		"AWS::IoT::JobTemplate",
		"AWS::IoT::Logging",
		"AWS::IoT::MitigationAction",
		"AWS::IoT::Policy",
		"AWS::IoT::ProvisioningTemplate",
		"AWS::IoT::ResourceSpecificLogging",
		"AWS::IoT::RoleAlias",
		"AWS::IoT::ScheduledAudit",
		"AWS::IoT::SecurityProfile",
		"AWS::IoT::SoftwarePackage",
		"AWS::IoT::Thing",
		"AWS::IoT::ThingGroup",
		"AWS::IoT::TopicRule",
		"AWS::IoT::TopicRuleDestination",
		"AWS::IoTAnalytics::Channel",
		"AWS::IoTAnalytics::Dataset",
		"AWS::IoTAnalytics::Datastore",
		"AWS::IoTAnalytics::Pipeline",
		"AWS::IoTCoreDeviceAdvisor::SuiteDefinition",
		"AWS::IoTEvents::AlarmModel",
		"AWS::IoTEvents::DetectorModel",
		"AWS::IoTEvents::Input",
		"AWS::IoTFleetWise::Campaign",
		"AWS::IoTFleetWise::DecoderManifest",
		"AWS::IoTFleetWise::Fleet",
		"AWS::IoTFleetWise::ModelManifest",
		"AWS::IoTFleetWise::SignalCatalog",
		"AWS::IoTFleetWise::Vehicle",
		"AWS::IoTSiteWise::Asset",
		"AWS::IoTSiteWise::AssetModel",
		"AWS::IoTSiteWise::Gateway",
		"AWS::IoTSiteWise::Portal",
		"AWS::IoTTwinMaker::Workspace",
		"AWS::IoTWireless::Destination",
		"AWS::IoTWireless::DeviceProfile",
		"AWS::IoTWireless::FuotaTask",
		"AWS::IoTWireless::MulticastGroup",
		"AWS::IoTWireless::NetworkAnalyzerConfiguration",
		"AWS::IoTWireless::PartnerAccount",
		"AWS::IoTWireless::ServiceProfile",
		"AWS::IoTWireless::TaskDefinition",
		"AWS::IoTWireless::WirelessDevice",
		"AWS::IoTWireless::WirelessDeviceImportTask",
		"AWS::IoTWireless::WirelessGateway",
		"AWS::IVS::Channel",
		"AWS::IVS::EncoderConfiguration",
		"AWS::IVS::PlaybackKeyPair",
		"AWS::IVS::PlaybackRestrictionPolicy",
		"AWS::IVS::PublicKey",
		"AWS::IVS::RecordingConfiguration",
		"AWS::IVS::Stage",
		"AWS::IVS::StorageConfiguration",
		"AWS::IVSChat::LoggingConfiguration",
		"AWS::IVSChat::Room",
		"AWS::KafkaConnect::Connector",
		"AWS::KafkaConnect::CustomPlugin",
		"AWS::KafkaConnect::WorkerConfiguration",
		"AWS::Kendra::Index",
		"AWS::KendraRanking::ExecutionPlan",
		"AWS::Kinesis::Stream",
		"AWS::KinesisAnalyticsV2::Application",
		"AWS::KinesisFirehose::DeliveryStream",
		"AWS::KMS::Alias",
		"AWS::KMS::Key",
		"AWS::KMS::ReplicaKey",
		"AWS::LakeFormation::DataCellsFilter",
		"AWS::LakeFormation::Tag",
		"AWS::Lambda::CodeSigningConfig",
		"AWS::Lambda::EventSourceMapping",
		"AWS::Lambda::Function",
		"AWS::LaunchWizard::Deployment",
		"AWS::Lex::Bot",
		"AWS::Lightsail::Alarm",
		"AWS::Lightsail::Bucket",
		"AWS::Lightsail::Certificate",
		"AWS::Lightsail::Container",
		"AWS::Lightsail::Database",
		"AWS::Lightsail::Disk",
		"AWS::Lightsail::Distribution",
		"AWS::Lightsail::Instance",
		"AWS::Lightsail::LoadBalancer",
		"AWS::Lightsail::StaticIp",
		"AWS::Location::APIKey",
		"AWS::Location::GeofenceCollection",
		"AWS::Location::Map",
		"AWS::Location::PlaceIndex",
		"AWS::Location::RouteCalculator",
		"AWS::Location::Tracker",
		"AWS::Logs::Delivery",
		"AWS::Logs::DeliveryDestination",
		"AWS::Logs::DeliverySource",
		"AWS::Logs::Destination",
		"AWS::Logs::LogAnomalyDetector",
		"AWS::Logs::LogGroup",
		"AWS::Logs::MetricFilter",
		"AWS::Logs::QueryDefinition",
		"AWS::Logs::ResourcePolicy",
		"AWS::LookoutEquipment::InferenceScheduler",
		"AWS::LookoutMetrics::Alert",
		"AWS::LookoutMetrics::AnomalyDetector",
		"AWS::LookoutVision::Project",
		"AWS::M2::Application",
		"AWS::M2::Environment",
		"AWS::Macie::Session",
		"AWS::ManagedBlockchain::Accessor",
		"AWS::MediaConnect::Bridge",
		"AWS::MediaConnect::Flow",
		"AWS::MediaConnect::Gateway",
		"AWS::MediaLive::CloudWatchAlarmTemplate",
		"AWS::MediaLive::CloudWatchAlarmTemplateGroup",
		"AWS::MediaLive::EventBridgeRuleTemplate",
		"AWS::MediaLive::EventBridgeRuleTemplateGroup",
		"AWS::MediaLive::Multiplex",
		"AWS::MediaLive::SignalMap",
		"AWS::MediaPackage::Channel",
		"AWS::MediaPackage::OriginEndpoint",
		"AWS::MediaPackage::PackagingGroup",
		"AWS::MediaPackageV2::ChannelGroup",
		"AWS::MediaTailor::Channel",
		"AWS::MediaTailor::PlaybackConfiguration",
		"AWS::MediaTailor::SourceLocation",
		"AWS::MemoryDB::ACL",
		"AWS::MemoryDB::Cluster",
		"AWS::MemoryDB::ParameterGroup",
		"AWS::MemoryDB::SubnetGroup",
		"AWS::MemoryDB::User",
		"AWS::MSK::Cluster",
		"AWS::MSK::Configuration",
		"AWS::MSK::Replicator",
		"AWS::MSK::ServerlessCluster",
		"AWS::MSK::VpcConnection",
		"AWS::MWAA::Environment",
		"AWS::Neptune::DBCluster",
		"AWS::NeptuneGraph::Graph",
		"AWS::NetworkFirewall::Firewall",
		"AWS::NetworkFirewall::FirewallPolicy",
		"AWS::NetworkFirewall::RuleGroup",
		"AWS::NetworkFirewall::TLSInspectionConfiguration",
		"AWS::NetworkManager::ConnectAttachment",
		"AWS::NetworkManager::ConnectPeer",
		"AWS::NetworkManager::CoreNetwork",
		"AWS::NetworkManager::GlobalNetwork",
		"AWS::NetworkManager::SiteToSiteVpnAttachment",
		"AWS::NetworkManager::TransitGatewayPeering",
		"AWS::NetworkManager::TransitGatewayRouteTableAttachment",
		"AWS::NetworkManager::VpcAttachment",
		"AWS::Oam::Link",
		"AWS::Oam::Sink",
		"AWS::Omics::AnnotationStore",
		"AWS::Omics::ReferenceStore",
		"AWS::Omics::RunGroup",
		"AWS::Omics::SequenceStore",
		"AWS::Omics::VariantStore",
		"AWS::Omics::Workflow",
		"AWS::OpenSearchServerless::Collection",
		"AWS::OpenSearchServerless::VpcEndpoint",
		"AWS::OpenSearchService::Application",
		"AWS::Organizations::Organization",
		"AWS::OSIS::Pipeline",
		"AWS::Panorama::ApplicationInstance",
		"AWS::Panorama::Package",
		"AWS::PaymentCryptography::Alias",
		"AWS::PaymentCryptography::Key",
		"AWS::PCAConnectorAD::Connector",
		"AWS::PCAConnectorAD::DirectoryRegistration",
		"AWS::PCAConnectorSCEP::Connector",
		"AWS::Personalize::Dataset",
		"AWS::Personalize::DatasetGroup",
		"AWS::Personalize::Schema",
		"AWS::Personalize::Solution",
		"AWS::Pinpoint::InAppTemplate",
		"AWS::Pipes::Pipe",
		"AWS::Proton::EnvironmentAccountConnection",
		"AWS::Proton::EnvironmentTemplate",
		"AWS::Proton::ServiceTemplate",
		"AWS::QBusiness::Application",
		"AWS::RAM::Permission",
		"AWS::RDS::CustomDBEngineVersion",
		"AWS::RDS::DBCluster",
		"AWS::RDS::DBClusterParameterGroup",
		"AWS::RDS::DBInstance",
		"AWS::RDS::DBParameterGroup",
		"AWS::RDS::DBProxy",
		"AWS::RDS::DBProxyEndpoint",
		"AWS::RDS::DBShardGroup",
		"AWS::RDS::DBSubnetGroup",
		"AWS::RDS::EventSubscription",
		"AWS::RDS::GlobalCluster",
		"AWS::RDS::Integration",
		"AWS::RDS::OptionGroup",
		"AWS::Redshift::Cluster",
		"AWS::Redshift::ClusterParameterGroup",
		"AWS::Redshift::ClusterSubnetGroup",
		"AWS::Redshift::EndpointAccess",
		"AWS::Redshift::EndpointAuthorization",
		"AWS::Redshift::EventSubscription",
		"AWS::Redshift::Integration",
		"AWS::Redshift::ScheduledAction",
		"AWS::RedshiftServerless::Namespace",
		"AWS::RedshiftServerless::Workgroup",
		"AWS::RefactorSpaces::Environment",
		"AWS::Rekognition::Collection",
		"AWS::Rekognition::Project",
		"AWS::Rekognition::StreamProcessor",
		"AWS::ResilienceHub::App",
		"AWS::ResilienceHub::ResiliencyPolicy",
		"AWS::ResourceExplorer2::Index",
		"AWS::ResourceExplorer2::View",
		"AWS::ResourceGroups::Group",
		"AWS::RoboMaker::RobotApplication",
		"AWS::RoboMaker::SimulationApplication",
		"AWS::RolesAnywhere::CRL",
		"AWS::RolesAnywhere::Profile",
		"AWS::RolesAnywhere::TrustAnchor",
		"AWS::Route53::CidrCollection",
		"AWS::Route53::DNSSEC",
		"AWS::Route53::HealthCheck",
		"AWS::Route53::HostedZone",
		"AWS::Route53::KeySigningKey",
		"AWS::Route53Profiles::Profile",
		"AWS::Route53Profiles::ProfileAssociation",
		"AWS::Route53RecoveryControl::Cluster",
		"AWS::Route53RecoveryControl::ControlPanel",
		"AWS::Route53RecoveryReadiness::Cell",
		"AWS::Route53RecoveryReadiness::ReadinessCheck",
		"AWS::Route53RecoveryReadiness::RecoveryGroup",
		"AWS::Route53RecoveryReadiness::ResourceSet",
		"AWS::Route53Resolver::FirewallDomainList",
		"AWS::Route53Resolver::FirewallRuleGroup",
		"AWS::Route53Resolver::FirewallRuleGroupAssociation",
		"AWS::Route53Resolver::OutpostResolver",
		"AWS::Route53Resolver::ResolverConfig",
		"AWS::Route53Resolver::ResolverDNSSECConfig",
		"AWS::Route53Resolver::ResolverQueryLoggingConfig",
		"AWS::Route53Resolver::ResolverQueryLoggingConfigAssociation",
		"AWS::Route53Resolver::ResolverRule",
		"AWS::Route53Resolver::ResolverRuleAssociation",
		"AWS::RUM::AppMonitor",
		"AWS::S3::AccessGrantsInstance",
		"AWS::S3::AccessPoint",
		"AWS::S3::Bucket",
		"AWS::S3::BucketPolicy",
		"AWS::S3::MultiRegionAccessPoint",
		"AWS::S3::StorageLens",
		"AWS::S3::StorageLensGroup",
		"AWS::S3Express::BucketPolicy",
		"AWS::S3Express::DirectoryBucket",
		"AWS::S3ObjectLambda::AccessPoint",
		"AWS::S3Outposts::Endpoint",
		"AWS::SageMaker::App",
		"AWS::SageMaker::AppImageConfig",
		"AWS::SageMaker::Cluster",
		"AWS::SageMaker::DataQualityJobDefinition",
		"AWS::SageMaker::Domain",
		"AWS::SageMaker::FeatureGroup",
		"AWS::SageMaker::Image",
		"AWS::SageMaker::InferenceComponent",
		"AWS::SageMaker::InferenceExperiment",
		"AWS::SageMaker::MlflowTrackingServer",
		"AWS::SageMaker::ModelBiasJobDefinition",
		"AWS::SageMaker::ModelCard",
		"AWS::SageMaker::ModelExplainabilityJobDefinition",
		"AWS::SageMaker::ModelPackage",
		"AWS::SageMaker::ModelPackageGroup",
		"AWS::SageMaker::ModelQualityJobDefinition",
		"AWS::SageMaker::MonitoringSchedule",
		"AWS::SageMaker::Pipeline",
		"AWS::SageMaker::Project",
		"AWS::SageMaker::Space",
		"AWS::SageMaker::StudioLifecycleConfig",
		"AWS::SageMaker::UserProfile",
		"AWS::Scheduler::Schedule",
		"AWS::Scheduler::ScheduleGroup",
		"AWS::SecretsManager::ResourcePolicy",
		"AWS::SecretsManager::RotationSchedule",
		"AWS::SecretsManager::Secret",
		"AWS::SecretsManager::SecretTargetAttachment",
		"AWS::SecurityHub::Hub",
		"AWS::ServiceCatalog::ServiceAction",
		"AWS::ServiceCatalogAppRegistry::Application",
		"AWS::ServiceCatalogAppRegistry::AttributeGroup",
		"AWS::SES::ConfigurationSet",
		"AWS::SES::ContactList",
		"AWS::SES::DedicatedIpPool",
		"AWS::SES::EmailIdentity",
		"AWS::SES::MailManagerAddonInstance",
		"AWS::SES::MailManagerAddonSubscription",
		"AWS::SES::MailManagerArchive",
		"AWS::SES::MailManagerIngressPoint",
		"AWS::SES::MailManagerRelay",
		"AWS::SES::MailManagerRuleSet",
		"AWS::SES::MailManagerTrafficPolicy",
		"AWS::SES::Template",
		"AWS::Signer::SigningProfile",
		"AWS::SimSpaceWeaver::Simulation",
		"AWS::SNS::Subscription",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
		"AWS::SSM::Association",
		"AWS::SSM::Document",
		"AWS::SSM::Parameter",
		"AWS::SSM::PatchBaseline",
		"AWS::SSM::ResourceDataSync",
		"AWS::SSM::ResourcePolicy",
		"AWS::SSMContacts::Contact",
		"AWS::SSMIncidents::ReplicationSet",
		"AWS::SSMIncidents::ResponsePlan",
		"AWS::SSMQuickSetup::ConfigurationManager",
		"AWS::SSO::Instance",
		"AWS::StepFunctions::Activity",
		"AWS::StepFunctions::StateMachine",
		"AWS::SupportApp::AccountAlias",
		"AWS::SupportApp::SlackChannelConfiguration",
		"AWS::SupportApp::SlackWorkspaceConfiguration",
		"AWS::Synthetics::Canary",
		"AWS::Synthetics::Group",
		"AWS::SystemsManagerSAP::Application",
		"AWS::Timestream::Database",
		"AWS::Timestream::InfluxDBInstance",
		"AWS::Timestream::ScheduledQuery",
		"AWS::Timestream::Table",
		"AWS::Transfer::Certificate",
		"AWS::Transfer::Connector",
		"AWS::Transfer::Profile",
		"AWS::Transfer::Server",
		"AWS::Transfer::Workflow",
		"AWS::VerifiedPermissions::PolicyStore",
		"AWS::VoiceID::Domain",
		"AWS::VpcLattice::Service",
		"AWS::VpcLattice::ServiceNetwork",
		"AWS::VpcLattice::TargetGroup",
		"AWS::WAFv2::LoggingConfiguration",
		"AWS::Wisdom::Assistant",
		"AWS::Wisdom::KnowledgeBase",
		"AWS::WorkSpaces::WorkspacesPool",
		"AWS::WorkSpacesThinClient::Environment",
		"AWS::WorkSpacesWeb::BrowserSettings",
		"AWS::WorkSpacesWeb::IpAccessSettings",
		"AWS::WorkSpacesWeb::NetworkSettings",
		"AWS::WorkSpacesWeb::Portal",
		"AWS::WorkSpacesWeb::TrustStore",
		"AWS::WorkSpacesWeb::UserAccessLoggingSettings",
		"AWS::WorkSpacesWeb::UserSettings",
		"AWS::XRay::Group",
		"AWS::XRay::ResourcePolicy",
		"AWS::XRay::SamplingRule",
	}

}
