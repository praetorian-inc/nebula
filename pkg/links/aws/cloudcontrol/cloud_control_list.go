package cloudcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"golang.org/x/time/rate"
)

type AWSCloudControl struct {
	*base.AwsReconLink
	wg                    sync.WaitGroup
	cloudControlClients   map[string]*cloudcontrol.Client // serviceRegionKey -> client
	regionRateLimiters    map[string]*rate.Limiter        // region -> rate limiter
	maxConcurrentServices int
	globalRateLimit       int           // per-region rate limit in TPS (requests per second)
	cachedAccountId       string        // cached account ID to avoid duplicate STS calls
	workQueue             chan workItem // unified queue for all work items
	processedResources    sync.Map      // concurrent map to track processed resource types
	startOnce             sync.Once
	workerStarted         bool
	workerMu              sync.Mutex // protects workerStarted
	pendingResources      []string   // buffer for resource types before processing
	mu                    sync.Mutex // protects pendingResources
	// Debug metrics for rate limiting analysis (disabled in production)
	debugMetrics       *DebugMetrics
	enableDebugMetrics bool
	shutdownCtx        context.Context
	shutdownCancel     context.CancelFunc

	// Completion tracking for proper shutdown
	completionTracker *CompletionTracker
	totalExpectedWork int
	completedWork     atomic.Int64
}

// workItem represents a unit of work to be processed
type workItem struct {
	resourceType string
	region       string
	retryCount   int
	lastAttempt  time.Time
}

// DebugMetrics tracks request rates for analyzing throttling patterns
type DebugMetrics struct {
	serviceRequestCounts       sync.Map // map[serviceName]int64
	serviceRegionRequestCounts sync.Map // map[serviceRegionKey]int64
	metricsStartTime           time.Time
	lastReportTime             time.Time
	reportTicker               *time.Ticker
	stopChan                   chan struct{}
}

// CompletionTracker tracks completion of work across all regions
type CompletionTracker struct {
	mu                       sync.Mutex
	expectedResourceRegions  map[string]bool // resourceTypeRegionKey -> expected
	completedResourceRegions map[string]bool // resourceTypeRegionKey -> completed
	pendingRetries           map[string]int  // resourceTypeRegionKey -> retry count
	totalExpected            int
	totalCompleted           int
}

func NewCompletionTracker() *CompletionTracker {
	return &CompletionTracker{
		expectedResourceRegions:  make(map[string]bool),
		completedResourceRegions: make(map[string]bool),
		pendingRetries:           make(map[string]int),
	}
}

func NewCompletionTrackerWithExpectedCount(expectedCount int) *CompletionTracker {
	return &CompletionTracker{
		expectedResourceRegions:  make(map[string]bool),
		completedResourceRegions: make(map[string]bool),
		pendingRetries:           make(map[string]int),
		totalExpected:            expectedCount,
	}
}

// AddExpectedWork registers a resourceType+region combination as expected work
// Note: totalExpected is now set at initialization, this just tracks individual work items
func (ct *CompletionTracker) AddExpectedWork(resourceTypeRegionKey string) {
	if ct == nil {
		slog.Warn("CompletionTracker is nil, cannot add expected work", "resourceTypeRegion", resourceTypeRegionKey)
		return
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	if !ct.expectedResourceRegions[resourceTypeRegionKey] {
		ct.expectedResourceRegions[resourceTypeRegionKey] = true
		// Validation: warn if we're registering more work than expected
		registeredCount := len(ct.expectedResourceRegions)
		if registeredCount > ct.totalExpected {
			slog.Warn("Registered more work items than expected",
				"registered", registeredCount,
				"expected", ct.totalExpected,
				"resourceTypeRegion", resourceTypeRegionKey)
		}
	}
}

// AddPendingRetry increments pending retry count for a resourceType+region
func (ct *CompletionTracker) AddPendingRetry(resourceTypeRegionKey string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ct.pendingRetries[resourceTypeRegionKey]++
	slog.Debug("Added pending retry", "resourceTypeRegion", resourceTypeRegionKey, "pendingRetries", ct.pendingRetries[resourceTypeRegionKey])
}

// RemovePendingRetry decrements pending retry count for a resourceType+region
func (ct *CompletionTracker) RemovePendingRetry(resourceTypeRegionKey string) {
	if ct == nil {
		slog.Warn("CompletionTracker is nil, cannot remove pending retry", "resourceTypeRegion", resourceTypeRegionKey)
		return
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.pendingRetries[resourceTypeRegionKey] > 0 {
		ct.pendingRetries[resourceTypeRegionKey]--
		slog.Debug("Removed pending retry", "resourceTypeRegion", resourceTypeRegionKey, "pendingRetries", ct.pendingRetries[resourceTypeRegionKey])
	}
}

// MarkCompleted marks a resourceType+region combination as completed (only if no pending retries)
func (ct *CompletionTracker) MarkCompleted(resourceTypeRegionKey string) {
	if ct == nil {
		slog.Warn("CompletionTracker is nil, cannot mark completed", "resourceTypeRegion", resourceTypeRegionKey)
		return
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Only mark as completed if there are no pending retries
	if ct.expectedResourceRegions[resourceTypeRegionKey] && !ct.completedResourceRegions[resourceTypeRegionKey] && ct.pendingRetries[resourceTypeRegionKey] == 0 {
		ct.completedResourceRegions[resourceTypeRegionKey] = true
		ct.totalCompleted++
		slog.Debug("Marked resourceType+region as completed", "resourceTypeRegion", resourceTypeRegionKey, "progress", fmt.Sprintf("%d/%d", ct.totalCompleted, ct.totalExpected))
	} else if ct.pendingRetries[resourceTypeRegionKey] > 0 {
		slog.Debug("Cannot mark as completed - has pending retries", "resourceTypeRegion", resourceTypeRegionKey, "pendingRetries", ct.pendingRetries[resourceTypeRegionKey])
	}
}

// IsAllComplete returns true if all expected work has been completed
func (ct *CompletionTracker) IsAllComplete() bool {
	if ct == nil {
		return false
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	return ct.totalExpected > 0 && ct.totalCompleted >= ct.totalExpected
}

// GetProgress returns current completion progress
func (ct *CompletionTracker) GetProgress() (completed, total int) {
	if ct == nil {
		return 0, 0
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	return ct.totalCompleted, ct.totalExpected
}

// GetRegistrationProgress returns work registration progress
func (ct *CompletionTracker) GetRegistrationProgress() (registered, expected int) {
	if ct == nil {
		return 0, 0
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	return len(ct.expectedResourceRegions), ct.totalExpected
}

// ValidateExpectedWorkRegistration checks if all expected work has been properly registered
func (ct *CompletionTracker) ValidateExpectedWorkRegistration() {
	if ct == nil {
		return
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	registered := len(ct.expectedResourceRegions)
	if registered != ct.totalExpected {
		slog.Warn("Expected work registration mismatch",
			"registered", registered,
			"expected", ct.totalExpected,
			"difference", ct.totalExpected-registered)
	} else {
		slog.Info("All expected work properly registered",
			"totalWork", ct.totalExpected)
	}
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
	params = append(params, cfg.NewParam[int]("global-rate-limit", "Per-region rate limit in requests per second (AWS SDK level)").
		WithDefault(5))
	params = append(params, cfg.NewParam[bool]("enable-debug-metrics", "Enable debug metrics for rate limiting analysis (disabled in production)").
		WithDefault(false))

	return params
}

func NewAWSCloudControl(configs ...cfg.Config) chain.Link {
	cc := &AWSCloudControl{
		wg:                    sync.WaitGroup{},
		maxConcurrentServices: 1000,                   // Default to 1000 concurrent services
		globalRateLimit:       5,                      // Default to 5 TPS per region rate limit
		completionTracker:     NewCompletionTracker(), // Initialize early to prevent nil panics, will be updated in Initialize()
	}
	cc.AwsReconLink = base.NewAwsReconLink(cc, configs...)

	return cc
}

func (a *AWSCloudControl) Initialize() error {
	if err := a.AwsReconLink.Initialize(); err != nil {
		slog.Error("AwsReconLink.Initialize() failed", "error", err)
		return err
	}

	// Configure max concurrent services from parameters
	if maxServices, err := cfg.As[int](a.Arg("max-concurrent-services")); err == nil {
		if maxServices > 0 && maxServices <= 10000 { // Reasonable bounds
			a.maxConcurrentServices = maxServices
		}
	}

	// Configure per-region rate limit from parameters
	if globalRateLimit, err := cfg.As[int](a.Arg("global-rate-limit")); err == nil {
		if globalRateLimit > 0 && globalRateLimit <= 100 { // Reasonable bounds for rate limits
			a.globalRateLimit = globalRateLimit
		}
	}

	// Configure debug metrics from parameters
	if enableDebugMetrics, err := cfg.As[bool](a.Arg("enable-debug-metrics")); err == nil {
		a.enableDebugMetrics = enableDebugMetrics
	}

	if err := a.initializeClients(); err != nil {
		slog.Error("Failed to initialize CloudControl clients", "error", err)
		return fmt.Errorf("failed to initialize CloudControl clients: %w", err)
	}

	a.initializeDebugMetrics()
	a.initializeAccountId()

	// Calculate total expected work based on regions and resource types
	expectedWorkCount := a.calculateExpectedWorkCount()
	a.completionTracker = NewCompletionTrackerWithExpectedCount(expectedWorkCount)

	slog.Info("CloudControl expected work calculated",
		"totalResourceTypes", len(a.GetFilteredResourceTypes()),
		"totalRegions", len(a.Regions),
		"expectedWorkItems", expectedWorkCount)

	a.workQueue = make(chan workItem, 2000) // Unified queue with larger buffer
	a.pendingResources = make([]string, 0)
	a.shutdownCtx, a.shutdownCancel = context.WithCancel(context.Background())

	// Start worker pool during initialization
	a.startWorkerPool()

	return nil
}

func (a *AWSCloudControl) initializeAccountId() {
	// Initialize cached account ID once to avoid duplicate STS calls
	// Use first region to get account ID (same for all regions with same profile)
	if len(a.Regions) > 0 {
		config, err := a.GetConfigWithRuntimeArgs(a.Regions[0])
		if err != nil {
			slog.Error("Failed to get AWS config for account ID caching", "error", err)
			return
		}

		accountId, err := helpers.GetAccountId(config)
		if err != nil {
			slog.Error("Failed to get account ID for caching", "error", err)
			return
		}

		a.cachedAccountId = accountId
	}
}

func (a *AWSCloudControl) initializeDebugMetrics() {
	if !a.enableDebugMetrics {
		return
	}

	a.debugMetrics = &DebugMetrics{
		metricsStartTime: time.Now(),
		lastReportTime:   time.Now(),
		reportTicker:     time.NewTicker(5 * time.Second), // Report every 5 seconds
		stopChan:         make(chan struct{}),
	}

	// Start metrics reporting goroutine
	go a.runMetricsReporter()
}

func (a *AWSCloudControl) runMetricsReporter() {
	if a.debugMetrics == nil {
		return
	}

	defer a.debugMetrics.reportTicker.Stop()

	for {
		select {
		case <-a.debugMetrics.reportTicker.C:
			a.reportRequestRates()
		case <-a.debugMetrics.stopChan:
			return
		}
	}
}

func (a *AWSCloudControl) reportRequestRates() {
	if a.debugMetrics == nil {
		return
	}

	now := time.Now()
	elapsed := now.Sub(a.debugMetrics.lastReportTime)
	totalElapsed := now.Sub(a.debugMetrics.metricsStartTime)

	slog.Info("CloudControl Request Rate Debug Metrics",
		"reportInterval", elapsed.String(),
		"totalRuntime", totalElapsed.String())

	// Report service-level rates
	a.debugMetrics.serviceRequestCounts.Range(func(key, value interface{}) bool {
		serviceName := key.(string)
		count := atomic.LoadInt64(value.(*int64))
		rate := float64(count) / totalElapsed.Seconds()
		slog.Info("Service request rate",
			"service", serviceName,
			"totalRequests", count,
			"requestsPerSecond", fmt.Sprintf("%.2f", rate))
		return true
	})

	// Report service+region rates
	a.debugMetrics.serviceRegionRequestCounts.Range(func(key, value interface{}) bool {
		serviceRegionKey := key.(string)
		count := atomic.LoadInt64(value.(*int64))
		rate := float64(count) / totalElapsed.Seconds()
		slog.Info("Service+Region request rate",
			"serviceRegion", serviceRegionKey,
			"totalRequests", count,
			"requestsPerSecond", fmt.Sprintf("%.2f", rate))
		return true
	})

	a.debugMetrics.lastReportTime = now
}

func (a *AWSCloudControl) incrementServiceRequestCount(serviceName string) {
	if !a.enableDebugMetrics || a.debugMetrics == nil {
		return
	}

	// Get or create atomic counter for this service
	value, _ := a.debugMetrics.serviceRequestCounts.LoadOrStore(serviceName, new(int64))
	counter := value.(*int64)
	atomic.AddInt64(counter, 1)
}

func (a *AWSCloudControl) incrementServiceRegionRequestCount(serviceName, region string) {
	if !a.enableDebugMetrics || a.debugMetrics == nil {
		return
	}

	serviceRegionKey := a.getServiceRegionKey(serviceName, region)

	// Get or create atomic counter for this service+region
	value, _ := a.debugMetrics.serviceRegionRequestCounts.LoadOrStore(serviceRegionKey, new(int64))
	counter := value.(*int64)
	atomic.AddInt64(counter, 1)
}

func (a *AWSCloudControl) stopDebugMetrics() {
	if a.debugMetrics != nil {
		close(a.debugMetrics.stopChan)
		a.debugMetrics = nil
	}
}

func (a *AWSCloudControl) extractServiceName(resourceType string) string {
	// Extract service name from AWS::ServiceName::ResourceType
	parts := strings.Split(resourceType, "::")
	if len(parts) >= 2 {
		return parts[1] // Return service name (e.g., "S3", "EC2", etc.)
	}
	return resourceType // Fallback to full resource type
}

func (a *AWSCloudControl) getServiceRegionKey(serviceName, region string) string {
	return fmt.Sprintf("%s:%s", serviceName, region)
}

func (a *AWSCloudControl) getResourceTypeRegionKey(resourceType, region string) string {
	return fmt.Sprintf("%s:%s", resourceType, region)
}

// waitForRateLimit waits for the rate limiter to allow a request
func (a *AWSCloudControl) waitForRateLimit(region string) error {
	rateLimiter := a.regionRateLimiters[region]
	if rateLimiter != nil {
		return rateLimiter.Wait(a.Context())
	}
	return nil
}

// checkIfCached checks if a response is cached without acquiring rate limits
func (a *AWSCloudControl) checkIfCached(resourceType, region string) bool {
	// Use cached account ID to avoid duplicate STS calls
	if a.cachedAccountId == "" {
		return false // If no cached account ID, assume not cached
	}

	// Get cache configuration from args
	opts := options.JanusArgsAdapter(a.Params(), a.Args())
	cacheDir := options.GetOptionByName(options.AwsCacheDirOpt.Name, opts).Value
	cacheExt := options.GetOptionByName(options.AwsCacheExtOpt.Name, opts).Value

	// Create input parameters for cache key generation (matching CloudControl API)
	input := &cloudcontrol.ListResourcesInput{
		TypeName:   &resourceType,
		MaxResults: aws.Int32(100),
	}

	// Generate cache key using the same logic as aws_cache.go (function is not exported, so we duplicate the logic)
	cacheKey := a.generateCacheKey(a.cachedAccountId, "CloudControl", region, "ListResources", input)
	cachePath := filepath.Join(cacheDir, cacheKey+cacheExt)

	// Check if cache file exists and is not expired
	if fileInfo, err := os.Stat(cachePath); err == nil {
		// Get cache TTL
		cacheTTL := options.GetOptionByName(options.AwsCacheTTLOpt.Name, opts).Value
		ttl, parseErr := strconv.Atoi(cacheTTL)
		if parseErr != nil {
			ttl = 3600 // Default TTL
		}

		// Check if cache is not expired
		if time.Since(fileInfo.ModTime()) < time.Duration(ttl)*time.Second {
			slog.Debug("Found valid cache for resource", "type", resourceType, "region", region, "cachePath", cachePath)
			return true
		} else {
			slog.Debug("Found expired cache for resource", "type", resourceType, "region", region, "age", time.Since(fileInfo.ModTime()))
		}
	}

	return false
}

// generateCacheKey duplicates the logic from helpers/aws_cache.go since it's not exported
func (a *AWSCloudControl) generateCacheKey(arn, service, region string, operation string, params interface{}) string {
	data, err := json.Marshal(params)
	if err != nil {
		slog.Error("Failed to marshal parameters for cache key", "error", err)
		return fmt.Sprintf("%s-%s-%s-%s", service, operation, arn, region)
	}

	combined := fmt.Sprintf("%s-%s-%s-%s-%s", arn, region, service, operation, string(data))
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
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

	// Check if work queue is nil
	if a.workQueue == nil {
		slog.Error("Work queue is nil, cannot send resources")
		return
	}

	// Shuffle resources randomly to avoid processing hotspots
	rand.Shuffle(len(resourcesCopy), func(i, j int) {
		resourcesCopy[i], resourcesCopy[j] = resourcesCopy[j], resourcesCopy[i]
	})

	// Send randomized resources to queue
	for _, resourceType := range resourcesCopy {
		slog.Debug("Queuing resource type", "type", resourceType)
		a.processResourceTypeWithDedupe(resourceType)
	}
}

func (a *AWSCloudControl) startWorkerPool() {
	// Start worker goroutines to process work items
	for i := 0; i < a.maxConcurrentServices; i++ {
		a.wg.Add(1)
		go a.workItemProcessor()
	}

	// Set workerStarted flag with mutex protection
	a.workerMu.Lock()
	a.workerStarted = true
	a.workerMu.Unlock()

	slog.Debug("Worker pool started", "workers", a.maxConcurrentServices)
}

func (a *AWSCloudControl) workItemProcessor() {
	defer a.wg.Done()

	for {
		select {
		case item, ok := <-a.workQueue:
			if !ok {
				return // Channel closed
			}
			a.processWorkItem(item)
		default:
			// Check for shutdown
			select {
			case <-a.shutdownCtx.Done():
				return
			default:
			}
			// Small sleep to prevent busy waiting (25ms for ~40 checks per second)
			time.Sleep(25 * time.Millisecond)
		}
	}
}

func (a *AWSCloudControl) processWorkItem(item workItem) {
	// No exponential backoff needed - rate limiter handles pacing at 5 RPS
	// Just process the work item directly

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()

		resourceTypeRegionKey := a.getResourceTypeRegionKey(item.resourceType, item.region)

		// Track whether work actually completed (not skipped during shutdown)
		workCompleted := false
		defer func() {
			// If this is a retry, remove it from pending retries when we start processing
			if item.retryCount > 0 {
				a.completionTracker.RemovePendingRetry(resourceTypeRegionKey)
			}
			// Only mark as completed if work actually finished (not skipped during shutdown)
			if workCompleted {
				a.completionTracker.MarkCompleted(resourceTypeRegionKey)
			}
		}()

		workCompleted = a.listResourcesInRegionWithRetry(item.resourceType, item.region, item.retryCount)
	}()
}

func (a *AWSCloudControl) processResourceTypeWithDedupe(resourceType string) {
	// Check if already processed using compare-and-swap
	if _, loaded := a.processedResources.LoadOrStore(resourceType, true); loaded {
		slog.Debug("Skipping already processed resource type", "type", resourceType)
		return
	}

	// Queue work items for all regions
	for _, region := range a.Regions {
		if a.isGlobalService(resourceType, region) {
			slog.Debug("Skipping global service", "type", resourceType, "region", region)
			continue
		}

		// Register expected work for completion tracking
		resourceTypeRegionKey := a.getResourceTypeRegionKey(resourceType, region)
		a.completionTracker.AddExpectedWork(resourceTypeRegionKey)

		item := workItem{
			resourceType: resourceType,
			region:       region,
			retryCount:   0,
			lastAttempt:  time.Time{},
		}

		select {
		case a.workQueue <- item:
		default:
			// Check for shutdown
			select {
			case <-a.shutdownCtx.Done():
				return
			default:
			}
			// Try again after delay optimized for 5 RPS (200ms per request cycle)
			time.Sleep(25 * time.Millisecond)
			select {
			case a.workQueue <- item:
			default:
				slog.Warn("Failed to queue work item, dropping", "type", resourceType, "region", region)
			}
		}
	}

}

func (a *AWSCloudControl) processResourceType(resourceType string) {
	a.processResourceTypeWithDedupe(resourceType)
}

func (a *AWSCloudControl) initializeClients() error {
	a.cloudControlClients = make(map[string]*cloudcontrol.Client)
	a.regionRateLimiters = make(map[string]*rate.Limiter)

	// Create per-region rate limiters using golang.org/x/time/rate for continuous 5 TPS
	for _, region := range a.Regions {
		// Create rate limiter: 5 requests per second with burst of 5
		limiter := rate.NewLimiter(rate.Limit(a.globalRateLimit), a.globalRateLimit)
		a.regionRateLimiters[region] = limiter
		slog.Debug("Created rate limiter for region", "region", region, "rateLimit", a.globalRateLimit)
	}

	// Get all unique service names from filtered resource types
	knownServices := make(map[string]bool)
	for _, resourceType := range a.GetFilteredResourceTypes() {
		serviceName := a.extractServiceName(resourceType)
		knownServices[serviceName] = true
	}

	// Pre-create clients for all known service+region combinations with no retries
	clientCount := 0
	for serviceName := range knownServices {
		for _, region := range a.Regions {
			serviceRegionKey := a.getServiceRegionKey(serviceName, region)

			// Get base config from framework
			baseConfig, err := a.GetConfigWithRuntimeArgs(region)
			if err != nil {
				return fmt.Errorf("failed to get base config for %s: %w", serviceRegionKey, err)
			}

			// Disable retries completely - we handle rate limiting manually
			baseConfig.Retryer = func() aws.Retryer {
				return retry.NewStandard(func(o *retry.StandardOptions) {
					o.MaxAttempts = 1 // No retries
				})
			}

			client := cloudcontrol.NewFromConfig(baseConfig)
			if client == nil {
				return fmt.Errorf("failed to create CloudControl client for %s", serviceRegionKey)
			}

			a.cloudControlClients[serviceRegionKey] = client
			clientCount++
			slog.Debug("Created CloudControl client with no retries",
				"serviceRegionKey", serviceRegionKey,
				"clientCount", clientCount)
		}
	}

	slog.Info("Pre-created CloudControl clients with per-region rate limiting",
		"services", len(knownServices),
		"regions", len(a.Regions),
		"totalClients", clientCount,
		"perRegionRateLimit", a.globalRateLimit,
		"totalCapacity", a.globalRateLimit*len(a.Regions))

	return nil
}

func (a *AWSCloudControl) getClient(serviceName, region string) *cloudcontrol.Client {
	serviceRegionKey := a.getServiceRegionKey(serviceName, region)
	client := a.cloudControlClients[serviceRegionKey]
	if client == nil {
		slog.Error("CloudControl client is nil", "serviceRegionKey", serviceRegionKey, "serviceName", serviceName, "region", region)
		slog.Debug("Available clients", "clientKeys", func() []string {
			keys := make([]string, 0, len(a.cloudControlClients))
			for k := range a.cloudControlClients {
				keys = append(keys, k)
			}
			return keys
		}())
	}
	return client
}

func (a *AWSCloudControl) Process(resourceType string) error {
	// Worker pool is already started in Initialize()

	// Only process resource types that are in the filtered list
	filteredTypes := a.GetFilteredResourceTypes()
	filteredMap := make(map[string]bool)
	for _, filteredType := range filteredTypes {
		filteredMap[filteredType] = true
	}

	if !filteredMap[resourceType] {
		slog.Debug("Skipping unfiltered resource type", "type", resourceType)
		return nil
	}

	// Add resource type to pending list
	a.addResourceType(resourceType)

	return nil
}

func (a *AWSCloudControl) isGlobalService(resourceType, region string) bool {
	return helpers.IsGlobalService(resourceType) && region != "us-east-1"
}

// calculateExpectedWorkCount calculates the total expected work items
// accounting for global services that are only processed in us-east-1
func (a *AWSCloudControl) calculateExpectedWorkCount() int {
	filteredTypes := a.GetFilteredResourceTypes()
	totalWork := 0

	for _, resourceType := range filteredTypes {
		if helpers.IsGlobalService(resourceType) {
			// Global services are only processed in us-east-1
			for _, region := range a.Regions {
				if region == "us-east-1" {
					totalWork++
					break
				}
			}
		} else {
			// Regular services are processed in all regions
			totalWork += len(a.Regions)
		}
	}

	return totalWork
}

func (a *AWSCloudControl) listResourcesInRegion(resourceType, region string) {
	_ = a.listResourcesInRegionWithRetry(resourceType, region, 0)
}

func (a *AWSCloudControl) listResourcesInRegionWithRetry(resourceType, region string, retryCount int) bool {
	serviceName := a.extractServiceName(resourceType)

	// Check if response is cached first - bypass all rate limiting for cached responses
	if a.checkIfCached(resourceType, region) {
		slog.Debug("Using cached response", "type", resourceType, "region", region)

		// Process cached request without any rate limiting
		a.processCachedOrUncachedRequest(resourceType, region, serviceName, true, retryCount)
		return true
	}

	// For uncached requests, rate limiting is handled by AWS SDK ratelimit package
	message.Info("Listing %s resources in %s (profile: %s)", resourceType, region, a.Profile)
	slog.Debug("Listing resources in region", "type", resourceType, "region", region, "profile", a.Profile)

	// Process uncached request - rate limiting handled by AWS SDK
	a.processCachedOrUncachedRequest(resourceType, region, serviceName, false, retryCount)
	return true
}

func (a *AWSCloudControl) processCachedOrUncachedRequest(resourceType, region, serviceName string, isCached bool, retryCount int) {
	// Note: Metrics are now incremented per actual API call in the pagination loop

	// Use cached account ID to avoid duplicate STS calls
	accountId := a.cachedAccountId

	cc := a.getClient(serviceName, region)
	if cc == nil {
		slog.Error("Failed to get CloudControl client, skipping", "serviceName", serviceName, "region", region, "resourceType", resourceType)
		return
	}

	paginator := cloudcontrol.NewListResourcesPaginator(cc, &cloudcontrol.ListResourcesInput{
		TypeName:   &resourceType,
		MaxResults: aws.Int32(100),
	})

	// No service semaphore needed - per-region rate limiting handles all throttling

	for paginator.HasMorePages() {
		// Apply per-region rate limiting before making API call
		if err := a.waitForRateLimit(region); err != nil {
			slog.Error("Rate limiter context cancelled", "error", err, "region", region)
			return
		}

		res, err := paginator.NextPage(a.Context())

		// Increment debug metrics counters for each actual API call
		a.incrementServiceRequestCount(serviceName)
		a.incrementServiceRegionRequestCount(serviceName, region)

		if err != nil {
			err, shouldBreak, workSkipped := a.processError(resourceType, region, err, retryCount)
			if err != nil {
				slog.Error("Failed to list resources", "error", err)
				return
			}

			if shouldBreak {
				if workSkipped {
					slog.Debug("shouldBreak, workSkipped", "serviceName", serviceName, "region", region)
					return // Work was skipped during shutdown
				}
				break
			}
		}

		for _, resource := range res.ResourceDescriptions {
			erd := a.resourceDescriptionToERD(resource, resourceType, accountId, region)
			a.sendResource(region, erd)
		}
	}

	// No service semaphore cleanup needed - using per-region rate limiting only
}

func (a *AWSCloudControl) processError(resourceType, region string, err error, retryCount int) (error, bool, bool) {
	errMsg := err.Error()
	switch {

	case strings.Contains(errMsg, "ThrottlingException"):
		slog.Warn("Rate limited, scheduling retry", "type", resourceType, "region", region, "retryCount", retryCount)

		// Track this as a pending retry
		resourceTypeRegionKey := a.getResourceTypeRegionKey(resourceType, region)
		a.completionTracker.AddPendingRetry(resourceTypeRegionKey)

		retryItem := workItem{
			resourceType: resourceType,
			region:       region,
			retryCount:   retryCount + 1,
			lastAttempt:  time.Now(),
		}

		// Check if shutdown is in progress first (with nil safety)
		if a.shutdownCtx != nil {
			select {
			case <-a.shutdownCtx.Done():
				slog.Debug("Shutdown in progress, skipping retry", "type", resourceType, "region", region)
				a.completionTracker.RemovePendingRetry(resourceTypeRegionKey) // Remove the pending retry we just added
				return nil, true, true                                        // Skip retry during shutdown (error, shouldBreak, workSkipped)
			default:
			}
		}

		// Try to send to queue (with nil safety)
		if a.shutdownCtx != nil {
			select {
			case a.workQueue <- retryItem:
				slog.Debug("Queued resource for retry after throttling", "type", resourceType, "region", region, "retryCount", retryItem.retryCount)
			case <-a.shutdownCtx.Done():
				slog.Debug("Shutdown during retry queue send, skipping", "type", resourceType, "region", region)
				a.completionTracker.RemovePendingRetry(resourceTypeRegionKey) // Remove the pending retry
			}
		} else {
			// No shutdown context, just try to send
			select {
			case a.workQueue <- retryItem:
				slog.Debug("Queued resource for retry after throttling", "type", resourceType, "region", region, "retryCount", retryItem.retryCount)
			default:
				slog.Warn("Work queue full, dropping retry request", "type", resourceType, "region", region)
				a.completionTracker.RemovePendingRetry(resourceTypeRegionKey)
			}
		}
		return nil, true, false // Don't return error, resource will be retried (error, shouldBreak, workSkipped)

	default:
		return err, false, false
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
	// No rate limiting needed for sending resources - API rate limiting handles throttling
	a.Send(resource)
}

func (a *AWSCloudControl) Complete() error {
	// Check if workers were started with mutex protection
	a.workerMu.Lock()
	started := a.workerStarted
	a.workerMu.Unlock()

	slog.Debug("Complete() method called", "workerStarted", started, "workQueueNotNil", a.workQueue != nil)

	// If initialization failed, workQueue will be nil - just return early
	if a.workQueue == nil {
		slog.Debug("Complete() called but initialization failed, skipping processing")
		return nil
	}

	if started && a.workQueue != nil {
		// Send all resources to the queue with random distribution
		a.sendResourcesRandomly()

		// Validate that all expected work has been registered
		a.completionTracker.ValidateExpectedWorkRegistration()

		// Wait for all work to be actually completed (not just queue to be empty)
		go func() {
			ticker := time.NewTicker(2 * time.Second) // Check every 2 seconds
			defer ticker.Stop()

			maxWaitTime := 600 * time.Second // 5 minutes max wait
			startTime := time.Now()

			for {
				select {
				case <-ticker.C:
					elapsed := time.Since(startTime)
					completed, total := a.completionTracker.GetProgress()
					queueLen := len(a.workQueue)

					// Shutdown condition: All expected work completed
					if a.completionTracker.IsAllComplete() {
						slog.Info("All work completed - initiating shutdown",
							"completed", completed, "total", total, "queueLength", queueLen, "waitTime", elapsed)
						a.shutdownCancel()
						close(a.workQueue)
						return
					}

					// Safety timeout
					if elapsed > maxWaitTime {
						slog.Warn("Max wait time exceeded - forcing shutdown",
							"completed", completed, "total", total, "queueLength", queueLen, "waitTime", elapsed)
						a.shutdownCancel()
						close(a.workQueue)
						return
					}

					// Log progress every 10 seconds with registration info
					if int(elapsed.Seconds())%10 == 0 {
						registered, expectedReg := a.completionTracker.GetRegistrationProgress()
						slog.Info("Waiting for work completion",
							"completed", completed, "total", total,
							"registered", registered, "expectedRegistrations", expectedReg,
							"queueLength", queueLen, "waitTime", elapsed,
							"completionPercent", fmt.Sprintf("%.1f%%", float64(completed)/float64(total)*100))
					}
				}
			}
		}()
	} else {
		// If no workers were started, process resources directly
		slog.Debug("No workers started, processing resources directly")

		// Copy pending resources under mutex protection
		a.mu.Lock()
		resourcesCopy := make([]string, len(a.pendingResources))
		copy(resourcesCopy, a.pendingResources)
		a.mu.Unlock()

		// Process each resource type directly
		for _, resourceType := range resourcesCopy {
			a.processResourceType(resourceType)
		}
	}

	// Wait for all region processing to complete
	a.wg.Wait()

	// Stop debug metrics reporting
	a.stopDebugMetrics()

	return nil
}

// GetFilteredResourceTypes returns resource types based on CLI arguments
func (a *AWSCloudControl) GetFilteredResourceTypes() []string {
	// Get resource types from command line arguments
	resourceTypes, err := cfg.As[[]string](a.Arg(options.AwsResourceType().Name()))
	if err != nil {
		slog.Warn("Failed to get resource types from arguments, using all supported types", "error", err)
		return a.SupportedResourceTypes()
	}

	// If empty or contains "all", return all supported types
	if len(resourceTypes) == 0 || (len(resourceTypes) == 1 && strings.ToLower(resourceTypes[0]) == "all") {
		return a.SupportedResourceTypes()
	}

	// Filter to only include supported resource types
	var filteredTypes []string
	supportedTypes := a.SupportedResourceTypes()
	supportedMap := make(map[string]bool)
	for _, t := range supportedTypes {
		supportedMap[t] = true
	}

	for _, requestedType := range resourceTypes {
		if supportedMap[requestedType] {
			filteredTypes = append(filteredTypes, requestedType)
		} else {
			slog.Warn("Unsupported resource type requested, skipping", "resourceType", requestedType)
		}
	}

	if len(filteredTypes) == 0 {
		slog.Warn("No valid resource types found in arguments, using all supported types")
		return a.SupportedResourceTypes()
	}

	slog.Info("Using filtered resource types", "requestedCount", len(resourceTypes), "filteredCount", len(filteredTypes))
	return filteredTypes
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
