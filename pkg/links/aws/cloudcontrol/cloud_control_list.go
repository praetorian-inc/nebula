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
	"github.com/praetorian-inc/tabularium/pkg/model/model"
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
	if ct == nil {
		slog.Warn("CompletionTracker is nil, cannot add pending retry", "resourceTypeRegion", resourceTypeRegionKey)
		return
	}

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
		WithDefault(100))
	params = append(params, cfg.NewParam[int]("global-rate-limit", "Per-region rate limit in requests per second (AWS SDK level)").
		WithDefault(5))
	params = append(params, cfg.NewParam[bool]("enable-debug-metrics", "Enable debug metrics for rate limiting analysis (disabled in production)").
		WithDefault(false))

	return params
}

func NewAWSCloudControl(configs ...cfg.Config) chain.Link {
	cc := &AWSCloudControl{
		wg:                    sync.WaitGroup{},
		maxConcurrentServices: 100,                    // Default to 100 concurrent services
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

func (a *AWSCloudControl) Process(resourceType model.CloudResourceType) error {
	// Worker pool is already started in Initialize()
	resourceTypeStr := resourceType.String()

	// Only process resource types that are in the filtered list
	filteredTypes := a.GetFilteredResourceTypes()
	filteredMap := make(map[string]bool)
	for _, filteredType := range filteredTypes {
		filteredMap[filteredType] = true
	}

	if !filteredMap[resourceTypeStr] {
		slog.Debug("Skipping unfiltered resource type", "type", resourceTypeStr)
		return nil
	}

	// Add resource type to pending list
	a.addResourceType(resourceTypeStr)

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
	// Convert supported types to strings for internal use
	supportedTypes := a.SupportedResourceTypes()
	supportedStrings := make([]string, len(supportedTypes))
	supportedMap := make(map[string]bool)
	for i, t := range supportedTypes {
		s := t.String()
		supportedStrings[i] = s
		supportedMap[s] = true
	}

	// Get resource types from command line arguments
	resourceTypes, err := cfg.As[[]string](a.Arg(options.AwsResourceType().Name()))
	if err != nil {
		slog.Warn("Failed to get resource types from arguments, using all supported types", "error", err)
		return supportedStrings
	}

	// If empty or contains "all", return all supported types
	if len(resourceTypes) == 0 || (len(resourceTypes) == 1 && strings.ToLower(resourceTypes[0]) == "all") {
		return supportedStrings
	}

	// Filter to only include supported resource types
	var filteredTypes []string
	for _, requestedType := range resourceTypes {
		if supportedMap[requestedType] {
			filteredTypes = append(filteredTypes, requestedType)
		} else {
			slog.Warn("Unsupported resource type requested, skipping", "resourceType", requestedType)
		}
	}

	if len(filteredTypes) == 0 {
		slog.Warn("No valid resource types found in arguments, using all supported types")
		return supportedStrings
	}

	slog.Info("Using filtered resource types", "requestedCount", len(resourceTypes), "filteredCount", len(filteredTypes))
	return filteredTypes
}

func (a *AWSCloudControl) SupportedResourceTypes() []model.CloudResourceType {
	return []model.CloudResourceType{
		model.CloudResourceType("AWS::AccessAnalyzer::Analyzer"),
		model.CloudResourceType("AWS::ACMPCA::CertificateAuthority"),
		model.CloudResourceType("AWS::Amplify::App"),
		model.CloudResourceType("AWS::ApiGateway::ApiKey"),
		model.CloudResourceType("AWS::ApiGateway::ClientCertificate"),
		model.CloudResourceType("AWS::ApiGateway::DomainName"),
		model.AWSGateway,
		model.CloudResourceType("AWS::ApiGateway::UsagePlan"),
		model.CloudResourceType("AWS::ApiGateway::VpcLink"),
		model.CloudResourceType("AWS::ApiGatewayV2::Api"),
		model.CloudResourceType("AWS::ApiGatewayV2::DomainName"),
		model.CloudResourceType("AWS::ApiGatewayV2::VpcLink"),
		model.CloudResourceType("AWS::AppConfig::Application"),
		model.CloudResourceType("AWS::AppConfig::DeploymentStrategy"),
		model.CloudResourceType("AWS::AppConfig::Extension"),
		model.CloudResourceType("AWS::AppConfig::ExtensionAssociation"),
		model.CloudResourceType("AWS::AppFlow::Connector"),
		model.CloudResourceType("AWS::AppFlow::ConnectorProfile"),
		model.CloudResourceType("AWS::AppFlow::Flow"),
		model.CloudResourceType("AWS::AppIntegrations::Application"),
		model.CloudResourceType("AWS::AppIntegrations::DataIntegration"),
		model.CloudResourceType("AWS::AppIntegrations::EventIntegration"),
		model.CloudResourceType("AWS::ApplicationInsights::Application"),
		model.CloudResourceType("AWS::ApplicationSignals::ServiceLevelObjective"),
		model.CloudResourceType("AWS::AppRunner::AutoScalingConfiguration"),
		model.CloudResourceType("AWS::AppRunner::ObservabilityConfiguration"),
		model.CloudResourceType("AWS::AppRunner::Service"),
		model.CloudResourceType("AWS::AppRunner::VpcConnector"),
		model.CloudResourceType("AWS::AppRunner::VpcIngressConnection"),
		model.CloudResourceType("AWS::AppStream::AppBlockBuilder"),
		model.CloudResourceType("AWS::AppSync::Api"),
		model.CloudResourceType("AWS::AppSync::DomainName"),
		model.CloudResourceType("AWS::AppTest::TestCase"),
		model.CloudResourceType("AWS::APS::Scraper"),
		model.CloudResourceType("AWS::APS::Workspace"),
		model.CloudResourceType("AWS::ARCZonalShift::AutoshiftObserverNotificationStatus"),
		model.CloudResourceType("AWS::ARCZonalShift::ZonalAutoshiftConfiguration"),
		model.CloudResourceType("AWS::Athena::CapacityReservation"),
		model.CloudResourceType("AWS::Athena::DataCatalog"),
		model.CloudResourceType("AWS::Athena::NamedQuery"),
		model.CloudResourceType("AWS::Athena::WorkGroup"),
		model.CloudResourceType("AWS::AutoScaling::AutoScalingGroup"),
		model.CloudResourceType("AWS::AutoScaling::LaunchConfiguration"),
		model.CloudResourceType("AWS::AutoScaling::ScalingPolicy"),
		model.CloudResourceType("AWS::AutoScaling::ScheduledAction"),
		model.CloudResourceType("AWS::B2BI::Capability"),
		model.CloudResourceType("AWS::B2BI::Partnership"),
		model.CloudResourceType("AWS::B2BI::Profile"),
		model.CloudResourceType("AWS::B2BI::Transformer"),
		model.CloudResourceType("AWS::Backup::BackupPlan"),
		model.CloudResourceType("AWS::Backup::BackupSelection"),
		model.CloudResourceType("AWS::Backup::BackupVault"),
		model.CloudResourceType("AWS::Backup::Framework"),
		model.CloudResourceType("AWS::Backup::LogicallyAirGappedBackupVault"),
		model.CloudResourceType("AWS::Backup::ReportPlan"),
		model.CloudResourceType("AWS::Backup::RestoreTestingPlan"),
		model.CloudResourceType("AWS::Backup::RestoreTestingSelection"),
		model.CloudResourceType("AWS::BackupGateway::Hypervisor"),
		model.CloudResourceType("AWS::Batch::ComputeEnvironment"),
		model.CloudResourceType("AWS::Batch::JobQueue"),
		model.CloudResourceType("AWS::Batch::SchedulingPolicy"),
		model.CloudResourceType("AWS::BCMDataExports::Export"),
		model.CloudResourceType("AWS::Bedrock::Agent"),
		model.CloudResourceType("AWS::Bedrock::ApplicationInferenceProfile"),
		model.CloudResourceType("AWS::Bedrock::Flow"),
		model.CloudResourceType("AWS::Bedrock::Guardrail"),
		model.CloudResourceType("AWS::Bedrock::KnowledgeBase"),
		model.CloudResourceType("AWS::Bedrock::Prompt"),
		model.CloudResourceType("AWS::Budgets::BudgetsAction"),
		model.CloudResourceType("AWS::Cassandra::Keyspace"),
		model.CloudResourceType("AWS::Cassandra::Table"),
		model.CloudResourceType("AWS::CE::AnomalyMonitor"),
		model.CloudResourceType("AWS::CE::AnomalySubscription"),
		model.CloudResourceType("AWS::Chatbot::MicrosoftTeamsChannelConfiguration"),
		model.CloudResourceType("AWS::Chatbot::SlackChannelConfiguration"),
		model.CloudResourceType("AWS::CleanRooms::Collaboration"),
		model.CloudResourceType("AWS::CleanRooms::ConfiguredTable"),
		model.CloudResourceType("AWS::CleanRooms::Membership"),
		model.CloudResourceType("AWS::CleanRoomsML::TrainingDataset"),
		model.CloudResourceType("AWS::CloudFormation::GuardHook"),
		model.CloudResourceType("AWS::CloudFormation::HookDefaultVersion"),
		model.CloudResourceType("AWS::CloudFormation::HookTypeConfig"),
		model.CloudResourceType("AWS::CloudFormation::HookVersion"),
		model.CloudResourceType("AWS::CloudFormation::LambdaHook"),
		model.CloudResourceType("AWS::CloudFormation::ModuleDefaultVersion"),
		model.CloudResourceType("AWS::CloudFormation::PublicTypeVersion"),
		model.AWSCloudFormationStack,
		model.CloudResourceType("AWS::CloudFormation::StackSet"),
		model.CloudResourceType("AWS::CloudFormation::TypeActivation"),
		model.CloudResourceType("AWS::CloudFront::CachePolicy"),
		model.CloudResourceType("AWS::CloudFront::CloudFrontOriginAccessIdentity"),
		model.CloudResourceType("AWS::CloudFront::ContinuousDeploymentPolicy"),
		model.CloudResourceType("AWS::CloudFront::Distribution"),
		model.CloudResourceType("AWS::CloudFront::Function"),
		model.CloudResourceType("AWS::CloudFront::KeyGroup"),
		model.CloudResourceType("AWS::CloudFront::KeyValueStore"),
		model.CloudResourceType("AWS::CloudFront::OriginAccessControl"),
		model.CloudResourceType("AWS::CloudFront::OriginRequestPolicy"),
		model.CloudResourceType("AWS::CloudFront::PublicKey"),
		model.CloudResourceType("AWS::CloudFront::RealtimeLogConfig"),
		model.CloudResourceType("AWS::CloudFront::ResponseHeadersPolicy"),
		model.CloudResourceType("AWS::CloudTrail::Channel"),
		model.CloudResourceType("AWS::CloudTrail::EventDataStore"),
		model.CloudResourceType("AWS::CloudTrail::Trail"),
		model.CloudResourceType("AWS::CloudWatch::Alarm"),
		model.CloudResourceType("AWS::CloudWatch::CompositeAlarm"),
		model.CloudResourceType("AWS::CloudWatch::Dashboard"),
		model.CloudResourceType("AWS::CloudWatch::MetricStream"),
		model.CloudResourceType("AWS::CodeArtifact::Domain"),
		model.CloudResourceType("AWS::CodeArtifact::Repository"),
		model.CloudResourceType("AWS::CodeBuild::Fleet"),
		model.CloudResourceType("AWS::CodeConnections::Connection"),
		model.CloudResourceType("AWS::CodeDeploy::Application"),
		model.CloudResourceType("AWS::CodeDeploy::DeploymentConfig"),
		model.CloudResourceType("AWS::CodeGuruProfiler::ProfilingGroup"),
		model.CloudResourceType("AWS::CodeGuruReviewer::RepositoryAssociation"),
		model.CloudResourceType("AWS::CodePipeline::CustomActionType"),
		model.CloudResourceType("AWS::CodePipeline::Pipeline"),
		model.CloudResourceType("AWS::CodeStarConnections::Connection"),
		model.CloudResourceType("AWS::CodeStarConnections::RepositoryLink"),
		model.CloudResourceType("AWS::CodeStarConnections::SyncConfiguration"),
		model.CloudResourceType("AWS::CodeStarNotifications::NotificationRule"),
		model.CloudResourceType("AWS::Cognito::IdentityPool"),
		model.CloudResourceType("AWS::Cognito::UserPool"),
		model.CloudResourceType("AWS::Comprehend::DocumentClassifier"),
		model.CloudResourceType("AWS::Comprehend::Flywheel"),
		model.CloudResourceType("AWS::Config::AggregationAuthorization"),
		model.CloudResourceType("AWS::Config::ConfigRule"),
		model.CloudResourceType("AWS::Config::ConfigurationAggregator"),
		model.CloudResourceType("AWS::Config::ConformancePack"),
		model.CloudResourceType("AWS::Config::OrganizationConformancePack"),
		model.CloudResourceType("AWS::Config::StoredQuery"),
		model.CloudResourceType("AWS::Connect::Instance"),
		model.CloudResourceType("AWS::Connect::TrafficDistributionGroup"),
		model.CloudResourceType("AWS::ConnectCampaigns::Campaign"),
		model.CloudResourceType("AWS::ControlTower::LandingZone"),
		model.CloudResourceType("AWS::CUR::ReportDefinition"),
		model.CloudResourceType("AWS::DataBrew::Dataset"),
		model.CloudResourceType("AWS::DataBrew::Job"),
		model.CloudResourceType("AWS::DataBrew::Project"),
		model.CloudResourceType("AWS::DataBrew::Recipe"),
		model.CloudResourceType("AWS::DataBrew::Ruleset"),
		model.CloudResourceType("AWS::DataBrew::Schedule"),
		model.CloudResourceType("AWS::DataSync::Agent"),
		model.CloudResourceType("AWS::DataSync::LocationAzureBlob"),
		model.CloudResourceType("AWS::DataSync::LocationEFS"),
		model.CloudResourceType("AWS::DataSync::LocationFSxLustre"),
		model.CloudResourceType("AWS::DataSync::LocationFSxONTAP"),
		model.CloudResourceType("AWS::DataSync::LocationFSxOpenZFS"),
		model.CloudResourceType("AWS::DataSync::LocationFSxWindows"),
		model.CloudResourceType("AWS::DataSync::LocationHDFS"),
		model.CloudResourceType("AWS::DataSync::LocationNFS"),
		model.CloudResourceType("AWS::DataSync::LocationObjectStorage"),
		model.CloudResourceType("AWS::DataSync::LocationS3"),
		model.CloudResourceType("AWS::DataSync::LocationSMB"),
		model.CloudResourceType("AWS::DataSync::StorageSystem"),
		model.CloudResourceType("AWS::DataSync::Task"),
		model.CloudResourceType("AWS::DataZone::Domain"),
		model.CloudResourceType("AWS::Deadline::Farm"),
		model.CloudResourceType("AWS::Deadline::LicenseEndpoint"),
		model.CloudResourceType("AWS::Deadline::Monitor"),
		model.CloudResourceType("AWS::Detective::Graph"),
		model.CloudResourceType("AWS::Detective::MemberInvitation"),
		model.CloudResourceType("AWS::DeviceFarm::InstanceProfile"),
		model.CloudResourceType("AWS::DeviceFarm::Project"),
		model.CloudResourceType("AWS::DeviceFarm::TestGridProject"),
		model.CloudResourceType("AWS::DevOpsGuru::LogAnomalyDetectionIntegration"),
		model.CloudResourceType("AWS::DevOpsGuru::NotificationChannel"),
		model.CloudResourceType("AWS::DevOpsGuru::ResourceCollection"),
		model.CloudResourceType("AWS::DMS::DataMigration"),
		model.CloudResourceType("AWS::DMS::DataProvider"),
		model.CloudResourceType("AWS::DMS::InstanceProfile"),
		model.CloudResourceType("AWS::DMS::MigrationProject"),
		model.CloudResourceType("AWS::DMS::ReplicationConfig"),
		model.CloudResourceType("AWS::DocDBElastic::Cluster"),
		model.CloudResourceType("AWS::DynamoDB::GlobalTable"),
		model.CloudResourceType("AWS::DynamoDB::Table"),
		model.CloudResourceType("AWS::EC2::CapacityReservation"),
		model.CloudResourceType("AWS::EC2::CapacityReservationFleet"),
		model.CloudResourceType("AWS::EC2::CarrierGateway"),
		model.CloudResourceType("AWS::EC2::CustomerGateway"),
		model.CloudResourceType("AWS::EC2::DHCPOptions"),
		model.CloudResourceType("AWS::EC2::EC2Fleet"),
		model.CloudResourceType("AWS::EC2::EgressOnlyInternetGateway"),
		model.CloudResourceType("AWS::EC2::EIP"),
		model.CloudResourceType("AWS::EC2::EIPAssociation"),
		model.CloudResourceType("AWS::EC2::FlowLog"),
		model.CloudResourceType("AWS::EC2::Host"),
		model.AWSEC2Instance,
		model.CloudResourceType("AWS::EC2::InstanceConnectEndpoint"),
		model.CloudResourceType("AWS::EC2::InternetGateway"),
		model.CloudResourceType("AWS::EC2::IPAM"),
		model.CloudResourceType("AWS::EC2::IPAMPool"),
		model.CloudResourceType("AWS::EC2::IPAMResourceDiscovery"),
		model.CloudResourceType("AWS::EC2::IPAMResourceDiscoveryAssociation"),
		model.CloudResourceType("AWS::EC2::IPAMScope"),
		model.CloudResourceType("AWS::EC2::KeyPair"),
		model.CloudResourceType("AWS::EC2::LaunchTemplate"),
		model.CloudResourceType("AWS::EC2::LocalGatewayRoute"),
		model.CloudResourceType("AWS::EC2::LocalGatewayRouteTable"),
		model.CloudResourceType("AWS::EC2::LocalGatewayRouteTableVirtualInterfaceGroupAssociation"),
		model.CloudResourceType("AWS::EC2::LocalGatewayRouteTableVPCAssociation"),
		model.CloudResourceType("AWS::EC2::NatGateway"),
		model.CloudResourceType("AWS::EC2::NetworkAcl"),
		model.CloudResourceType("AWS::EC2::NetworkInsightsAccessScope"),
		model.CloudResourceType("AWS::EC2::NetworkInsightsAccessScopeAnalysis"),
		model.CloudResourceType("AWS::EC2::NetworkInsightsAnalysis"),
		model.CloudResourceType("AWS::EC2::NetworkInsightsPath"),
		model.CloudResourceType("AWS::EC2::NetworkInterface"),
		model.CloudResourceType("AWS::EC2::NetworkInterfaceAttachment"),
		model.CloudResourceType("AWS::EC2::NetworkPerformanceMetricSubscription"),
		model.CloudResourceType("AWS::EC2::PlacementGroup"),
		model.CloudResourceType("AWS::EC2::PrefixList"),
		model.CloudResourceType("AWS::EC2::RouteTable"),
		model.CloudResourceType("AWS::EC2::SecurityGroup"),
		model.CloudResourceType("AWS::EC2::SecurityGroupEgress"),
		model.CloudResourceType("AWS::EC2::SecurityGroupIngress"),
		model.CloudResourceType("AWS::EC2::SecurityGroupVpcAssociation"),
		model.CloudResourceType("AWS::EC2::SnapshotBlockPublicAccess"),
		model.CloudResourceType("AWS::EC2::SpotFleet"),
		model.CloudResourceType("AWS::EC2::Subnet"),
		model.CloudResourceType("AWS::EC2::SubnetCidrBlock"),
		model.CloudResourceType("AWS::EC2::SubnetNetworkAclAssociation"),
		model.CloudResourceType("AWS::EC2::SubnetRouteTableAssociation"),
		model.CloudResourceType("AWS::EC2::TransitGateway"),
		model.CloudResourceType("AWS::EC2::TransitGatewayAttachment"),
		model.CloudResourceType("AWS::EC2::TransitGatewayConnect"),
		model.CloudResourceType("AWS::EC2::TransitGatewayMulticastDomain"),
		model.CloudResourceType("AWS::EC2::TransitGatewayPeeringAttachment"),
		model.CloudResourceType("AWS::EC2::TransitGatewayRouteTable"),
		model.CloudResourceType("AWS::EC2::TransitGatewayVpcAttachment"),
		model.CloudResourceType("AWS::EC2::VerifiedAccessEndpoint"),
		model.CloudResourceType("AWS::EC2::VerifiedAccessGroup"),
		model.CloudResourceType("AWS::EC2::VerifiedAccessInstance"),
		model.CloudResourceType("AWS::EC2::VerifiedAccessTrustProvider"),
		model.CloudResourceType("AWS::EC2::Volume"),
		model.CloudResourceType("AWS::EC2::VolumeAttachment"),
		model.CloudResourceType("AWS::EC2::VPC"),
		model.CloudResourceType("AWS::EC2::VPCDHCPOptionsAssociation"),
		model.CloudResourceType("AWS::EC2::VPCEndpoint"),
		model.CloudResourceType("AWS::EC2::VPCEndpointConnectionNotification"),
		model.CloudResourceType("AWS::EC2::VPCEndpointService"),
		model.CloudResourceType("AWS::EC2::VPCEndpointServicePermissions"),
		model.CloudResourceType("AWS::EC2::VPCGatewayAttachment"),
		model.CloudResourceType("AWS::EC2::VPCPeeringConnection"),
		model.CloudResourceType("AWS::EC2::VPNConnection"),
		model.CloudResourceType("AWS::EC2::VPNConnectionRoute"),
		model.CloudResourceType("AWS::EC2::VPNGateway"),
		model.AWSEcrPublicRepository,
		model.CloudResourceType("AWS::ECR::PullThroughCacheRule"),
		model.CloudResourceType("AWS::ECR::RegistryPolicy"),
		model.CloudResourceType("AWS::ECR::ReplicationConfiguration"),
		model.AWSEcrRepository,
		model.CloudResourceType("AWS::ECR::RepositoryCreationTemplate"),
		model.CloudResourceType("AWS::ECS::CapacityProvider"),
		model.CloudResourceType("AWS::ECS::Cluster"),
		model.CloudResourceType("AWS::ECS::ClusterCapacityProviderAssociations"),
		model.CloudResourceType("AWS::ECS::Service"),
		model.CloudResourceType("AWS::ECS::TaskDefinition"),
		model.CloudResourceType("AWS::EFS::AccessPoint"),
		model.CloudResourceType("AWS::EFS::FileSystem"),
		model.CloudResourceType("AWS::EKS::Cluster"),
		model.CloudResourceType("AWS::ElastiCache::GlobalReplicationGroup"),
		model.CloudResourceType("AWS::ElastiCache::ParameterGroup"),
		model.CloudResourceType("AWS::ElastiCache::ServerlessCache"),
		model.CloudResourceType("AWS::ElastiCache::SubnetGroup"),
		model.CloudResourceType("AWS::ElastiCache::User"),
		model.CloudResourceType("AWS::ElastiCache::UserGroup"),
		model.CloudResourceType("AWS::ElasticBeanstalk::Application"),
		model.CloudResourceType("AWS::ElasticBeanstalk::ApplicationVersion"),
		model.CloudResourceType("AWS::ElasticBeanstalk::ConfigurationTemplate"),
		model.CloudResourceType("AWS::ElasticBeanstalk::Environment"),
		model.CloudResourceType("AWS::ElasticLoadBalancingV2::LoadBalancer"),
		model.CloudResourceType("AWS::ElasticLoadBalancingV2::TargetGroup"),
		model.CloudResourceType("AWS::ElasticLoadBalancingV2::TrustStore"),
		model.CloudResourceType("AWS::EMR::SecurityConfiguration"),
		model.CloudResourceType("AWS::EMR::Studio"),
		model.CloudResourceType("AWS::EMR::StudioSessionMapping"),
		model.CloudResourceType("AWS::EMR::WALWorkspace"),
		model.CloudResourceType("AWS::EMRContainers::VirtualCluster"),
		model.CloudResourceType("AWS::EMRServerless::Application"),
		model.CloudResourceType("AWS::EntityResolution::IdMappingWorkflow"),
		model.CloudResourceType("AWS::EntityResolution::IdNamespace"),
		model.CloudResourceType("AWS::EntityResolution::MatchingWorkflow"),
		model.CloudResourceType("AWS::EntityResolution::SchemaMapping"),
		model.CloudResourceType("AWS::Events::ApiDestination"),
		model.CloudResourceType("AWS::Events::Archive"),
		model.CloudResourceType("AWS::Events::Connection"),
		model.CloudResourceType("AWS::Events::Endpoint"),
		model.CloudResourceType("AWS::Events::EventBus"),
		model.CloudResourceType("AWS::Events::Rule"),
		model.CloudResourceType("AWS::EventSchemas::Discoverer"),
		model.CloudResourceType("AWS::EventSchemas::Registry"),
		model.CloudResourceType("AWS::FinSpace::Environment"),
		model.CloudResourceType("AWS::FIS::ExperimentTemplate"),
		model.CloudResourceType("AWS::Forecast::Dataset"),
		model.CloudResourceType("AWS::Forecast::DatasetGroup"),
		model.CloudResourceType("AWS::FraudDetector::Detector"),
		model.CloudResourceType("AWS::FraudDetector::EntityType"),
		model.CloudResourceType("AWS::FraudDetector::EventType"),
		model.CloudResourceType("AWS::FraudDetector::Label"),
		model.CloudResourceType("AWS::FraudDetector::List"),
		model.CloudResourceType("AWS::FraudDetector::Outcome"),
		model.CloudResourceType("AWS::FraudDetector::Variable"),
		model.CloudResourceType("AWS::FSx::DataRepositoryAssociation"),
		model.CloudResourceType("AWS::GameLift::Alias"),
		model.CloudResourceType("AWS::GameLift::Build"),
		model.CloudResourceType("AWS::GameLift::ContainerFleet"),
		model.CloudResourceType("AWS::GameLift::ContainerGroupDefinition"),
		model.CloudResourceType("AWS::GameLift::Fleet"),
		model.CloudResourceType("AWS::GameLift::GameServerGroup"),
		model.CloudResourceType("AWS::GameLift::GameSessionQueue"),
		model.CloudResourceType("AWS::GameLift::Location"),
		model.CloudResourceType("AWS::GameLift::Script"),
		model.CloudResourceType("AWS::GlobalAccelerator::Accelerator"),
		model.CloudResourceType("AWS::GlobalAccelerator::CrossAccountAttachment"),
		model.CloudResourceType("AWS::Glue::Crawler"),
		model.CloudResourceType("AWS::Glue::Database"),
		model.CloudResourceType("AWS::Glue::Job"),
		model.CloudResourceType("AWS::Glue::Registry"),
		model.CloudResourceType("AWS::Glue::Schema"),
		model.CloudResourceType("AWS::Glue::Trigger"),
		model.CloudResourceType("AWS::Glue::UsageProfile"),
		model.CloudResourceType("AWS::Grafana::Workspace"),
		model.CloudResourceType("AWS::GreengrassV2::Deployment"),
		model.CloudResourceType("AWS::GroundStation::Config"),
		model.CloudResourceType("AWS::GroundStation::DataflowEndpointGroup"),
		model.CloudResourceType("AWS::GroundStation::MissionProfile"),
		model.CloudResourceType("AWS::GuardDuty::Detector"),
		model.CloudResourceType("AWS::GuardDuty::MalwareProtectionPlan"),
		model.CloudResourceType("AWS::HealthImaging::Datastore"),
		model.CloudResourceType("AWS::HealthLake::FHIRDatastore"),
		model.AWSGroup,
		model.CloudResourceType("AWS::IAM::InstanceProfile"),
		model.CloudResourceType("AWS::IAM::ManagedPolicy"),
		model.CloudResourceType("AWS::IAM::OIDCProvider"),
		model.AWSRole,
		model.CloudResourceType("AWS::IAM::SAMLProvider"),
		model.CloudResourceType("AWS::IAM::ServerCertificate"),
		model.AWSUser,
		model.CloudResourceType("AWS::IAM::VirtualMFADevice"),
		model.CloudResourceType("AWS::ImageBuilder::ContainerRecipe"),
		model.CloudResourceType("AWS::ImageBuilder::DistributionConfiguration"),
		model.CloudResourceType("AWS::ImageBuilder::ImagePipeline"),
		model.CloudResourceType("AWS::ImageBuilder::ImageRecipe"),
		model.CloudResourceType("AWS::ImageBuilder::InfrastructureConfiguration"),
		model.CloudResourceType("AWS::ImageBuilder::LifecyclePolicy"),
		model.CloudResourceType("AWS::Inspector::AssessmentTarget"),
		model.CloudResourceType("AWS::Inspector::AssessmentTemplate"),
		model.CloudResourceType("AWS::InspectorV2::Filter"),
		model.CloudResourceType("AWS::InternetMonitor::Monitor"),
		model.CloudResourceType("AWS::IoT::AccountAuditConfiguration"),
		model.CloudResourceType("AWS::IoT::Authorizer"),
		model.CloudResourceType("AWS::IoT::BillingGroup"),
		model.CloudResourceType("AWS::IoT::CACertificate"),
		model.CloudResourceType("AWS::IoT::Certificate"),
		model.CloudResourceType("AWS::IoT::CertificateProvider"),
		model.CloudResourceType("AWS::IoT::CustomMetric"),
		model.CloudResourceType("AWS::IoT::Dimension"),
		model.CloudResourceType("AWS::IoT::DomainConfiguration"),
		model.CloudResourceType("AWS::IoT::FleetMetric"),
		model.CloudResourceType("AWS::IoT::JobTemplate"),
		model.CloudResourceType("AWS::IoT::Logging"),
		model.CloudResourceType("AWS::IoT::MitigationAction"),
		model.CloudResourceType("AWS::IoT::Policy"),
		model.CloudResourceType("AWS::IoT::ProvisioningTemplate"),
		model.CloudResourceType("AWS::IoT::ResourceSpecificLogging"),
		model.CloudResourceType("AWS::IoT::RoleAlias"),
		model.CloudResourceType("AWS::IoT::ScheduledAudit"),
		model.CloudResourceType("AWS::IoT::SecurityProfile"),
		model.CloudResourceType("AWS::IoT::SoftwarePackage"),
		model.CloudResourceType("AWS::IoT::Thing"),
		model.CloudResourceType("AWS::IoT::ThingGroup"),
		model.CloudResourceType("AWS::IoT::TopicRule"),
		model.CloudResourceType("AWS::IoT::TopicRuleDestination"),
		model.CloudResourceType("AWS::IoTAnalytics::Channel"),
		model.CloudResourceType("AWS::IoTAnalytics::Dataset"),
		model.CloudResourceType("AWS::IoTAnalytics::Datastore"),
		model.CloudResourceType("AWS::IoTAnalytics::Pipeline"),
		model.CloudResourceType("AWS::IoTCoreDeviceAdvisor::SuiteDefinition"),
		model.CloudResourceType("AWS::IoTEvents::AlarmModel"),
		model.CloudResourceType("AWS::IoTEvents::DetectorModel"),
		model.CloudResourceType("AWS::IoTEvents::Input"),
		model.CloudResourceType("AWS::IoTFleetWise::Campaign"),
		model.CloudResourceType("AWS::IoTFleetWise::DecoderManifest"),
		model.CloudResourceType("AWS::IoTFleetWise::Fleet"),
		model.CloudResourceType("AWS::IoTFleetWise::ModelManifest"),
		model.CloudResourceType("AWS::IoTFleetWise::SignalCatalog"),
		model.CloudResourceType("AWS::IoTFleetWise::Vehicle"),
		model.CloudResourceType("AWS::IoTSiteWise::Asset"),
		model.CloudResourceType("AWS::IoTSiteWise::AssetModel"),
		model.CloudResourceType("AWS::IoTSiteWise::Gateway"),
		model.CloudResourceType("AWS::IoTSiteWise::Portal"),
		model.CloudResourceType("AWS::IoTTwinMaker::Workspace"),
		model.CloudResourceType("AWS::IoTWireless::Destination"),
		model.CloudResourceType("AWS::IoTWireless::DeviceProfile"),
		model.CloudResourceType("AWS::IoTWireless::FuotaTask"),
		model.CloudResourceType("AWS::IoTWireless::MulticastGroup"),
		model.CloudResourceType("AWS::IoTWireless::NetworkAnalyzerConfiguration"),
		model.CloudResourceType("AWS::IoTWireless::PartnerAccount"),
		model.CloudResourceType("AWS::IoTWireless::ServiceProfile"),
		model.CloudResourceType("AWS::IoTWireless::TaskDefinition"),
		model.CloudResourceType("AWS::IoTWireless::WirelessDevice"),
		model.CloudResourceType("AWS::IoTWireless::WirelessDeviceImportTask"),
		model.CloudResourceType("AWS::IoTWireless::WirelessGateway"),
		model.CloudResourceType("AWS::IVS::Channel"),
		model.CloudResourceType("AWS::IVS::EncoderConfiguration"),
		model.CloudResourceType("AWS::IVS::PlaybackKeyPair"),
		model.CloudResourceType("AWS::IVS::PlaybackRestrictionPolicy"),
		model.CloudResourceType("AWS::IVS::PublicKey"),
		model.CloudResourceType("AWS::IVS::RecordingConfiguration"),
		model.CloudResourceType("AWS::IVS::Stage"),
		model.CloudResourceType("AWS::IVS::StorageConfiguration"),
		model.CloudResourceType("AWS::IVSChat::LoggingConfiguration"),
		model.CloudResourceType("AWS::IVSChat::Room"),
		model.CloudResourceType("AWS::KafkaConnect::Connector"),
		model.CloudResourceType("AWS::KafkaConnect::CustomPlugin"),
		model.CloudResourceType("AWS::KafkaConnect::WorkerConfiguration"),
		model.CloudResourceType("AWS::Kendra::Index"),
		model.CloudResourceType("AWS::KendraRanking::ExecutionPlan"),
		model.CloudResourceType("AWS::Kinesis::Stream"),
		model.CloudResourceType("AWS::KinesisAnalyticsV2::Application"),
		model.CloudResourceType("AWS::KinesisFirehose::DeliveryStream"),
		model.CloudResourceType("AWS::KMS::Alias"),
		model.CloudResourceType("AWS::KMS::Key"),
		model.CloudResourceType("AWS::KMS::ReplicaKey"),
		model.CloudResourceType("AWS::LakeFormation::DataCellsFilter"),
		model.CloudResourceType("AWS::LakeFormation::Tag"),
		model.CloudResourceType("AWS::Lambda::CodeSigningConfig"),
		model.CloudResourceType("AWS::Lambda::EventSourceMapping"),
		model.AWSLambdaFunction,
		model.CloudResourceType("AWS::LaunchWizard::Deployment"),
		model.CloudResourceType("AWS::Lex::Bot"),
		model.CloudResourceType("AWS::Lightsail::Alarm"),
		model.CloudResourceType("AWS::Lightsail::Bucket"),
		model.CloudResourceType("AWS::Lightsail::Certificate"),
		model.CloudResourceType("AWS::Lightsail::Container"),
		model.CloudResourceType("AWS::Lightsail::Database"),
		model.CloudResourceType("AWS::Lightsail::Disk"),
		model.CloudResourceType("AWS::Lightsail::Distribution"),
		model.CloudResourceType("AWS::Lightsail::Instance"),
		model.CloudResourceType("AWS::Lightsail::LoadBalancer"),
		model.CloudResourceType("AWS::Lightsail::StaticIp"),
		model.CloudResourceType("AWS::Location::APIKey"),
		model.CloudResourceType("AWS::Location::GeofenceCollection"),
		model.CloudResourceType("AWS::Location::Map"),
		model.CloudResourceType("AWS::Location::PlaceIndex"),
		model.CloudResourceType("AWS::Location::RouteCalculator"),
		model.CloudResourceType("AWS::Location::Tracker"),
		model.CloudResourceType("AWS::Logs::Delivery"),
		model.CloudResourceType("AWS::Logs::DeliveryDestination"),
		model.CloudResourceType("AWS::Logs::DeliverySource"),
		model.CloudResourceType("AWS::Logs::Destination"),
		model.CloudResourceType("AWS::Logs::LogAnomalyDetector"),
		model.CloudResourceType("AWS::Logs::LogGroup"),
		model.CloudResourceType("AWS::Logs::MetricFilter"),
		model.CloudResourceType("AWS::Logs::QueryDefinition"),
		model.CloudResourceType("AWS::Logs::ResourcePolicy"),
		model.CloudResourceType("AWS::LookoutEquipment::InferenceScheduler"),
		model.CloudResourceType("AWS::LookoutMetrics::Alert"),
		model.CloudResourceType("AWS::LookoutMetrics::AnomalyDetector"),
		model.CloudResourceType("AWS::LookoutVision::Project"),
		model.CloudResourceType("AWS::M2::Application"),
		model.CloudResourceType("AWS::M2::Environment"),
		model.CloudResourceType("AWS::Macie::Session"),
		model.CloudResourceType("AWS::ManagedBlockchain::Accessor"),
		model.CloudResourceType("AWS::MediaConnect::Bridge"),
		model.CloudResourceType("AWS::MediaConnect::Flow"),
		model.CloudResourceType("AWS::MediaConnect::Gateway"),
		model.CloudResourceType("AWS::MediaLive::CloudWatchAlarmTemplate"),
		model.CloudResourceType("AWS::MediaLive::CloudWatchAlarmTemplateGroup"),
		model.CloudResourceType("AWS::MediaLive::EventBridgeRuleTemplate"),
		model.CloudResourceType("AWS::MediaLive::EventBridgeRuleTemplateGroup"),
		model.CloudResourceType("AWS::MediaLive::Multiplex"),
		model.CloudResourceType("AWS::MediaLive::SignalMap"),
		model.CloudResourceType("AWS::MediaPackage::Channel"),
		model.CloudResourceType("AWS::MediaPackage::OriginEndpoint"),
		model.CloudResourceType("AWS::MediaPackage::PackagingGroup"),
		model.CloudResourceType("AWS::MediaPackageV2::ChannelGroup"),
		model.CloudResourceType("AWS::MediaTailor::Channel"),
		model.CloudResourceType("AWS::MediaTailor::PlaybackConfiguration"),
		model.CloudResourceType("AWS::MediaTailor::SourceLocation"),
		model.CloudResourceType("AWS::MemoryDB::ACL"),
		model.CloudResourceType("AWS::MemoryDB::Cluster"),
		model.CloudResourceType("AWS::MemoryDB::ParameterGroup"),
		model.CloudResourceType("AWS::MemoryDB::SubnetGroup"),
		model.CloudResourceType("AWS::MemoryDB::User"),
		model.CloudResourceType("AWS::MSK::Cluster"),
		model.CloudResourceType("AWS::MSK::Configuration"),
		model.CloudResourceType("AWS::MSK::Replicator"),
		model.CloudResourceType("AWS::MSK::ServerlessCluster"),
		model.CloudResourceType("AWS::MSK::VpcConnection"),
		model.CloudResourceType("AWS::MWAA::Environment"),
		model.CloudResourceType("AWS::Neptune::DBCluster"),
		model.CloudResourceType("AWS::NeptuneGraph::Graph"),
		model.CloudResourceType("AWS::NetworkFirewall::Firewall"),
		model.CloudResourceType("AWS::NetworkFirewall::FirewallPolicy"),
		model.CloudResourceType("AWS::NetworkFirewall::RuleGroup"),
		model.CloudResourceType("AWS::NetworkFirewall::TLSInspectionConfiguration"),
		model.CloudResourceType("AWS::NetworkManager::ConnectAttachment"),
		model.CloudResourceType("AWS::NetworkManager::ConnectPeer"),
		model.CloudResourceType("AWS::NetworkManager::CoreNetwork"),
		model.CloudResourceType("AWS::NetworkManager::GlobalNetwork"),
		model.CloudResourceType("AWS::NetworkManager::SiteToSiteVpnAttachment"),
		model.CloudResourceType("AWS::NetworkManager::TransitGatewayPeering"),
		model.CloudResourceType("AWS::NetworkManager::TransitGatewayRouteTableAttachment"),
		model.CloudResourceType("AWS::NetworkManager::VpcAttachment"),
		model.CloudResourceType("AWS::Oam::Link"),
		model.CloudResourceType("AWS::Oam::Sink"),
		model.CloudResourceType("AWS::Omics::AnnotationStore"),
		model.CloudResourceType("AWS::Omics::ReferenceStore"),
		model.CloudResourceType("AWS::Omics::RunGroup"),
		model.CloudResourceType("AWS::Omics::SequenceStore"),
		model.CloudResourceType("AWS::Omics::VariantStore"),
		model.CloudResourceType("AWS::Omics::Workflow"),
		model.CloudResourceType("AWS::OpenSearchServerless::Collection"),
		model.CloudResourceType("AWS::OpenSearchServerless::VpcEndpoint"),
		model.CloudResourceType("AWS::OpenSearchService::Application"),
		model.CloudResourceType("AWS::Organizations::Organization"),
		model.CloudResourceType("AWS::OSIS::Pipeline"),
		model.CloudResourceType("AWS::Panorama::ApplicationInstance"),
		model.CloudResourceType("AWS::Panorama::Package"),
		model.CloudResourceType("AWS::PaymentCryptography::Alias"),
		model.CloudResourceType("AWS::PaymentCryptography::Key"),
		model.CloudResourceType("AWS::PCAConnectorAD::Connector"),
		model.CloudResourceType("AWS::PCAConnectorAD::DirectoryRegistration"),
		model.CloudResourceType("AWS::PCAConnectorSCEP::Connector"),
		model.CloudResourceType("AWS::Personalize::Dataset"),
		model.CloudResourceType("AWS::Personalize::DatasetGroup"),
		model.CloudResourceType("AWS::Personalize::Schema"),
		model.CloudResourceType("AWS::Personalize::Solution"),
		model.CloudResourceType("AWS::Pinpoint::InAppTemplate"),
		model.CloudResourceType("AWS::Pipes::Pipe"),
		model.CloudResourceType("AWS::Proton::EnvironmentAccountConnection"),
		model.CloudResourceType("AWS::Proton::EnvironmentTemplate"),
		model.CloudResourceType("AWS::Proton::ServiceTemplate"),
		model.CloudResourceType("AWS::QBusiness::Application"),
		model.CloudResourceType("AWS::RAM::Permission"),
		model.CloudResourceType("AWS::RDS::CustomDBEngineVersion"),
		model.CloudResourceType("AWS::RDS::DBCluster"),
		model.CloudResourceType("AWS::RDS::DBClusterParameterGroup"),
		model.AWSRDSInstance,
		model.CloudResourceType("AWS::RDS::DBParameterGroup"),
		model.CloudResourceType("AWS::RDS::DBProxy"),
		model.CloudResourceType("AWS::RDS::DBProxyEndpoint"),
		model.CloudResourceType("AWS::RDS::DBShardGroup"),
		model.CloudResourceType("AWS::RDS::DBSubnetGroup"),
		model.CloudResourceType("AWS::RDS::EventSubscription"),
		model.CloudResourceType("AWS::RDS::GlobalCluster"),
		model.CloudResourceType("AWS::RDS::Integration"),
		model.CloudResourceType("AWS::RDS::OptionGroup"),
		model.CloudResourceType("AWS::Redshift::Cluster"),
		model.CloudResourceType("AWS::Redshift::ClusterParameterGroup"),
		model.CloudResourceType("AWS::Redshift::ClusterSubnetGroup"),
		model.CloudResourceType("AWS::Redshift::EndpointAccess"),
		model.CloudResourceType("AWS::Redshift::EndpointAuthorization"),
		model.CloudResourceType("AWS::Redshift::EventSubscription"),
		model.CloudResourceType("AWS::Redshift::Integration"),
		model.CloudResourceType("AWS::Redshift::ScheduledAction"),
		model.CloudResourceType("AWS::RedshiftServerless::Namespace"),
		model.CloudResourceType("AWS::RedshiftServerless::Workgroup"),
		model.CloudResourceType("AWS::RefactorSpaces::Environment"),
		model.CloudResourceType("AWS::Rekognition::Collection"),
		model.CloudResourceType("AWS::Rekognition::Project"),
		model.CloudResourceType("AWS::Rekognition::StreamProcessor"),
		model.CloudResourceType("AWS::ResilienceHub::App"),
		model.CloudResourceType("AWS::ResilienceHub::ResiliencyPolicy"),
		model.CloudResourceType("AWS::ResourceExplorer2::Index"),
		model.CloudResourceType("AWS::ResourceExplorer2::View"),
		model.CloudResourceType("AWS::ResourceGroups::Group"),
		model.CloudResourceType("AWS::RoboMaker::RobotApplication"),
		model.CloudResourceType("AWS::RoboMaker::SimulationApplication"),
		model.CloudResourceType("AWS::RolesAnywhere::CRL"),
		model.CloudResourceType("AWS::RolesAnywhere::Profile"),
		model.CloudResourceType("AWS::RolesAnywhere::TrustAnchor"),
		model.CloudResourceType("AWS::Route53::CidrCollection"),
		model.CloudResourceType("AWS::Route53::DNSSEC"),
		model.CloudResourceType("AWS::Route53::HealthCheck"),
		model.CloudResourceType("AWS::Route53::HostedZone"),
		model.CloudResourceType("AWS::Route53::KeySigningKey"),
		model.CloudResourceType("AWS::Route53Profiles::Profile"),
		model.CloudResourceType("AWS::Route53Profiles::ProfileAssociation"),
		model.CloudResourceType("AWS::Route53RecoveryControl::Cluster"),
		model.CloudResourceType("AWS::Route53RecoveryControl::ControlPanel"),
		model.CloudResourceType("AWS::Route53RecoveryReadiness::Cell"),
		model.CloudResourceType("AWS::Route53RecoveryReadiness::ReadinessCheck"),
		model.CloudResourceType("AWS::Route53RecoveryReadiness::RecoveryGroup"),
		model.CloudResourceType("AWS::Route53RecoveryReadiness::ResourceSet"),
		model.CloudResourceType("AWS::Route53Resolver::FirewallDomainList"),
		model.CloudResourceType("AWS::Route53Resolver::FirewallRuleGroup"),
		model.CloudResourceType("AWS::Route53Resolver::FirewallRuleGroupAssociation"),
		model.CloudResourceType("AWS::Route53Resolver::OutpostResolver"),
		model.CloudResourceType("AWS::Route53Resolver::ResolverConfig"),
		model.CloudResourceType("AWS::Route53Resolver::ResolverDNSSECConfig"),
		model.CloudResourceType("AWS::Route53Resolver::ResolverQueryLoggingConfig"),
		model.CloudResourceType("AWS::Route53Resolver::ResolverQueryLoggingConfigAssociation"),
		model.CloudResourceType("AWS::Route53Resolver::ResolverRule"),
		model.CloudResourceType("AWS::Route53Resolver::ResolverRuleAssociation"),
		model.CloudResourceType("AWS::RUM::AppMonitor"),
		model.CloudResourceType("AWS::S3::AccessGrantsInstance"),
		model.CloudResourceType("AWS::S3::AccessPoint"),
		model.AWSS3Bucket,
		model.CloudResourceType("AWS::S3::BucketPolicy"),
		model.CloudResourceType("AWS::S3::MultiRegionAccessPoint"),
		model.CloudResourceType("AWS::S3::StorageLens"),
		model.CloudResourceType("AWS::S3::StorageLensGroup"),
		model.CloudResourceType("AWS::S3Express::BucketPolicy"),
		model.CloudResourceType("AWS::S3Express::DirectoryBucket"),
		model.CloudResourceType("AWS::S3ObjectLambda::AccessPoint"),
		model.CloudResourceType("AWS::S3Outposts::Endpoint"),
		model.CloudResourceType("AWS::SageMaker::App"),
		model.CloudResourceType("AWS::SageMaker::AppImageConfig"),
		model.CloudResourceType("AWS::SageMaker::Cluster"),
		model.CloudResourceType("AWS::SageMaker::DataQualityJobDefinition"),
		model.CloudResourceType("AWS::SageMaker::Domain"),
		model.CloudResourceType("AWS::SageMaker::FeatureGroup"),
		model.CloudResourceType("AWS::SageMaker::Image"),
		model.CloudResourceType("AWS::SageMaker::InferenceComponent"),
		model.CloudResourceType("AWS::SageMaker::InferenceExperiment"),
		model.CloudResourceType("AWS::SageMaker::MlflowTrackingServer"),
		model.CloudResourceType("AWS::SageMaker::ModelBiasJobDefinition"),
		model.CloudResourceType("AWS::SageMaker::ModelCard"),
		model.CloudResourceType("AWS::SageMaker::ModelExplainabilityJobDefinition"),
		model.CloudResourceType("AWS::SageMaker::ModelPackage"),
		model.CloudResourceType("AWS::SageMaker::ModelPackageGroup"),
		model.CloudResourceType("AWS::SageMaker::ModelQualityJobDefinition"),
		model.CloudResourceType("AWS::SageMaker::MonitoringSchedule"),
		model.CloudResourceType("AWS::SageMaker::Pipeline"),
		model.CloudResourceType("AWS::SageMaker::Project"),
		model.CloudResourceType("AWS::SageMaker::Space"),
		model.CloudResourceType("AWS::SageMaker::StudioLifecycleConfig"),
		model.CloudResourceType("AWS::SageMaker::UserProfile"),
		model.CloudResourceType("AWS::Scheduler::Schedule"),
		model.CloudResourceType("AWS::Scheduler::ScheduleGroup"),
		model.CloudResourceType("AWS::SecretsManager::ResourcePolicy"),
		model.CloudResourceType("AWS::SecretsManager::RotationSchedule"),
		model.CloudResourceType("AWS::SecretsManager::Secret"),
		model.CloudResourceType("AWS::SecretsManager::SecretTargetAttachment"),
		model.CloudResourceType("AWS::SecurityHub::Hub"),
		model.CloudResourceType("AWS::ServiceCatalog::ServiceAction"),
		model.CloudResourceType("AWS::ServiceCatalogAppRegistry::Application"),
		model.CloudResourceType("AWS::ServiceCatalogAppRegistry::AttributeGroup"),
		model.CloudResourceType("AWS::SES::ConfigurationSet"),
		model.CloudResourceType("AWS::SES::ContactList"),
		model.CloudResourceType("AWS::SES::DedicatedIpPool"),
		model.CloudResourceType("AWS::SES::EmailIdentity"),
		model.CloudResourceType("AWS::SES::MailManagerAddonInstance"),
		model.CloudResourceType("AWS::SES::MailManagerAddonSubscription"),
		model.CloudResourceType("AWS::SES::MailManagerArchive"),
		model.CloudResourceType("AWS::SES::MailManagerIngressPoint"),
		model.CloudResourceType("AWS::SES::MailManagerRelay"),
		model.CloudResourceType("AWS::SES::MailManagerRuleSet"),
		model.CloudResourceType("AWS::SES::MailManagerTrafficPolicy"),
		model.CloudResourceType("AWS::SES::Template"),
		model.CloudResourceType("AWS::Signer::SigningProfile"),
		model.CloudResourceType("AWS::SimSpaceWeaver::Simulation"),
		model.CloudResourceType("AWS::SNS::Subscription"),
		model.AWSSNSTopic,
		model.AWSSQSQueue,
		model.CloudResourceType("AWS::SSM::Association"),
		model.CloudResourceType("AWS::SSM::Document"),
		model.CloudResourceType("AWS::SSM::Parameter"),
		model.CloudResourceType("AWS::SSM::PatchBaseline"),
		model.CloudResourceType("AWS::SSM::ResourceDataSync"),
		model.CloudResourceType("AWS::SSM::ResourcePolicy"),
		model.CloudResourceType("AWS::SSMContacts::Contact"),
		model.CloudResourceType("AWS::SSMIncidents::ReplicationSet"),
		model.CloudResourceType("AWS::SSMIncidents::ResponsePlan"),
		model.CloudResourceType("AWS::SSMQuickSetup::ConfigurationManager"),
		model.CloudResourceType("AWS::SSO::Instance"),
		model.CloudResourceType("AWS::StepFunctions::Activity"),
		model.CloudResourceType("AWS::StepFunctions::StateMachine"),
		model.CloudResourceType("AWS::SupportApp::AccountAlias"),
		model.CloudResourceType("AWS::SupportApp::SlackChannelConfiguration"),
		model.CloudResourceType("AWS::SupportApp::SlackWorkspaceConfiguration"),
		model.CloudResourceType("AWS::Synthetics::Canary"),
		model.CloudResourceType("AWS::Synthetics::Group"),
		model.CloudResourceType("AWS::SystemsManagerSAP::Application"),
		model.CloudResourceType("AWS::Timestream::Database"),
		model.CloudResourceType("AWS::Timestream::InfluxDBInstance"),
		model.CloudResourceType("AWS::Timestream::ScheduledQuery"),
		model.CloudResourceType("AWS::Timestream::Table"),
		model.CloudResourceType("AWS::Transfer::Certificate"),
		model.CloudResourceType("AWS::Transfer::Connector"),
		model.CloudResourceType("AWS::Transfer::Profile"),
		model.CloudResourceType("AWS::Transfer::Server"),
		model.CloudResourceType("AWS::Transfer::Workflow"),
		model.CloudResourceType("AWS::VerifiedPermissions::PolicyStore"),
		model.CloudResourceType("AWS::VoiceID::Domain"),
		model.CloudResourceType("AWS::VpcLattice::Service"),
		model.CloudResourceType("AWS::VpcLattice::ServiceNetwork"),
		model.CloudResourceType("AWS::VpcLattice::TargetGroup"),
		model.CloudResourceType("AWS::WAFv2::LoggingConfiguration"),
		model.CloudResourceType("AWS::Wisdom::Assistant"),
		model.CloudResourceType("AWS::Wisdom::KnowledgeBase"),
		model.CloudResourceType("AWS::WorkSpaces::WorkspacesPool"),
		model.CloudResourceType("AWS::WorkSpacesThinClient::Environment"),
		model.CloudResourceType("AWS::WorkSpacesWeb::BrowserSettings"),
		model.CloudResourceType("AWS::WorkSpacesWeb::IpAccessSettings"),
		model.CloudResourceType("AWS::WorkSpacesWeb::NetworkSettings"),
		model.CloudResourceType("AWS::WorkSpacesWeb::Portal"),
		model.CloudResourceType("AWS::WorkSpacesWeb::TrustStore"),
		model.CloudResourceType("AWS::WorkSpacesWeb::UserAccessLoggingSettings"),
		model.CloudResourceType("AWS::WorkSpacesWeb::UserSettings"),
		model.CloudResourceType("AWS::XRay::Group"),
		model.CloudResourceType("AWS::XRay::ResourcePolicy"),
		model.CloudResourceType("AWS::XRay::SamplingRule"),
	}

}
