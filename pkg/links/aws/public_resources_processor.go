package aws

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

const (
	// DefaultWorkerCount is the default number of concurrent workers for processing resources
	DefaultWorkerCount = 20
)

// AWSPublicResourcesProcessor processes ResourceChainPair objects concurrently for public resources
type AWSPublicResourcesProcessor struct {
	*base.AwsReconLink
	semaphore chan struct{}  // Limits concurrent processing
	wg        sync.WaitGroup // Tracks in-flight work
	sendMu    sync.Mutex     // Protects Send() calls
}

func NewAWSPublicResourcesProcessor(configs ...cfg.Config) chain.Link {
	p := &AWSPublicResourcesProcessor{}
	p.AwsReconLink = base.NewAwsReconLink(p, configs...)
	return p
}

func (p *AWSPublicResourcesProcessor) Params() []cfg.Param {
	params := p.AwsReconLink.Params()
	params = append(params, cfg.NewParam[int]("workers", "Number of concurrent workers for processing resources").WithDefault(DefaultWorkerCount))
	return params
}

func (p *AWSPublicResourcesProcessor) Initialize() error {
	if err := p.AwsReconLink.Initialize(); err != nil {
		return err
	}

	// Initialize semaphore with worker count
	workerCount, _ := cfg.As[int](p.Arg("workers"))
	if workerCount <= 0 {
		workerCount = DefaultWorkerCount
	}
	p.semaphore = make(chan struct{}, workerCount)
	slog.Debug("Initialized public resources processor", "workers", workerCount)

	return nil
}

func (p *AWSPublicResourcesProcessor) Process(pair *ResourceChainPair) error {
	// Ensure Initialize() was called before Process()
	if p.semaphore == nil {
		return fmt.Errorf("processor not initialized: call Initialize before Process")
	}

	// Acquire semaphore slot (blocks if all workers are busy)
	p.semaphore <- struct{}{}
	p.wg.Add(1)

	// Process in goroutine for concurrency
	go func() {
		// Ensure cleanup happens even on panic
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Panic in resource processor", "resource", pair.Resource.Identifier, "panic", r)
			}
			<-p.semaphore // Release semaphore slot
			p.wg.Done()
		}()

		p.processResource(pair)
	}()

	return nil
}

// processResource handles the actual processing of a single resource
func (p *AWSPublicResourcesProcessor) processResource(pair *ResourceChainPair) {
	slog.Debug("Processing public resource chain",
		"resource_type", pair.Resource.TypeName,
		"resource_id", pair.Resource.Identifier)

	// Build the specific chain for this resource type
	resourceChain := pair.ChainConstructor()
	if resourceChain == nil {
		slog.Error("Failed to create resource chain", "resource", pair.Resource.Identifier)
		return
	}

	// Only pass essential AWS parameters, not module-level parameters
	essentialArgs := p.extractEssentialArgs(pair.Args)
	if len(essentialArgs) > 0 {
		resourceChain.WithConfigs(cfg.WithArgs(essentialArgs))
	}

	// Process the resource
	if err := resourceChain.Send(pair.Resource); err != nil {
		slog.Error("Failed to send resource to chain", "error", err)
		resourceChain.Close()
		resourceChain.Wait()
		return
	}
	resourceChain.Close()

	// Stream outputs while the chain is running - consume before Wait()
	for output, ok := chain.RecvAs[*types.EnrichedResourceDescription](resourceChain); ok; output, ok = chain.RecvAs[*types.EnrichedResourceDescription](resourceChain) {
		slog.Debug("Forwarding output", "resource_type", pair.Resource.TypeName, "output_type", fmt.Sprintf("%T", output))

		// Protect Send() with mutex since multiple goroutines may call it
		p.sendMu.Lock()
		if err := p.Send(output); err != nil {
			slog.Error("Failed to send output", "error", err)
		}
		p.sendMu.Unlock()
	}

	// Wait for chain completion after consuming all outputs
	resourceChain.Wait()

	if err := resourceChain.Error(); err != nil {
		slog.Error("Error processing public resource chain", "resource", pair.Resource, "error", err)
		return
	}

	slog.Debug("Completed processing public resource chain", "resource_type", pair.Resource.TypeName)
}

// Complete waits for all in-flight workers to finish
func (p *AWSPublicResourcesProcessor) Complete() error {
	slog.Debug("Waiting for all public resource workers to complete")
	p.wg.Wait()
	slog.Debug("All public resource workers completed")
	return nil
}

// extractEssentialArgs extracts only AWS-specific parameters needed by resource chains
// Excludes module-level and outputter-specific parameters to prevent conflicts
func (p *AWSPublicResourcesProcessor) extractEssentialArgs(args map[string]any) map[string]any {
	// Only include essential AWS parameters that resource chains need
	essentialParams := map[string]bool{
		"profile":          true, // AWS profile
		"regions":          true, // AWS regions
		"cache-dir":        true, // Cache directory
		"cache-ttl":        true, // Cache TTL
		"disable-cache":    true, // Cache disable flag
		"cache-ext":        true, // Cache extension
		"cache-error-resp": true, // Cache error response flag
	}

	essential := make(map[string]any)
	for key, value := range args {
		if essentialParams[key] {
			essential[key] = value
		} else {
			slog.Debug("Excluding non-essential parameter from public resource chain", "param", key)
		}
	}

	return essential
}
