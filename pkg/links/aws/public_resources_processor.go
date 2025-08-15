package aws

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AWSPublicResourcesProcessor processes multiple ResourceChainPair objects in parallel
// using a worker pool pattern for maximum efficiency
type AWSPublicResourcesProcessor struct {
	*base.AwsReconLink
	maxWorkers    int
	workerPool    chan struct{}
	resourceQueue chan *ResourceChainPair
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
	activeChains  map[string]chain.Chain
	results       chan *types.EnrichedResourceDescription
}

func NewAWSPublicResourcesProcessor(configs ...cfg.Config) chain.Link {
	ctx, cancel := context.WithCancel(context.Background())

	// Default concurrency values
	maxWorkers := 100
	queueSize := 99999
	resultsSize := 99999

	p := &AWSPublicResourcesProcessor{
		maxWorkers:    maxWorkers,
		workerPool:    make(chan struct{}, maxWorkers),
		resourceQueue: make(chan *ResourceChainPair, queueSize),
		ctx:           ctx,
		cancel:        cancel,
		activeChains:  make(map[string]chain.Chain),
		results:       make(chan *types.EnrichedResourceDescription, resultsSize),
	}
	p.AwsReconLink = base.NewAwsReconLink(p, configs...)
	return p
}

func (p *AWSPublicResourcesProcessor) Initialize() error {
	if err := p.AwsReconLink.Initialize(); err != nil {
		return err
	}

	// Start the worker pool
	p.startWorkerPool()

	// Start the results processor
	go p.processResults()

	return nil
}

func (p *AWSPublicResourcesProcessor) startWorkerPool() {
	// Initialize worker pool
	for i := 0; i < p.maxWorkers; i++ {
		p.workerPool <- struct{}{}
	}

	// Start workers
	for i := 0; i < p.maxWorkers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
}

func (p *AWSPublicResourcesProcessor) worker() {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return
		case resource := <-p.resourceQueue:
			if resource == nil {
				return
			}
			p.processResource(resource)
		}
	}
}

func (p *AWSPublicResourcesProcessor) processResource(pair *ResourceChainPair) {
	// Acquire worker slot
	<-p.workerPool
	defer func() {
		p.workerPool <- struct{}{}
	}()

	slog.Debug("Processing resource in worker",
		"resource_type", pair.Resource.TypeName,
		"resource_id", pair.Resource.Identifier)

	// Build the specific chain for this resource type
	resourceChain := pair.ChainConstructor()
	chainID := fmt.Sprintf("%s-%s-%d", pair.Resource.TypeName, pair.Resource.Identifier, time.Now().UnixNano())

	// Track active chain
	p.mu.Lock()
	p.activeChains[chainID] = resourceChain
	p.mu.Unlock()

	defer func() {
		// Clean up the chain from active chains
		p.mu.Lock()
		delete(p.activeChains, chainID)
		p.mu.Unlock()
	}()

	// Only pass essential AWS parameters
	essentialArgs := p.extractEssentialArgs(pair.Args)
	if len(essentialArgs) > 0 {
		resourceChain.WithConfigs(cfg.WithArgs(essentialArgs))
	}

	// Process the resource
	if err := resourceChain.Send(pair.Resource); err != nil {
		slog.Error("Failed to send resource to chain", "error", err)
		return
	}
	resourceChain.Close()

	// Stream outputs to results channel
	for output, ok := chain.RecvAs[*types.EnrichedResourceDescription](resourceChain); ok; output, ok = chain.RecvAs[*types.EnrichedResourceDescription](resourceChain) {
		select {
		case p.results <- output:
			slog.Debug("Queued output for processing", "resource_type", pair.Resource.TypeName)
		case <-p.ctx.Done():
			return
		}
	}

	// Wait for chain completion
	resourceChain.Wait()

	if err := resourceChain.Error(); err != nil {
		slog.Error("Error processing resource chain", "resource", pair.Resource, "error", err)
		return
	}

	slog.Debug("Completed processing resource chain", "resource_type", pair.Resource.TypeName)
}

func (p *AWSPublicResourcesProcessor) processResults() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case result := <-p.results:
			if result == nil {
				continue
			}
			// Forward the result downstream
			if err := p.Send(result); err != nil {
				slog.Error("Failed to send result downstream", "error", err)
			}
		}
	}
}

func (p *AWSPublicResourcesProcessor) Process(pair *ResourceChainPair) error {
	select {
	case p.resourceQueue <- pair:
		slog.Debug("Queued resource for processing",
			"resource_type", pair.Resource.TypeName,
			"resource_id", pair.Resource.Identifier)
		return nil
	case <-p.ctx.Done():
		return fmt.Errorf("processor is shutting down")
	default:
		// Queue is full - wait for a slot to become available
		slog.Debug("Queue full, waiting for available slot",
			"resource_type", pair.Resource.TypeName,
			"max_workers", p.maxWorkers)

		select {
		case p.resourceQueue <- pair:
			slog.Debug("Successfully queued resource after waiting",
				"resource_type", pair.Resource.TypeName)
			return nil
		case <-p.ctx.Done():
			return fmt.Errorf("processor is shutting down while waiting")
		}
	}
}

func (p *AWSPublicResourcesProcessor) Close() {
	p.cancel()

	// Wait for all workers to finish
	p.wg.Wait()

	// Close channels
	close(p.resourceQueue)
	close(p.results)
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
