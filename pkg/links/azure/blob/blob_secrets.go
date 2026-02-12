package blob

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// scannedAccounts prevents duplicate scans when account appears in multiple regions
var scannedAccounts sync.Map

// BlobSecretsConfig configures secrets scanning for Azure Blob Storage
type BlobSecretsConfig struct {
	MaxObjectSize   int64         // Maximum object size to scan (bytes)
	SkipExtensions  []string      // File extensions to skip
	ExcludePatterns []string      // Path patterns to exclude
	MaxAge          time.Duration // Only scan objects modified within this duration (0 = no limit)
	ScanMode        string        // "critical" (default) or "all"
}

// AzureBlobSecrets scans Azure Blob Storage for secrets
type AzureBlobSecrets struct {
	config BlobSecretsConfig
	logger *slog.Logger
	region string
}

// SendFunc is the type for sending NoseyParker inputs
type SendFunc func(any) error

// Default configuration values
var (
	defaultSkipExtensions = []string{
		// Archives
		".zip", ".tar", ".tar.gz", ".gz", ".7z", ".rar", ".bz2",
		// Binaries
		".exe", ".dll", ".so", ".dylib", ".jar",
		// Images
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp",
		// Video
		".mp4", ".mkv", ".avi", ".mov", ".flv", ".wmv",
		// Audio
		".mp3", ".flac", ".wav", ".ogg", ".aac",
		// Fonts
		".ttf", ".otf", ".woff", ".woff2",
		// Lock files
		".lock",
	}

	defaultExcludePatterns = []string{
		"/node_modules/",
		"/vendor/",
		"/.git/",
		"/test-data/",
		"/tmp/",
		"/__pycache__/",
	}
)

// NewAzureBlobSecrets creates a new Azure Blob secrets scanner
func NewAzureBlobSecrets(scanMode string) *AzureBlobSecrets {
	return &AzureBlobSecrets{
		config: BlobSecretsConfig{
			MaxObjectSize:   100 * 1024 * 1024, // 100MB default
			SkipExtensions:  defaultSkipExtensions,
			ExcludePatterns: defaultExcludePatterns,
			MaxAge:          0,        // No age limit by default
			ScanMode:        scanMode, // "critical" or "all"
		},
		logger: slog.Default(),
	}
}

// parseStorageAccountFromKey extracts subscription ID and account name from nebula key
func parseStorageAccountFromKey(key string) (subscriptionID, accountName string, err error) {
	// Format: #azureresource#subscription#/subscriptions/{subID}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{accountName}
	parts := strings.Split(key, "#")
	if len(parts) < 4 {
		return "", "", fmt.Errorf("invalid nebula resource key format")
	}
	actualResourceID := parts[3] // The actual Azure resource ID

	parsed, err := helpers.ParseAzureResourceID(actualResourceID)
	if err != nil {
		return "", "", err
	}

	subscriptionID = parsed["subscriptions"]
	accountName = parsed["storageAccounts"]

	if subscriptionID == "" || accountName == "" {
		return "", "", fmt.Errorf("invalid storage account resource ID format")
	}

	return subscriptionID, accountName, nil
}

// Process scans an Azure storage account for secrets
func (s *AzureBlobSecrets) Process(ctx context.Context, resource *model.AzureResource, send SendFunc) error {
	// Parse storage account details from resource key
	subscriptionID, accountName, err := parseStorageAccountFromKey(resource.Key)
	if err != nil {
		return fmt.Errorf("failed to parse storage account key: %w", err)
	}

	// Deduplicate: Skip if already scanned
	if _, alreadyScanned := scannedAccounts.LoadOrStore(accountName, true); alreadyScanned {
		s.logger.Info("Skipping already-scanned storage account (duplicate from multi-region query)",
			"account", accountName,
			"subscription", subscriptionID)
		return nil
	}

	s.region = resource.Region

	s.logger.Debug("Starting Azure Blob storage scan",
		"account", accountName,
		"subscription", subscriptionID)

	// Get Azure credential
	cred, err := helpers.NewAzureCredential()
	if err != nil {
		return fmt.Errorf("failed to get Azure credential: %w", err)
	}

	// Build service URL
	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", accountName)

	// Create blob service client
	client, err := azblob.NewClient(serviceURL, cred, nil)
	if err != nil {
		s.logger.Error("Failed to create blob client, storage account may be unreachable",
			"account", accountName)
		return nil // Don't fail chain
	}

	// List containers
	pager := client.NewListContainersPager(nil)

	// Track scan progress
	var scannedCount, skippedCount int64

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			s.logger.Error("Failed to list containers", "error", err, "account", accountName)
			return nil // Don't fail chain
		}

		for _, container := range page.ContainerItems {
			if container.Name == nil {
				continue
			}

			scanned, skipped, err := s.processContainer(ctx, client, accountName, *container.Name, subscriptionID, send)
			if err != nil {
				s.logger.Warn("Failed to process container",
					"error", err,
					"container", *container.Name,
					"account", accountName)
				continue
			}

			scannedCount += scanned
			skippedCount += skipped
		}
	}

	// Log completion with statistics
	totalProcessed := scannedCount + skippedCount
	skipPercentage := 0.0
	if totalProcessed > 0 {
		skipPercentage = float64(skippedCount) / float64(totalProcessed) * 100
	}

	s.logger.Info("Azure Blob storage scan complete",
		"account", accountName,
		"scan_mode", s.config.ScanMode,
		"total_objects", totalProcessed,
		"scanned", scannedCount,
		"skipped", skippedCount,
		"skip_percentage", fmt.Sprintf("%.1f%%", skipPercentage))

	return nil
}

// processContainer processes all blobs in a container
func (s *AzureBlobSecrets) processContainer(
	ctx context.Context,
	client *azblob.Client,
	accountName string,
	containerName string,
	subscriptionID string,
	send SendFunc,
) (scanned int64, skipped int64, err error) {
	s.logger.Debug("Processing container", "container", containerName, "account", accountName)

	pager := client.NewListBlobsFlatPager(containerName, nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			// Container access denied - log warning but continue
			errStr := err.Error()
			if strings.Contains(errStr, "AuthorizationPermissionMismatch") ||
				strings.Contains(errStr, "AuthorizationFailure") ||
				strings.Contains(errStr, "AuthenticationFailed") ||
				strings.Contains(errStr, "PublicAccessNotPermitted") ||
				strings.Contains(errStr, "403") {
				s.logger.Warn("Container access denied, skipping",
					"container", containerName,
					"account", accountName)
				return 0, 0, nil
			}
			return scanned, skipped, fmt.Errorf("failed to list blobs: %w", err)
		}

		for _, blob := range page.Segment.BlobItems {
			if blob.Name == nil {
				continue
			}

			scannedBlob, err := s.processBlob(ctx, client, accountName, containerName, blob, subscriptionID, send)
			if err != nil {
				s.logger.Warn("Failed to process blob",
					"error", err,
					"blob", *blob.Name,
					"container", containerName)
				skipped++
				continue
			}

			if scannedBlob {
				scanned++
			} else {
				skipped++
			}

			// Log progress every 100 objects
			totalProcessed := scanned + skipped
			if totalProcessed > 0 && totalProcessed%100 == 0 {
				s.logger.Debug("Container scan progress",
					"container", containerName,
					"account", accountName,
					"processed", totalProcessed,
					"scanned", scanned,
					"skipped", skipped)
			}
		}
	}

	return scanned, skipped, nil
}

// processBlob processes a single blob
func (s *AzureBlobSecrets) processBlob(
	ctx context.Context,
	client *azblob.Client,
	accountName string,
	containerName string,
	blob *container.BlobItem,
	subscriptionID string,
	send SendFunc,
) (bool, error) {
	if blob.Name == nil || blob.Properties == nil {
		return false, nil
	}

	blobName := *blob.Name
	size := int64(0)
	if blob.Properties.ContentLength != nil {
		size = *blob.Properties.ContentLength
	}

	var lastModified time.Time
	if blob.Properties.LastModified != nil {
		lastModified = *blob.Properties.LastModified
	}

	// Tier 2: Metadata filtering
	if !s.shouldScanBlob(blobName, size, lastModified) {
		return false, nil
	}

	// Tier 3: Binary detection (download first 512 bytes)
	if s.isBinaryBlob(ctx, client, containerName, blobName) {
		s.logger.Debug("Skipping blob", "blob", blobName, "reason", "binary content detected")
		return false, nil
	}

	// Tier 4: Full download
	content, err := s.downloadBlob(ctx, client, containerName, blobName)
	if err != nil {
		return false, fmt.Errorf("failed to download blob: %w", err)
	}

	// Generate NPInput and send to NoseyParker
	if err := s.sendToNoseyParker(accountName, containerName, blobName, content, subscriptionID, s.region, send); err != nil {
		return false, fmt.Errorf("failed to scan with NoseyParker: %w", err)
	}

	return true, nil
}

// matchesCriticalPattern checks if filename indicates critical credential file
func matchesCriticalPattern(key string) bool {
	lowerKey := strings.ToLower(key)

	criticalPatterns := []string{
		// Terraform state and vars
		"terraform.tfstate", ".tfstate",
		".tfvars", "terraform.tfvars",

		// Environment files
		".env",

		// Cloud credentials
		"credentials.json", "credentials.csv", "credentials",
		"service-account.json", "gcp-keyfile",
		"aws-config", "azure-credentials",

		// SSH/SSL keys
		"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
		".pem", ".key", "private-key",

		// Generic secret patterns
		"secret.json", "secret.yml", "secrets.yaml",
		"password", "token",

		// Vault configs
		".vault.yml", "vault.yml",

		// Application configs (may contain secrets)
		"config.json", "config.yml", "config.yaml",
		"appsettings.json",
		"database.yml", "database.json", "db.config",
		"settings.json", "settings.yml",
		"application.properties",

		// Container configs
		"docker-compose.yml", "docker-compose.yaml",
		".dockercfg",
		"kubeconfig",

		// CI/CD configs
		".gitlab-ci.yml",
		"buildspec.yml",
		"jenkinsfile",
		".circleci/config.yml",
		".github/workflows",

		// Database connection
		".pgpass",
		".my.cnf",

		// Package manager configs
		".npmrc",
		".pypirc",
		"settings.xml", // Maven
	}

	for _, pattern := range criticalPatterns {
		if strings.Contains(lowerKey, pattern) {
			return true
		}
	}

	return false
}

// shouldScanBlob checks if a blob should be scanned based on metadata
func (s *AzureBlobSecrets) shouldScanBlob(name string, size int64, lastModified time.Time) bool {
	lowerName := strings.ToLower(name)

	// Tier 1: Critical patterns (bypass ALL filters)
	if matchesCriticalPattern(lowerName) {
		s.logger.Debug("Critical priority file - bypassing all filters",
			"blob", name,
			"mode", s.config.ScanMode)
		return true
	}

	// Tier 2: If mode is "all", apply standard filters
	if s.config.ScanMode == "all" {
		return s.passesStandardFilters(name, size, lastModified)
	}

	// Tier 3: If mode is "critical" (default), skip everything else
	s.logger.Debug("Skipping non-critical file in critical mode",
		"blob", name)
	return false
}

// passesStandardFilters checks if a blob passes size, age, extension, and path filters
func (s *AzureBlobSecrets) passesStandardFilters(name string, size int64, lastModified time.Time) bool {
	// Check size
	if size > s.config.MaxObjectSize {
		s.logger.Debug("Skipping blob", "blob", name, "reason", "exceeds size limit", "size", size)
		return false
	}
	if size == 0 {
		s.logger.Debug("Skipping blob", "blob", name, "reason", "empty file", "size", 0)
		return false
	}

	// Check age (if configured)
	if s.config.MaxAge > 0 && !lastModified.IsZero() {
		if time.Since(lastModified) > s.config.MaxAge {
			s.logger.Debug("Skipping blob", "blob", name, "reason", "exceeds max age", "age", time.Since(lastModified))
			return false
		}
	}

	// Check extension
	ext := strings.ToLower(filepath.Ext(name))
	for _, skipExt := range s.config.SkipExtensions {
		if ext == skipExt {
			s.logger.Debug("Skipping blob", "blob", name, "reason", "binary extension", "ext", ext)
			return false
		}
	}

	// Check path exclusions
	for _, pattern := range s.config.ExcludePatterns {
		if strings.Contains(name, pattern) {
			s.logger.Debug("Skipping blob", "blob", name, "reason", "excluded path", "pattern", pattern)
			return false
		}
	}

	// Skip directory markers
	if strings.HasSuffix(name, "/") {
		s.logger.Debug("Skipping blob", "blob", name, "reason", "directory marker")
		return false
	}

	return true
}

// isBinaryBlob checks if a blob is binary by downloading first 512 bytes
func (s *AzureBlobSecrets) isBinaryBlob(ctx context.Context, client *azblob.Client, containerName, blobName string) bool {
	// Download first 512 bytes for magic number check
	resp, err := client.DownloadStream(ctx, containerName, blobName, &azblob.DownloadStreamOptions{
		Range: azblob.HTTPRange{Offset: 0, Count: 512},
	})
	if err != nil {
		s.logger.Warn("Failed to check binary status", "error", err, "blob", blobName)
		return false // Assume not binary if check fails
	}
	defer resp.Body.Close()

	header := make([]byte, 512)
	n, _ := io.ReadFull(resp.Body, header)
	if n == 0 {
		return false
	}

	return isBinaryFile(header[:n])
}

// downloadBlob downloads the full contents of a blob
func (s *AzureBlobSecrets) downloadBlob(ctx context.Context, client *azblob.Client, containerName, blobName string) ([]byte, error) {
	resp, err := client.DownloadStream(ctx, containerName, blobName, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// sendToNoseyParker sends blob content to NoseyParker for secret scanning
func (s *AzureBlobSecrets) sendToNoseyParker(
	accountName string,
	containerName string,
	blobName string,
	content []byte,
	subscriptionID string,
	region string,
	send SendFunc,
) error {
	// Check if content is binary
	var npInput jtypes.NPInput
	if isBinaryFile(content) {
		npInput = jtypes.NPInput{
			ContentBase64: base64.StdEncoding.EncodeToString(content),
			Provenance: jtypes.NPProvenance{
				Kind:         "file",
				Platform:     "azure",
				ResourceType: "Microsoft.Storage/storageAccounts::BlobContent",
				ResourceID:   fmt.Sprintf("%s/%s/%s", accountName, containerName, blobName),
				AccountID:    subscriptionID,
				Region:       region,
				RepoPath:     fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", accountName, containerName, blobName),
			},
		}
	} else {
		npInput = jtypes.NPInput{
			Content: string(content),
			Provenance: jtypes.NPProvenance{
				Kind:         "file",
				Platform:     "azure",
				ResourceType: "Microsoft.Storage/storageAccounts::BlobContent",
				ResourceID:   fmt.Sprintf("%s/%s/%s", accountName, containerName, blobName),
				AccountID:    subscriptionID,
				Region:       region,
				RepoPath:     fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", accountName, containerName, blobName),
			},
		}
	}

	return send(npInput)
}

// isBinaryFile checks if content is binary based on magic numbers
func isBinaryFile(header []byte) bool {
	// Check for null bytes (simple heuristic)
	for _, b := range header {
		if b == 0x00 {
			return true
		}
	}

	// Check common binary magic numbers
	magicNumbers := [][]byte{
		{0xFF, 0xD8, 0xFF},                               // JPEG
		{0x50, 0x4B, 0x03, 0x04},                         // ZIP
		{0x7F, 0x45, 0x4C, 0x46},                         // ELF
		{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, // PNG
		{0x47, 0x49, 0x46, 0x38},                         // GIF
		{0x25, 0x50, 0x44, 0x46},                         // PDF
		{0x1F, 0x8B, 0x08},                               // GZIP
	}

	for _, magic := range magicNumbers {
		if len(header) >= len(magic) && bytes.HasPrefix(header, magic) {
			return true
		}
	}

	return false
}

// ResetScannedAccounts clears the scanned accounts cache (for testing)
func ResetScannedAccounts() {
	scannedAccounts = sync.Map{}
}
