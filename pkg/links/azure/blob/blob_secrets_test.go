package blob

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestShouldScanBlob(t *testing.T) {
	tests := []struct {
		name         string
		blobName     string
		size         int64
		lastModified time.Time
		config       BlobSecretsConfig
		expected     bool
	}{
		{
			name:         "small text file should scan",
			blobName:     "config.txt",
			size:         1024, // 1KB
			lastModified: time.Now(),
			config:       defaultConfig(),
			expected:     true,
		},
		{
			name:         "large file should skip",
			blobName:     "large.log",
			size:         200 * 1024 * 1024, // 200MB
			lastModified: time.Now(),
			config:       defaultConfig(),
			expected:     false,
		},
		{
			name:         "binary extension .exe should skip",
			blobName:     "app.exe",
			size:         1024,
			lastModified: time.Now(),
			config:       defaultConfig(),
			expected:     false,
		},
		{
			name:         "zero size file should skip",
			blobName:     "empty.txt",
			size:         0,
			lastModified: time.Now(),
			config:       defaultConfig(),
			expected:     false,
		},
		{
			name:         "directory marker should skip",
			blobName:     "folder/",
			size:         0,
			lastModified: time.Now(),
			config:       defaultConfig(),
			expected:     false,
		},
		{
			name:         "node_modules path should skip",
			blobName:     "project/node_modules/package.json",
			size:         1024,
			lastModified: time.Now(),
			config:       defaultConfig(),
			expected:     false,
		},
		{
			name:         "old file with max age configured should skip",
			blobName:     "old.txt",
			size:         1024,
			lastModified: time.Now().Add(-48 * time.Hour),
			config: BlobSecretsConfig{
				MaxObjectSize:   100 * 1024 * 1024,
				SkipExtensions:  defaultSkipExtensions,
				ExcludePatterns: defaultExcludePatterns,
				MaxAge:          24 * time.Hour,
				ScanMode:        "all",
			},
			expected: false,
		},
		{
			name:         "recent file with max age configured should scan",
			blobName:     "recent.txt",
			size:         1024,
			lastModified: time.Now().Add(-1 * time.Hour),
			config: BlobSecretsConfig{
				MaxObjectSize:   100 * 1024 * 1024,
				SkipExtensions:  defaultSkipExtensions,
				ExcludePatterns: defaultExcludePatterns,
				MaxAge:          24 * time.Hour,
				ScanMode:        "all",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := &AzureBlobSecrets{config: tt.config, logger: slog.Default()}
			result := scanner.shouldScanBlob(tt.blobName, tt.size, tt.lastModified)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsBinaryFile(t *testing.T) {
	tests := []struct {
		name     string
		header   []byte
		expected bool
	}{
		{
			name:     "plain text should not be binary",
			header:   []byte("This is plain text content"),
			expected: false,
		},
		{
			name:     "null byte should be binary",
			header:   []byte{0x00, 0x01, 0x02},
			expected: true,
		},
		{
			name:     "JPEG magic number should be binary",
			header:   []byte{0xFF, 0xD8, 0xFF, 0xE0},
			expected: true,
		},
		{
			name:     "ZIP magic number should be binary",
			header:   []byte{0x50, 0x4B, 0x03, 0x04},
			expected: true,
		},
		{
			name:     "ELF magic number should be binary",
			header:   []byte{0x7F, 0x45, 0x4C, 0x46},
			expected: true,
		},
		{
			name:     "PNG magic number should be binary",
			header:   []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			expected: true,
		},
		{
			name:     "GIF magic number should be binary",
			header:   []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61},
			expected: true,
		},
		{
			name:     "PDF magic number should be binary",
			header:   []byte{0x25, 0x50, 0x44, 0x46, 0x2D},
			expected: true,
		},
		{
			name:     "GZIP magic number should be binary",
			header:   []byte{0x1F, 0x8B, 0x08},
			expected: true,
		},
		{
			name:     "empty header should not be binary",
			header:   []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBinaryFile(tt.header)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMatchesCriticalPattern verifies that critical credential files are detected
func TestMatchesCriticalPattern(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		// Terraform state and vars
		{"terraform.tfstate", "terraform.tfstate", true},
		{"backend terraform.tfstate", "backend/terraform.tfstate", true},
		{"custom.tfstate", "configs/prod.tfstate", true},
		{"terraform vars", "vars.tfvars", true},
		{"terraform.tfvars", "terraform.tfvars", true},

		// Environment files
		{".env", ".env", true},
		{".env.production", "backend/.env.production", true},

		// Cloud credentials
		{"credentials.json", "credentials.json", true},
		{"gcp credentials", "secrets/gcp-credentials.json", true},
		{"credentials.csv", "aws-exports/credentials.csv", true},
		{"service-account", "service-account.json", true},
		{"gcp-keyfile", "keys/gcp-keyfile.json", true},
		{"aws-config", "aws-config", true},
		{"azure-credentials", "azure-credentials.xml", true},

		// SSH/SSL keys
		{"id_rsa", "id_rsa", true},
		{"id_ed25519", ".ssh/id_ed25519", true},
		{"private key", "certs/private-key.pem", true},
		{"ssl key", "ssl/server.key", true},

		// Generic secret patterns
		{"secret.json", "config/secret.json", true},
		{"secrets.yaml", "k8s/secrets.yaml", true},
		{"password file", "database-password.txt", true},
		{"token file", "api-token.json", true},

		// Vault configs
		{"vault yml", ".vault.yml", true},
		{"vault.yml", "ansible/vault.yml", true},

		// Application configs (may contain secrets)
		{"config.json", "config.json", true},
		{"config.yml", "config.yml", true},
		{"config.yaml", "backend/config.yaml", true},
		{"appsettings.json", "appsettings.json", true},
		{"database.yml", "database.yml", true},
		{"database.json", "config/database.json", true},
		{"db.config", "db.config", true},
		{"settings.json", "settings.json", true},
		{"settings.yml", "app/settings.yml", true},
		{"application.properties", "application.properties", true},

		// Container configs
		{"docker-compose.yml", "docker-compose.yml", true},
		{"docker-compose.yaml", "docker-compose.yaml", true},
		{".dockercfg", ".dockercfg", true},
		{"kubeconfig", "kubeconfig", true},

		// CI/CD configs
		{".gitlab-ci.yml", ".gitlab-ci.yml", true},
		{"buildspec.yml", "buildspec.yml", true},
		{"jenkinsfile", "jenkinsfile", true},
		{"circleci config", ".circleci/config.yml", true},
		{"github workflows", ".github/workflows/deploy.yml", true},

		// Database connection
		{".pgpass", ".pgpass", true},
		{".my.cnf", ".my.cnf", true},

		// Package manager configs
		{".npmrc", ".npmrc", true},
		{".pypirc", ".pypirc", true},
		{"settings.xml", "settings.xml", true},

		// NON-CRITICAL: Normal application files
		{"regular source", "main.go", false},
		{"documentation", "README.md", false},
		{"data file", "data.csv", false},
		{"log file", "application.log", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesCriticalPattern(tt.key)
			assert.Equal(t, tt.expected, result, "matchesCriticalPattern(%q) = %v, want %v", tt.key, result, tt.expected)
		})
	}
}

// TestMatchesCriticalPattern_CaseInsensitive verifies case-insensitive matching
func TestMatchesCriticalPattern_CaseInsensitive(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"TERRAFORM.TFSTATE", true},
		{"Credentials.JSON", true},
		{"ID_RSA", true},
		{".ENV", true},
		{"SECRET.JSON", true},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			result := matchesCriticalPattern(tt.key)
			assert.Equal(t, tt.expected, result, "matchesCriticalPattern should be case-insensitive")
		})
	}
}

// TestShouldScanBlob_CriticalMode verifies critical-only scanning behavior
func TestShouldScanBlob_CriticalMode(t *testing.T) {
	tests := []struct {
		name         string
		blobName     string
		size         int64
		lastModified time.Time
		scanMode     string
		expected     bool
	}{
		{
			name:         "critical mode: terraform.tfstate should scan",
			blobName:     "terraform.tfstate",
			size:         1024,
			lastModified: time.Now(),
			scanMode:     "critical",
			expected:     true,
		},
		{
			name:         "critical mode: .env should scan",
			blobName:     ".env",
			size:         512,
			lastModified: time.Now(),
			scanMode:     "critical",
			expected:     true,
		},
		{
			name:         "critical mode: credentials.json should scan",
			blobName:     "aws/credentials.json",
			size:         2048,
			lastModified: time.Now(),
			scanMode:     "critical",
			expected:     true,
		},
		{
			name:         "critical mode: regular file should skip",
			blobName:     "src/main.go",
			size:         1024,
			lastModified: time.Now(),
			scanMode:     "critical",
			expected:     false,
		},
		{
			name:         "critical mode: config.yaml should scan",
			blobName:     "config.yaml",
			size:         512,
			lastModified: time.Now(),
			scanMode:     "critical",
			expected:     true,
		},
		{
			name:         "all mode: regular file should scan",
			blobName:     "src/main.go",
			size:         1024,
			lastModified: time.Now(),
			scanMode:     "all",
			expected:     true,
		},
		{
			name:         "all mode: critical file should still scan",
			blobName:     "terraform.tfstate",
			size:         1024,
			lastModified: time.Now(),
			scanMode:     "all",
			expected:     true,
		},
		{
			name:         "critical mode: critical file exceeds size limit should still scan (bypass filters)",
			blobName:     "secrets/credentials.json",
			size:         200 * 1024 * 1024, // 200MB, exceeds limit
			lastModified: time.Now(),
			scanMode:     "critical",
			expected:     true,
		},
		{
			name:         "critical mode: critical file in node_modules should still scan (bypass filters)",
			blobName:     "node_modules/.env",
			size:         1024,
			lastModified: time.Now(),
			scanMode:     "critical",
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := defaultConfig()
			config.ScanMode = tt.scanMode
			scanner := &AzureBlobSecrets{config: config, logger: slog.Default()}

			result := scanner.shouldScanBlob(tt.blobName, tt.size, tt.lastModified)
			assert.Equal(t, tt.expected, result, "scanMode=%s key=%s", tt.scanMode, tt.blobName)
		})
	}
}

// TestParseStorageAccountFromKey tests extracting subscription ID and account name from resource key
func TestParseStorageAccountFromKey(t *testing.T) {
	tests := []struct {
		name              string
		key               string
		expectedSubID     string
		expectedAccount   string
		expectError       bool
	}{
		{
			name:            "valid key",
			key:             "#azureresource#sub1#/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/myaccount",
			expectedSubID:   "sub-123",
			expectedAccount: "myaccount",
			expectError:     false,
		},
		{
			name:        "invalid key - too few parts",
			key:         "#azureresource#sub1",
			expectError: true,
		},
		{
			name:        "invalid key - missing storageAccounts",
			key:         "#azureresource#sub1#/subscriptions/sub-123/resourceGroups/rg1",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subID, accountName, err := parseStorageAccountFromKey(tt.key)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedSubID, subID)
				assert.Equal(t, tt.expectedAccount, accountName)
			}
		})
	}
}

// TestDeduplication tests the account deduplication mechanism
func TestDeduplication(t *testing.T) {
	// Reset scannedAccounts before test
	ResetScannedAccounts()

	accountKey := "sub-123/myaccount"

	// First scan should not be skipped
	_, alreadyScanned := scannedAccounts.LoadOrStore(accountKey, true)
	assert.False(t, alreadyScanned, "First scan should not be skipped")

	// Second scan should be skipped
	_, alreadyScanned = scannedAccounts.LoadOrStore(accountKey, true)
	assert.True(t, alreadyScanned, "Second scan should be skipped")
}

// TestPassesStandardFilters tests the standard filtering logic
func TestPassesStandardFilters(t *testing.T) {
	tests := []struct {
		name         string
		blobName     string
		size         int64
		lastModified time.Time
		config       BlobSecretsConfig
		expected     bool
	}{
		{
			name:         "passes all filters",
			blobName:     "config.txt",
			size:         1024,
			lastModified: time.Now(),
			config:       defaultConfig(),
			expected:     true,
		},
		{
			name:         "fails size filter",
			blobName:     "large.log",
			size:         200 * 1024 * 1024,
			lastModified: time.Now(),
			config:       defaultConfig(),
			expected:     false,
		},
		{
			name:         "fails extension filter",
			blobName:     "app.exe",
			size:         1024,
			lastModified: time.Now(),
			config:       defaultConfig(),
			expected:     false,
		},
		{
			name:         "fails age filter",
			blobName:     "old.txt",
			size:         1024,
			lastModified: time.Now().Add(-48 * time.Hour),
			config: BlobSecretsConfig{
				MaxObjectSize:   100 * 1024 * 1024,
				SkipExtensions:  defaultSkipExtensions,
				ExcludePatterns: defaultExcludePatterns,
				MaxAge:          24 * time.Hour,
				ScanMode:        "all",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := &AzureBlobSecrets{config: tt.config, logger: slog.Default()}
			result := scanner.passesStandardFilters(tt.blobName, tt.size, tt.lastModified)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to create default config for tests
// Uses "all" mode for backward compatibility with existing tests
func defaultConfig() BlobSecretsConfig {
	return BlobSecretsConfig{
		MaxObjectSize:   100 * 1024 * 1024, // 100MB
		SkipExtensions:  defaultSkipExtensions,
		ExcludePatterns: defaultExcludePatterns,
		MaxAge:          0,    // No age limit by default
		ScanMode:        "all", // Use "all" for existing test compatibility
	}
}

