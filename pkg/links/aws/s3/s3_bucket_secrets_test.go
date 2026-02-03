package s3

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
)

func TestShouldScanObject(t *testing.T) {
	tests := []struct {
		name     string
		obj      types.Object
		config   S3SecretsConfig
		expected bool
	}{
		{
			name: "small text file should scan",
			obj: types.Object{
				Size:         aws.Int64(1024), // 1KB
				Key:          aws.String("config.txt"),
				LastModified: aws.Time(time.Now()),
			},
			config:   defaultConfig(),
			expected: true,
		},
		{
			name: "large file should skip",
			obj: types.Object{
				Size:         aws.Int64(200 * 1024 * 1024), // 200MB
				Key:          aws.String("large.log"),
				LastModified: aws.Time(time.Now()),
			},
			config:   defaultConfig(),
			expected: false,
		},
		{
			name: "binary extension .exe should skip",
			obj: types.Object{
				Size:         aws.Int64(1024),
				Key:          aws.String("app.exe"),
				LastModified: aws.Time(time.Now()),
			},
			config:   defaultConfig(),
			expected: false,
		},
		{
			name: "zero size file should skip",
			obj: types.Object{
				Size:         aws.Int64(0),
				Key:          aws.String("empty.txt"),
				LastModified: aws.Time(time.Now()),
			},
			config:   defaultConfig(),
			expected: false,
		},
		{
			name: "directory marker should skip",
			obj: types.Object{
				Size:         aws.Int64(0),
				Key:          aws.String("folder/"),
				LastModified: aws.Time(time.Now()),
			},
			config:   defaultConfig(),
			expected: false,
		},
		{
			name: "node_modules path should skip",
			obj: types.Object{
				Size:         aws.Int64(1024),
				Key:          aws.String("project/node_modules/package.json"),
				LastModified: aws.Time(time.Now()),
			},
			config:   defaultConfig(),
			expected: false,
		},
		{
			name: "old file with max age configured should skip",
			obj: types.Object{
				Size:         aws.Int64(1024),
				Key:          aws.String("old.txt"),
				LastModified: aws.Time(time.Now().Add(-48 * time.Hour)),
			},
			config: S3SecretsConfig{
				MaxObjectSize:   100 * 1024 * 1024,
				SkipExtensions:  defaultSkipExtensions,
				ExcludePatterns: defaultExcludePatterns,
				MaxAge:          24 * time.Hour,
			},
			expected: false,
		},
		{
			name: "recent file with max age configured should scan",
			obj: types.Object{
				Size:         aws.Int64(1024),
				Key:          aws.String("recent.txt"),
				LastModified: aws.Time(time.Now().Add(-1 * time.Hour)),
			},
			config: S3SecretsConfig{
				MaxObjectSize:   100 * 1024 * 1024,
				SkipExtensions:  defaultSkipExtensions,
				ExcludePatterns: defaultExcludePatterns,
				MaxAge:          24 * time.Hour,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link := &AWSS3BucketSecrets{config: tt.config}
			result := link.shouldScanObject(tt.obj)
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

// Helper function to create default config for tests
func defaultConfig() S3SecretsConfig {
	return S3SecretsConfig{
		MaxObjectSize:   100 * 1024 * 1024, // 100MB
		SkipExtensions:  defaultSkipExtensions,
		ExcludePatterns: defaultExcludePatterns,
		MaxAge:          0, // No age limit by default
	}
}
