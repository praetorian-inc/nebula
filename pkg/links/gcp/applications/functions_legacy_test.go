package applications

import (
	"testing"
)

func TestParseGCSURL(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		wantBucket  string
		wantObject  string
		wantErr     bool
	}{
		{
			name:        "valid GCS URL",
			url:         "https://storage.googleapis.com/my-bucket/path/to/object.zip",
			wantBucket:  "my-bucket",
			wantObject:  "path/to/object.zip",
			wantErr:     false,
		},
		{
			name:        "valid GCS URL with nested path",
			url:         "https://storage.googleapis.com/my-bucket/foo/bar/baz/file.zip",
			wantBucket:  "my-bucket",
			wantObject:  "foo/bar/baz/file.zip",
			wantErr:     false,
		},
		{
			name:        "invalid URL - not GCS",
			url:         "https://example.com/file.zip",
			wantBucket:  "",
			wantObject:  "",
			wantErr:     true,
		},
		{
			name:        "invalid URL - missing object",
			url:         "https://storage.googleapis.com/my-bucket",
			wantBucket:  "",
			wantObject:  "",
			wantErr:     true,
		},
		{
			name:        "invalid URL - empty",
			url:         "",
			wantBucket:  "",
			wantObject:  "",
			wantErr:     true,
		},
		{
			name:        "valid gs:// URL",
			url:         "gs://my-bucket/path/to/object.zip",
			wantBucket:  "my-bucket",
			wantObject:  "path/to/object.zip",
			wantErr:     false,
		},
		{
			name:        "valid gs:// URL with nested path",
			url:         "gs://my-bucket/foo/bar/baz/file.zip",
			wantBucket:  "my-bucket",
			wantObject:  "foo/bar/baz/file.zip",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, object, err := parseGCSURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseGCSURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if bucket != tt.wantBucket {
				t.Errorf("parseGCSURL() bucket = %v, want %v", bucket, tt.wantBucket)
			}
			if object != tt.wantObject {
				t.Errorf("parseGCSURL() object = %v, want %v", object, tt.wantObject)
			}
		})
	}
}
