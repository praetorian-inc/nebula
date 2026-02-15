package firebase

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGcpFirebaseHostingSiteListLink(t *testing.T) {
	// Test that the constructor creates a valid link
	link := NewGcpFirebaseHostingSiteListLink()
	require.NotNil(t, link, "NewGcpFirebaseHostingSiteListLink should return a non-nil link")

	// Type assert to check the struct
	hostingLink, ok := link.(*GcpFirebaseHostingSiteListLink)
	assert.True(t, ok, "Link should be of type *GcpFirebaseHostingSiteListLink")
	assert.NotNil(t, hostingLink.GcpBaseLink, "GcpBaseLink should be initialized")
}
