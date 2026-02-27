package outputters

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRiskCSVOutputter_PriorityStringConversion(t *testing.T) {
	// Create a temporary CSV file
	tmpFile, err := os.CreateTemp("", "test-risks-*.csv")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Create outputter with temp file
	outputter := NewRiskCSVOutputter().(*RiskCSVOutputter)
	outputter.outputFile = tmpFile.Name()

	// Create test risks with different priority values
	testRisks := []model.Risk{
		{
			Name:     "Test Risk 1",
			Priority: 10,
			DNS:      "example.com",
		},
		{
			Name:     "Test Risk 2",
			Priority: 65, // ASCII 'A' - would be "A" with string(int)
			DNS:      "test.com",
		},
		{
			Name:     "Test Risk 3",
			Priority: 5,
			DNS:      "another.com",
		},
	}

	// Output each risk
	for _, risk := range testRisks {
		err := outputter.Output(risk)
		require.NoError(t, err)
	}

	// Complete to write CSV
	err = outputter.Complete()
	require.NoError(t, err)

	// Read back the CSV file as text lines
	file, err := os.Open(tmpFile.Name())
	require.NoError(t, err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	require.NoError(t, scanner.Err())

	// We should have header + 3 data rows
	require.Len(t, lines, 4, "Should have header + 3 data rows")

	// Check header
	assert.Contains(t, lines[0], "Name")
	assert.Contains(t, lines[0], "Severity")

	// Verify priority values are decimal strings in CSV output
	// Lines should contain "Name,Priority,DNS,..." format
	// Line 1: "Test Risk 1,10,example.com,,"
	assert.Contains(t, lines[1], "Test Risk 1", "First risk name should be present")
	assert.Contains(t, lines[1], ",10,", "Priority 10 should be ',10,' not ',\\n,' (newline character)")
	assert.Contains(t, lines[1], "example.com", "First risk DNS should be present")

	// Line 2: "Test Risk 2,65,test.com,,"
	assert.Contains(t, lines[2], "Test Risk 2", "Second risk name should be present")
	assert.Contains(t, lines[2], ",65,", "Priority 65 should be ',65,' not ',A,' (char 'A')")
	assert.Contains(t, lines[2], "test.com", "Second risk DNS should be present")

	// Line 3: "Test Risk 3,5,another.com,,"
	assert.Contains(t, lines[3], "Test Risk 3", "Third risk name should be present")
	assert.Contains(t, lines[3], ",5,", "Priority 5 should be ',5,' not a control character")
	assert.Contains(t, lines[3], "another.com", "Third risk DNS should be present")

	// Verify the fix by checking field 2 (priority) explicitly with string splitting
	parts := strings.Split(lines[1], ",")
	require.Greater(t, len(parts), 1, "Should have at least 2 fields")
	assert.Equal(t, "10", parts[1], "Priority field should contain '10' as decimal string")

	parts = strings.Split(lines[2], ",")
	require.Greater(t, len(parts), 1, "Should have at least 2 fields")
	assert.Equal(t, "65", parts[1], "Priority field should contain '65' as decimal string")

	parts = strings.Split(lines[3], ",")
	require.Greater(t, len(parts), 1, "Should have at least 2 fields")
	assert.Equal(t, "5", parts[1], "Priority field should contain '5' as decimal string")

	// Sanity check: ensure we're not getting Unicode characters in the data rows
	// Check that priority field doesn't contain 'A' (which would be string(65))
	assert.NotContains(t, lines[2], "Test Risk 2,A,", "Should not contain 'A' from string(65) conversion")

	// The actual bug: string(10) would create a literal newline character IN the CSV field
	// We can't easily detect that with our line-by-line reading, but our explicit field checks above confirm the fix
}
