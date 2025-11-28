package types

// ApolloQueryResult represents a result from an Apollo analysis query
type ApolloQueryResult struct {
	Name             string         // Query name
	Severity         string         // Query severity (HIGH, MEDIUM, LOW, CRITICAL)
	Vulnerable       string         // The vulnerable entity ARN
	Description      string         // Query description
	ImpactedServices []string       // Services impacted by this finding
	Proof            map[string]any // Additional fields from query result (e.g., hops, methods, targets)
}
