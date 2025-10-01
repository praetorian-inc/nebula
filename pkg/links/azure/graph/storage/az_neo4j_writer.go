package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/azure/graph/models"
)

// AZNeo4jWriter writes Azure Graph entities to Neo4j
type AZNeo4jWriter struct {
	driver    neo4j.DriverWithContext
	database  string
	nodeCount int
	mu        sync.Mutex
}

// AZNeo4jWriterLink is the Janus link wrapper
type AZNeo4jWriterLink struct {
	*chain.Base
	writer *AZNeo4jWriter
}

func NewAZNeo4jWriterLink(configs ...cfg.Config) chain.Link {
	l := &AZNeo4jWriterLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AZNeo4jWriterLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("neo4j_uri", "Neo4j connection URI").WithDefault("neo4j://localhost:7687"),
		cfg.NewParam[string]("neo4j_username", "Neo4j username").WithDefault("neo4j"),
		cfg.NewParam[string]("neo4j_password", "Neo4j password").WithDefault("neo4j"),
		cfg.NewParam[string]("neo4j_database", "Neo4j database").WithDefault("neo4j"),
	}
}

func (l *AZNeo4jWriterLink) Process(data any) error {
	uri, _ := cfg.As[string](l.Arg("neo4j_uri"))
	username, _ := cfg.As[string](l.Arg("neo4j_username"))
	password, _ := cfg.As[string](l.Arg("neo4j_password"))
	database, _ := cfg.As[string](l.Arg("neo4j_database"))

	l.Logger.Info("Connecting to Neo4j", "uri", uri, "database", database)

	// Create Neo4j driver
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		return fmt.Errorf("failed to create Neo4j driver: %w", err)
	}

	// Verify connection
	err = driver.VerifyConnectivity(l.Context())
	if err != nil {
		return fmt.Errorf("failed to connect to Neo4j: %w", err)
	}

	l.writer = &AZNeo4jWriter{
		driver:   driver,
		database: database,
	}

	// Create indexes for performance
	if err := l.writer.CreateIndexes(l.Context()); err != nil {
		l.Logger.Warn("Failed to create indexes", "error", err)
	}

	// Store writer in context for collectors
	ctx := context.WithValue(l.Context(), "neo4j_writer", l.writer)
	l.SetContext(ctx)

	// Pass writer to next link
	l.Send(l.writer)

	return nil
}

func (l *AZNeo4jWriterLink) Close() {
	if l.writer != nil && l.writer.driver != nil {
		l.writer.driver.Close(context.Background())
	}
}

// CreateIndexes creates Neo4j indexes for performance
func (w *AZNeo4jWriter) CreateIndexes(ctx context.Context) error {
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS FOR (n:AZUser) ON (n.id)",
		"CREATE INDEX IF NOT EXISTS FOR (n:AZUser) ON (n.userPrincipalName)",
		"CREATE INDEX IF NOT EXISTS FOR (n:AZGroup) ON (n.id)",
		"CREATE INDEX IF NOT EXISTS FOR (n:AZServicePrincipal) ON (n.id)",
		"CREATE INDEX IF NOT EXISTS FOR (n:AZApplication) ON (n.appId)",
		"CREATE INDEX IF NOT EXISTS FOR (n:AZRole) ON (n.id)",
		"CREATE INDEX IF NOT EXISTS FOR (n:AZRole) ON (n.roleTemplateId)",
		"CREATE INDEX IF NOT EXISTS FOR (n:AZDevice) ON (n.id)",
		"CREATE INDEX IF NOT EXISTS FOR (n:AZTenant) ON (n.id)",
	}

	session := w.driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode:   neo4j.AccessModeWrite,
		DatabaseName: w.database,
	})
	defer session.Close(ctx)

	for _, index := range indexes {
		_, err := session.Run(ctx, index, nil)
		if err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// CreateNode creates a node in Neo4j
func (w *AZNeo4jWriter) CreateNode(ctx context.Context, node any) error {
	w.mu.Lock()
	w.nodeCount++
	w.mu.Unlock()

	session := w.driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode:   neo4j.AccessModeWrite,
		DatabaseName: w.database,
	})
	defer session.Close(ctx)

	var query string
	var params map[string]any

	switch n := node.(type) {
	case *models.AZUser:
		query = `
			MERGE (u:AZUser {id: $id})
			SET u = $props
		`
		params = map[string]any{
			"id":    n.ID,
			"props": structToMap(n),
		}

	case *models.AZGroup:
		query = `
			MERGE (g:AZGroup {id: $id})
			SET g = $props
		`
		params = map[string]any{
			"id":    n.ID,
			"props": structToMap(n),
		}

	case *models.AZServicePrincipal:
		query = `
			MERGE (sp:AZServicePrincipal {id: $id})
			SET sp = $props
		`
		params = map[string]any{
			"id":    n.ID,
			"props": structToMap(n),
		}

	case *models.AZApplication:
		query = `
			MERGE (app:AZApplication {id: $id})
			SET app = $props
		`
		params = map[string]any{
			"id":    n.ID,
			"props": structToMap(n),
		}

	case *models.AZRole:
		query = `
			MERGE (r:AZRole {id: $id})
			SET r = $props
		`
		params = map[string]any{
			"id":    n.ID,
			"props": structToMap(n),
		}

	case *models.AZDevice:
		query = `
			MERGE (d:AZDevice {id: $id})
			SET d = $props
		`
		params = map[string]any{
			"id":    n.ID,
			"props": structToMap(n),
		}

	case *models.AZTenant:
		query = `
			MERGE (t:AZTenant {id: $id})
			SET t = $props
		`
		params = map[string]any{
			"id":    n.ID,
			"props": structToMap(n),
		}

	default:
		return fmt.Errorf("unknown node type: %T", node)
	}

	_, err := session.Run(ctx, query, params)
	return err
}

// CreateEdge creates an edge in Neo4j
func (w *AZNeo4jWriter) CreateEdge(ctx context.Context, fromID, toID, edgeType string, fromLabel, toLabel string) error {
	session := w.driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode:   neo4j.AccessModeWrite,
		DatabaseName: w.database,
	})
	defer session.Close(ctx)

	query := fmt.Sprintf(`
		MATCH (from:%s {id: $fromId})
		MATCH (to:%s {id: $toId})
		MERGE (from)-[r:%s]->(to)
	`, fromLabel, toLabel, edgeType)

	_, err := session.Run(ctx, query, map[string]any{
		"fromId": fromID,
		"toId":   toID,
	})
	return err
}

// GetNodeCount returns the number of nodes created
func (w *AZNeo4jWriter) GetNodeCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.nodeCount
}

// structToMap converts a struct to a map for Neo4j
func structToMap(s any) map[string]any {
	// Use JSON as intermediate format
	data, _ := json.Marshal(s)
	var result map[string]any
	json.Unmarshal(data, &result)

	// Convert complex types to JSON strings
	for k, v := range result {
		switch v.(type) {
		case map[string]any, []any:
			if jsonStr, err := json.Marshal(v); err == nil {
				result[k] = string(jsonStr)
			}
		}
	}

	return result
}