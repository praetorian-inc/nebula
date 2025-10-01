package storage

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
)

// AZNeo4jReaderLink reads Azure Graph entities from Neo4j
type AZNeo4jReaderLink struct {
	*chain.Base
	driver   neo4j.DriverWithContext
	database string
}

func NewAZNeo4jReaderLink(configs ...cfg.Config) chain.Link {
	l := &AZNeo4jReaderLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AZNeo4jReaderLink) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("neo4j_uri", "Neo4j connection URI").WithDefault("neo4j://localhost:7687"),
		cfg.NewParam[string]("neo4j_username", "Neo4j username").WithDefault("neo4j"),
		cfg.NewParam[string]("neo4j_password", "Neo4j password").WithDefault("neo4j"),
		cfg.NewParam[string]("neo4j_database", "Neo4j database").WithDefault("neo4j"),
	}
}

func (l *AZNeo4jReaderLink) Process(data any) error {
	uri, _ := cfg.As[string](l.Arg("neo4j_uri"))
	username, _ := cfg.As[string](l.Arg("neo4j_username"))
	password, _ := cfg.As[string](l.Arg("neo4j_password"))
	l.database, _ = cfg.As[string](l.Arg("neo4j_database"))

	l.Logger.Info("Connecting to Neo4j for reading", "uri", uri, "database", l.database)

	// Create Neo4j driver
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		return fmt.Errorf("failed to create Neo4j driver: %w", err)
	}
	l.driver = driver

	// Verify connection
	err = driver.VerifyConnectivity(l.Context())
	if err != nil {
		return fmt.Errorf("failed to connect to Neo4j: %w", err)
	}

	// Get node data for edge creation
	nodeData, err := l.getNodeData(l.Context())
	if err != nil {
		return fmt.Errorf("failed to get node data: %w", err)
	}

	// Pass data to next link
	l.Send(nodeData)

	return nil
}

func (l *AZNeo4jReaderLink) getNodeData(ctx context.Context) (*NodeData, error) {
	session := l.driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode:   neo4j.AccessModeRead,
		DatabaseName: l.database,
	})
	defer session.Close(ctx)

	data := &NodeData{
		Users:             make(map[string]map[string]any),
		Groups:            make(map[string]map[string]any),
		ServicePrincipals: make(map[string]map[string]any),
		Applications:      make(map[string]map[string]any),
		Roles:             make(map[string]map[string]any),
	}

	// Read users with their relationship data
	userQuery := `
		MATCH (u:AZUser)
		RETURN u.id as id, u.memberOfGroups as groups, u.assignedRoles as roles,
		       u.eligibleRoles as eligibleRoles, u.ownedApplications as apps
	`
	result, err := session.Run(ctx, userQuery, nil)
	if err != nil {
		return nil, err
	}

	for result.Next(ctx) {
		record := result.Record()
		id, _ := record.Get("id")
		groups, _ := record.Get("groups")
		roles, _ := record.Get("roles")
		eligibleRoles, _ := record.Get("eligibleRoles")
		apps, _ := record.Get("apps")

		data.Users[id.(string)] = map[string]any{
			"memberOfGroups":    groups,
			"assignedRoles":     roles,
			"eligibleRoles":     eligibleRoles,
			"ownedApplications": apps,
		}
	}

	// Read groups with their relationship data
	groupQuery := `
		MATCH (g:AZGroup)
		RETURN g.id as id, g.owners as owners, g.members as members, g.assignedRoles as roles
	`
	result, err = session.Run(ctx, groupQuery, nil)
	if err != nil {
		return nil, err
	}

	for result.Next(ctx) {
		record := result.Record()
		id, _ := record.Get("id")
		owners, _ := record.Get("owners")
		members, _ := record.Get("members")
		roles, _ := record.Get("roles")

		data.Groups[id.(string)] = map[string]any{
			"owners":       owners,
			"members":      members,
			"assignedRoles": roles,
		}
	}

	// Similar queries for other entity types...

	return data, nil
}

func (l *AZNeo4jReaderLink) Close() {
	if l.driver != nil {
		l.driver.Close(context.Background())
	}
}

// NodeData contains all node relationship data for edge creation
type NodeData struct {
	Users             map[string]map[string]any
	Groups            map[string]map[string]any
	ServicePrincipals map[string]map[string]any
	Applications      map[string]map[string]any
	Roles             map[string]map[string]any
}