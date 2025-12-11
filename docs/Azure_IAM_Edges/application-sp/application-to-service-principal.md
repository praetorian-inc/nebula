# Application To Service Principal

## Description

Applications can escalate to their corresponding Service Principals because application compromise (through credential addition) provides access to the runtime Service Principal and all its permissions.

## Edge Information

- **Attack Method**: ApplicationToServicePrincipal
- **Edge Category**: ApplicationIdentity
- **From**: Application registration
- **To**: Corresponding Service Principal

## Escalation Condition

Application compromise (credential addition) provides access to corresponding Service Principal and all its permissions.

## Technical Details

### Detection Query
```cypher
MATCH (app:Resource)-[:CONTAINS]->(sp:Resource)
WHERE app.resourceType = "Microsoft.DirectoryServices/applications"
  AND sp.resourceType = "Microsoft.DirectoryServices/servicePrincipals"
CREATE (app)-[r:CAN_ESCALATE]->(sp)
SET r.method = "ApplicationToServicePrincipal",
    r.condition = "Application compromise (credential addition) provides access to corresponding Service Principal and all its permissions",
    r.category = "ApplicationIdentity"
```

### Prerequisites
- Application must have corresponding Service Principal (linked by appId)
- CONTAINS relationship must exist between Application and Service Principal
- No additional authentication restrictions

### Attack Scenarios

1. **Credential Addition**: Add client secret or certificate to application → authenticate as SP
2. **Permission Inheritance**: Assume all permissions granted to the Service Principal
3. **Token Theft**: Steal application credentials → request SP access tokens
4. **Configuration Abuse**: Modify application configuration to weaken security
5. **Federated Identity Abuse**: Add federated credentials for token exchange

### Application vs Service Principal Roles

#### **Application (Registration)**
- **Purpose**: Configuration and credential management
- **Permissions**: Defines what the app can request
- **Security**: Client secrets, certificates, redirect URIs

#### **Service Principal (Runtime)**
- **Purpose**: Runtime security principal in the tenant
- **Permissions**: Actual granted permissions (Graph API, Azure RBAC)
- **Security**: What the application can actually do

### Attack Techniques

1. **Direct Credential Addition**:
   ```http
   POST https://graph.microsoft.com/v1.0/applications/{app-id}/addPassword
   ```

2. **Certificate Addition**:
   ```http
   POST https://graph.microsoft.com/v1.0/applications/{app-id}/addKey
   ```

3. **Federated Credential Addition**:
   ```http
   POST https://graph.microsoft.com/v1.0/applications/{app-id}/federatedIdentityCredentials
   ```

### Permission Flow

```
Application Credentials → Service Principal Token → Granted Permissions
```

1. **Application**: Stores credentials (secrets, certificates)
2. **Authentication**: Use app credentials to get SP token
3. **Authorization**: SP token contains all granted permissions
4. **Access**: Use SP permissions to access resources

### Mitigation Strategies

1. **Application Security**:
   - Use certificate authentication instead of client secrets
   - Implement short-lived credentials with rotation
   - Apply Conditional Access policies to applications

2. **Service Principal Protection**:
   - Minimize SP permissions (principle of least privilege)
   - Regular audit of SP permissions
   - Monitor SP authentication and activity

3. **Credential Management**:
   - Enable servicePrincipalLockConfiguration when available
   - Use Azure Key Vault for credential storage
   - Implement credential rotation policies

4. **Monitoring**:
   - Alert on credential additions to applications
   - Monitor unusual SP authentication patterns
   - Track permission grant events

### Detection Queries

Find applications with dangerous SP permissions:
```cypher
MATCH (app:Resource)-[:CONTAINS]->(sp:Resource),
      (sp)-[perm:HAS_GRAPH_PERMISSION]->(target:Resource)
WHERE perm.permission IN ["RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All"]
RETURN app.displayName, sp.displayName, perm.permission
```

Find applications owned by regular users:
```cypher
MATCH (user:Resource)-[:OWNS]->(app:Resource)-[:CONTAINS]->(sp:Resource),
      (sp)-[perm:HAS_PERMISSION|HAS_GRAPH_PERMISSION]->(target:Resource)
WHERE user.resourceType = "Microsoft.DirectoryServices/users"
RETURN user.displayName, app.displayName, sp.displayName, perm.permission
ORDER BY perm.permission
```

### Real-World Impact

This edge enables analysis of:
- **Application security posture**: How app compromise affects SP permissions
- **Transitive privilege risks**: App owners → app compromise → SP permissions
- **Attack surface mapping**: Complete application-to-privilege relationships

### Common Vulnerable Patterns

1. **Over-Privileged Service Principals**: SPs with excessive Graph API permissions
2. **Weak Application Security**: Apps with client secrets instead of certificates
3. **Broad Ownership**: Applications owned by many users
4. **Legacy Applications**: Old apps with accumulated permissions over time

### Related Edges

- [Application Owner Add Secret](app-owner-add-secret.md) - How application owners can add credentials
- [Service Principal Owner Add Secret](sp-owner-add-secret.md) - Direct SP credential addition
- [Application Administrator](../directory-roles/application-administrator.md) - Can add credentials to any application

## References

- [Azure Application and Service Principal Objects](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
- [Application Credential Management](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)