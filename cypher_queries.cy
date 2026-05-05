// ============================================================================
// AIHound 4.0 — Cypher Queries for BloodHound CE
// ============================================================================
// Import your AIHound OpenGraph JSON via Data Collection > File Ingest,
// then paste these queries in BloodHound's Cypher query bar.
//
// IMPORTANT: BloodHound CE's graph view needs "RETURN path" to render
// nodes and edges visually. Queries that RETURN columns (tables) will
// show "no data found" in the graph view — switch to the table/list
// toggle to see those results, or use the path-based versions below.
//
// Each section has a GRAPH version (visual) and optionally a TABLE
// version (detailed columns). Start with the GRAPH versions.
// ============================================================================


// ---------------------------------------------------------------------------
// 1. FULL GRAPH — "Show me everything" (START HERE)
// ---------------------------------------------------------------------------

// All AIHound nodes and edges — best for screenshots
MATCH path = (a:AIHound)-[r]->(b:AIHound)
RETURN path


// ---------------------------------------------------------------------------
// 2. BLAST RADIUS — "If a critical credential leaks, what's exposed?"
// ---------------------------------------------------------------------------

// Graph: all nodes reachable from critical credentials (up to 4 hops)
MATCH path = (c:AICredential)-[*1..4]->(target)
WHERE c.risk_level = "critical"
RETURN path

// Graph: blast radius from a specific file
MATCH path = (f:ConfigFile)-[:ContainsCredential]->(c:AICredential)-[*1..3]->(target)
WHERE f.path CONTAINS ".credentials.json"
RETURN path


// ---------------------------------------------------------------------------
// 3. CREDENTIAL → SERVICE → DATA — "What services and data are at risk?"
// ---------------------------------------------------------------------------

// Graph: full attack chain from credentials through services to data stores
MATCH path = (c:AICredential)-[:Authenticates]->(s:AIService)-[:GrantsAccessTo]->(d:DataStore)
RETURN path

// Graph: critical and high risk credentials with their services
MATCH path = (c:AICredential)-[:Authenticates]->(s:AIService)
WHERE c.risk_level = "critical" OR c.risk_level = "high"
RETURN path

// Graph: ALL credentials and their services
MATCH path = (c:AICredential)-[:Authenticates]->(s:AIService)
RETURN path


// ---------------------------------------------------------------------------
// 4. FILE COMPROMISE — "What if an attacker reads this config file?"
// ---------------------------------------------------------------------------

// Graph: .credentials.json contents → services
MATCH path = (f:ConfigFile)-[:ContainsCredential]->(c:AICredential)-[:Authenticates]->(s:AIService)
WHERE f.path CONTAINS ".credentials.json"
RETURN path

// Graph: .claude.json contents → services
MATCH path = (f:ConfigFile)-[:ContainsCredential]->(c:AICredential)-[:Authenticates]->(s:AIService)
WHERE f.path CONTAINS ".claude.json"
RETURN path

// Graph: tool → file → credential → service (full read chain)
MATCH path = (t:AITool)-[:ReadsFrom]->(f:ConfigFile)-[:ContainsCredential]->(c:AICredential)-[:Authenticates]->(s:AIService)
RETURN path


// ---------------------------------------------------------------------------
// 5. OVERLY PERMISSIVE FILES — "World-readable credentials"
// ---------------------------------------------------------------------------

// Graph: critical credentials and the files they're stored in
MATCH path = (c:AICredential)-[:StoredIn]->(f:ConfigFile)
WHERE c.risk_level = "critical"
RETURN path

// Graph: credentials with non-0600 permissions and their files
MATCH path = (c:AICredential)-[:StoredIn]->(f:ConfigFile)
WHERE c.file_permissions IS NOT NULL AND NOT c.file_permissions = "0600"
RETURN path


// ---------------------------------------------------------------------------
// 6. MCP SERVER ATTACK CHAINS — "Tool → MCP → Credential → Service"
// ---------------------------------------------------------------------------

// Graph: MCP server chain (tool → MCP server → credential it needs)
MATCH path = (t:AITool)-[:UsesMCPServer]->(m:MCPServer)-[:RequiresCredential]->(c:AICredential)
RETURN path

// Graph: extended MCP chain through to services
MATCH path = (t:AITool)-[:UsesMCPServer]->(m:MCPServer)-[:RequiresCredential]->(c:AICredential)-[:Authenticates]->(s:AIService)
RETURN path


// ---------------------------------------------------------------------------
// 7. SAME SECRET SPRAWL — "Same key in multiple places"
// ---------------------------------------------------------------------------

// Graph: credentials linked by SameSecret edges
MATCH path = (c1:AICredential)-[:SameSecret]->(c2:AICredential)
RETURN path

// Graph: same secret with their storage locations
MATCH path1 = (c1:AICredential)-[:SameSecret]->(c2:AICredential),
      path2 = (c1)-[:StoredIn]->(f1:ConfigFile),
      path3 = (c2)-[:StoredIn]->(f2:ConfigFile)
RETURN path1, path2, path3


// ---------------------------------------------------------------------------
// 8. CREDENTIAL ROTATION — "What breaks if I rotate this key?"
// ---------------------------------------------------------------------------

// Graph: PERPLEXITY key dependencies (tool → MCP server → credential)
MATCH path = (t:AITool)-[:UsesMCPServer]->(m:MCPServer)-[:RequiresCredential]->(c:AICredential)
WHERE c.credential_type CONTAINS "PERPLEXITY"
RETURN path

// Graph: all MCP server credential dependencies
MATCH path = (m:MCPServer)-[:RequiresCredential]->(c:AICredential)
RETURN path


// ---------------------------------------------------------------------------
// 9. CROSS-TOOL — "Multiple tools accessing the same service"
// ---------------------------------------------------------------------------

// Graph: different tools authenticating to the same service
MATCH path1 = (c1:AICredential)-[:Authenticates]->(s:AIService),
      path2 = (c2:AICredential)-[:Authenticates]->(s)
WHERE c1.tool <> c2.tool
RETURN path1, path2


// ---------------------------------------------------------------------------
// 10. DOCKER CREDENTIALS
// ---------------------------------------------------------------------------

// Graph: Docker configs and their contents
MATCH path = (d:DockerConfig)-[:ContainsCredential]->(c:AICredential)
RETURN path


// ---------------------------------------------------------------------------
// 11. NETWORK ATTACK SURFACE — "Unauthenticated AI services on the network"
// ---------------------------------------------------------------------------
// NOTE: Only returns results if your scan found exposed AI services
// (Ollama, LM Studio, Jupyter on 0.0.0.0). Uses OPTIONAL MATCH to
// avoid errors when no NetworkEndpoint nodes exist.

OPTIONAL MATCH path = (n:NetworkEndpoint)-[:ExposesService]->(s:AIService)
RETURN path


// ---------------------------------------------------------------------------
// 12. SHELL HISTORY / GIT CREDENTIALS
// ---------------------------------------------------------------------------
// NOTE: Only returns results if those credential types were found in scan.

OPTIONAL MATCH path = (h:ShellHistory)-[:ContainsCredential]->(c:AICredential)-[:Authenticates]->(s:AIService)
RETURN path

OPTIONAL MATCH path = (g:GitCredential)-[:ContainsCredential]->(c:AICredential)
RETURN path


// ============================================================================
// TABLE QUERIES — Use BloodHound's "table" view toggle for these
// ============================================================================
// These return columns (not paths) for detailed analysis. If the graph view
// shows "no data found", switch to the table/list view.

// Most dangerous files ranked by credential count
MATCH (f:ConfigFile)-[:ContainsCredential]->(c:AICredential)
RETURN f.path AS file, f.file_permissions AS permissions, COUNT(c) AS credential_count
ORDER BY credential_count DESC

// Risk distribution
MATCH (c:AICredential)
RETURN c.risk_level AS risk, COUNT(c) AS count
ORDER BY count DESC

// Services by credential exposure
MATCH (c:AICredential)-[:Authenticates]->(s:AIService)
RETURN s.name AS service, COUNT(c) AS credentials,
       COLLECT(DISTINCT c.risk_level) AS risk_levels
ORDER BY credentials DESC

// Node type counts
MATCH (n:AIHound)
RETURN n.primarykind AS node_type, COUNT(n) AS count
ORDER BY count DESC

// All critical credentials with remediation
MATCH (c:AICredential)
WHERE c.risk_level = "critical"
RETURN c.name AS credential, c.tool AS tool, c.location AS location,
       c.file_permissions AS permissions, c.remediation AS fix

// Overly permissive files (detailed)
MATCH (f:ConfigFile)-[:ContainsCredential]->(c:AICredential)
WHERE c.file_permissions IS NOT NULL AND NOT c.file_permissions = "0600"
RETURN f.path AS file, c.name AS credential,
       c.file_permissions AS permissions, c.risk_level AS risk
ORDER BY c.risk_level

// Credentials with expiry dates
MATCH (c:AICredential)
WHERE c.expiry IS NOT NULL
RETURN c.name AS credential, c.tool AS tool, c.expiry AS expires
