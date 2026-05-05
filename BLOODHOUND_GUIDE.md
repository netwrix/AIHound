# AIHound + BloodHound CE — Step-by-Step Walkthrough

## What This Does

AIHound scans your machine for AI credentials (API keys, OAuth tokens, MCP server secrets, etc.) and exports them as an attack path graph that BloodHound CE can visualize. You can then explore how an attacker could move from one compromised credential to sensitive data across your AI tools.

---

## Prerequisites

- Python 3.10+
- AIHound installed (this repo)
- BloodHound CE v8.0+ running (Docker recommended)
  - Default: `http://localhost:8080`

---

## Step 1: Register Custom Node Types (One Time Only)

Before BloodHound can display AI credential nodes with proper icons, you need to register AIHound's custom node types. **You only need to do this once per BloodHound instance.**

```bash
python3 aihound400/register_ai_nodes.py \
  -s http://localhost:8080 \
  -u admin \
  -p <your-bloodhound-password>
```

You should see:

```
Authenticated as admin
Registered 14 custom node kinds:
                   key  AICredential          AI API key, OAuth token, or session credential
                 cloud  AIService             AI platform or service (OpenAI, Anthropic, AWS, etc.)
                  plug  MCPServer             Model Context Protocol server instance
                  ...
Done! You can now import AIHound OpenGraph JSON files into BloodHound CE.
```

> **Tip:** If you need to re-register (e.g., after a BloodHound reset), add `--reset` to clear old kinds first.

---

## Step 2: Run the Scan and Generate the BloodHound File

Run AIHound with the `--bloodhound` flag to generate the OpenGraph JSON file:

```bash
python3 -m aihound --bloodhound aihound-bloodhound.json
```

This runs all scanners and writes the graph file. You'll see normal scan output plus:

```
BloodHound OpenGraph JSON written to: aihound-bloodhound.json
```

> **Tip:** You can combine with other flags:
> ```bash
> # Also save HTML report
> python3 -m aihound --bloodhound aihound-bloodhound.json --html-file report.html
>
> # Only scan specific tools
> python3 -m aihound --bloodhound aihound-bloodhound.json --tools claude-code ollama
> ```

---

## Step 3: Upload to BloodHound CE

1. Open BloodHound CE in your browser (default: `http://localhost:8080`)
2. Log in with your admin credentials
3. Click **"Data Collection"** in the left sidebar (upload icon)
4. Click **"File Ingest"**
5. Drag and drop `aihound-bloodhound.json` into the upload area (or click to browse)
6. Wait for the ingest to complete — you'll see a success message

---

## Step 4: Explore the Graph

### Search for Nodes

Use the **search bar** at the top of BloodHound to find specific nodes:

| Search for... | To find... |
|--------------|-----------|
| `Anthropic` | The Anthropic AI service node |
| `OpenAI` | The OpenAI service node |
| `Claude Code CLI` | The Claude Code tool node |
| `.claude.json` | Config files containing Claude credentials |
| `sk-ant-` | Anthropic API keys by prefix |
| `perplexity` | MCP server nodes |

### View Node Details

Click any node to see its properties in the right panel:

- **AICredential nodes** show: risk level, credential type, storage location, file permissions, masked value, remediation guidance
- **AIService nodes** show: service name
- **ConfigFile nodes** show: file path, permissions, owner
- **MCPServer nodes** show: server name, config path

### Trace Attack Paths

**Right-click any node** for path options:

- **"Shortest Path From Here"** → Shows how an attacker could move FROM this node to other targets
- **"Shortest Path To Here"** → Shows how an attacker could REACH this node from entry points

---

## Step 5: Run Cypher Queries

BloodHound CE has a **Cypher query bar** where you can run custom graph queries. Open the Cypher query input (look for the search/query bar — you may need to toggle to Cypher mode).

### Query 1: See Everything (Start Here)

Paste this to see all credentials and what services they authenticate to:

```cypher
MATCH (c:AICredential)-[:Authenticates]->(s:AIService)
RETURN c, s
```

This shows every credential node connected to its target service. Click on nodes to inspect them.

### Query 2: High-Risk Credentials

Show only CRITICAL and HIGH risk findings:

```cypher
MATCH (c:AICredential)-[:Authenticates]->(s:AIService)
WHERE c.risk_level IN ["critical", "high"]
RETURN c.name, c.tool, c.risk_level, c.location, s.name AS service
```

### Query 3: File Compromise Impact

Pick a config file and see what an attacker gets if they read it:

```cypher
MATCH (f:ConfigFile)-[:ContainsCredential]->(c:AICredential)-[:Authenticates]->(s:AIService)
WHERE f.path CONTAINS ".claude.json"
RETURN f, c, s
```

> **Try changing** `.claude.json` to other paths like `.env`, `credentials.json`, `.bashrc`

### Query 4: MCP Server Attack Chain

Trace the full path from AI tool → MCP server → credential → service → data:

```cypher
MATCH path = (t:AITool)-[:UsesMCPServer]->(m:MCPServer)-[:RequiresCredential]->(c:AICredential)-[:Authenticates]->(s:AIService)-[:GrantsAccessTo]->(d:DataStore)
RETURN path
```

This is the most powerful query — it shows complete attack chains through MCP server configurations.

### Query 5: Same Secret Sprawl

Find the same API key stored in multiple locations:

```cypher
MATCH (c1:AICredential)-[:SameSecret]->(c2:AICredential)
WHERE id(c1) < id(c2)
RETURN c1.name AS cred1, c1.location AS loc1,
       c2.name AS cred2, c2.location AS loc2
```

Each match means the same secret exists in two places — that's 2x the attack surface.

### Query 6: Blast Radius from One Credential

Pick any credential and see everything reachable from it (up to 4 hops):

```cypher
MATCH path = (c:AICredential)-[*1..4]->(target)
WHERE c.name CONTAINS "ANTHROPIC"
RETURN path
```

> **Try changing** `ANTHROPIC` to `OPENAI`, `PERPLEXITY`, `AWS`, etc.

### Query 7: Network Attack Surface

Find AI services exposed on the network without authentication:

```cypher
OPTIONAL MATCH path = (n:NetworkEndpoint)-[:ExposesService]->(s:AIService)-[:GrantsAccessTo]->(d:DataStore)
RETURN path
```

If this returns results, you have AI services (like Ollama) listening on all interfaces. Returns empty (null row) if no network-exposed services were found.

### Query 8: What Would Break If I Rotate a Key?

See what depends on a specific credential:

```cypher
MATCH (c:AICredential)<-[:RequiresCredential]-(m:MCPServer)<-[:UsesMCPServer]-(t:AITool)
WHERE c.credential_type CONTAINS "ANTHROPIC"
RETURN c.name AS credential, m.server_name AS mcp_server, t.name AS tool
```

### Query 9: Shell History Leaks

Find credentials leaked via command-line history:

```cypher
MATCH path = (h:ShellHistory)-[:ContainsCredential]->(c:AICredential)-[:Authenticates]->(s:AIService)
RETURN path
```

### Query 10: Most Dangerous Files

Rank files by how many credentials they contain:

```cypher
MATCH (f:ConfigFile)-[:ContainsCredential]->(c:AICredential)
RETURN f.path AS file, f.file_permissions AS perms, COUNT(c) AS credential_count
ORDER BY credential_count DESC
```

---

## Step 6: Ongoing Use

Re-scan anytime your AI tool configuration changes:

```bash
# Re-scan and update the BloodHound graph
python3 -m aihound --bloodhound aihound-bloodhound.json
```

Then upload the new file to BloodHound CE (Step 3). New nodes/edges will be merged with existing data.

---

## All Cypher Queries Reference

The full set of 20+ pre-built queries is in:

```
aihound400/cypher_queries.cy
```

Open that file in any text editor, find the query you want, and paste it into BloodHound's Cypher query bar.

---

## Understanding the Graph

### Node Types (What You'll See)

| Icon | Color | Node Type | What It Is |
|------|-------|-----------|-----------|
| Key | Red | AICredential | An API key, OAuth token, or session token |
| Cloud | Blue | AIService | An AI platform (OpenAI, Anthropic, AWS, etc.) |
| Plug | Purple | MCPServer | An MCP server configured in your AI tools |
| File | Orange | ConfigFile | A config file that contains credentials |
| Terminal | Green | EnvVariable | An environment variable holding a secret |
| Wrench | Teal | AITool | An AI tool (Claude Code, Cursor, Copilot, etc.) |
| Globe | Red | NetworkEndpoint | A network-exposed AI service |
| Database | Gold | DataStore | Accessible data (conversations, models, training data) |
| Lock | Gray | CredentialStore | OS credential store (Keychain, Credential Manager) |
| Scroll | Yellow | ShellHistory | Shell history with leaked credentials |
| Cube | Blue | DockerConfig | Docker config with registry auth |
| Window | Cyan | BrowserSession | Browser session for an AI service |
| Branch | Orange | GitCredential | Git credential for an AI platform |
| Book | Orange | JupyterInstance | Jupyter notebook server |

### Edge Types (The Arrows)

| Arrow Label | Meaning |
|-------------|---------|
| StoredIn | Credential is saved in this file/store |
| ContainsCredential | This file contains this credential |
| Authenticates | This credential grants access to this service |
| GrantsAccessTo | This service exposes this data |
| UsesMCPServer | This tool has this MCP server configured |
| RequiresCredential | This MCP server needs this credential |
| ConfiguredBy | This MCP server's config is in this file |
| ExposesService | This network endpoint exposes this service |
| SameSecret | These two credentials are the same secret |
| ReadsFrom | This tool reads secrets from this file |
| BrowserAuthTo | This browser session authenticates to this service |
| DockerRegistryAuth | This Docker config authenticates to this registry |
| GitAuthTo | This git credential authenticates to this platform |
| InheritsEnv | This MCP server consumes this environment variable |

### Reading an Attack Path

A typical attack path in the graph looks like:

```
ConfigFile (.claude.json)
    ↓ ContainsCredential
AICredential (sk-ant-...)
    ↓ Authenticates
AIService (Anthropic)
    ↓ GrantsAccessTo
DataStore (Conversation History)
```

**Read it as:** "If an attacker reads `.claude.json`, they get the Anthropic API key, which lets them access conversation history."

A more complex MCP path:

```
AITool (Claude Code CLI)
    ↓ UsesMCPServer
MCPServer (perplexity)
    ↓ RequiresCredential
AICredential (PERPLEXITY_API_KEY)
    ↓ Authenticates
AIService (Perplexity)
```

**Read it as:** "Claude Code CLI uses the perplexity MCP server, which has the Perplexity API key in its config. Compromising Claude Code's config exposes Perplexity access."

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Nodes show as generic circles | Run `register_ai_nodes.py` again (Step 1) |
| "No results" on a query | Check spelling — node properties are lowercase |
| Upload fails | Ensure BloodHound CE is v8.0+ (OpenGraph support required) |
| Can't find Cypher input | Look for a toggle between "Search" and "Cypher" mode in the query bar |
| Graph looks empty | Make sure the scan found credentials: run `python3 -m aihound` first to check |
| Registration script fails with 401 | Check your BloodHound password or use `--token-id` / `--token-key` instead |
