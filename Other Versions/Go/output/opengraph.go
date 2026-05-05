package output

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aihound/core"
)

// ---------------------------------------------------------------------------
// OpenGraph JSON types (BloodHound CE v8.0+)
// ---------------------------------------------------------------------------

type openGraphDoc struct {
	Metadata openGraphMeta  `json:"metadata"`
	Graph    openGraphGraph `json:"graph"`
}

type openGraphMeta struct {
	SourceKind string `json:"source_kind"`
}

type openGraphGraph struct {
	Nodes []openGraphNode `json:"nodes"`
	Edges []openGraphEdge `json:"edges"`
}

type openGraphNode struct {
	ID         string            `json:"id"`
	Kinds      []string          `json:"kinds"`
	Properties map[string]any    `json:"properties"`
}

type openGraphEdge struct {
	Start      openGraphEndpoint `json:"start"`
	End        openGraphEndpoint `json:"end"`
	Kind       string            `json:"kind"`
	Properties map[string]any    `json:"properties,omitempty"`
}

type openGraphEndpoint struct {
	MatchBy string `json:"match_by"`
	Value   string `json:"value"`
}

// ---------------------------------------------------------------------------
// Service inference mappings
// ---------------------------------------------------------------------------

var toolToService = map[string]string{
	"Claude Code CLI":    "Anthropic",
	"Claude Desktop":     "Anthropic",
	"Claude Sessions":    "Anthropic",
	"OpenAI/Codex CLI":   "OpenAI",
	"ChatGPT Desktop":    "OpenAI",
	"GitHub Copilot":     "GitHub Copilot",
	"Gemini CLI / GCloud": "Google AI",
	"Hugging Face CLI":   "Hugging Face",
	"Amazon Q / AWS":     "AWS",
	"Ollama":             "Ollama",
	"LM Studio":          "LM Studio",
	"Jupyter":            "Jupyter",
}

var credTypeToService = map[string]string{
	"oauth_access_token":         "Anthropic",
	"oauth_refresh_token":        "Anthropic",
	"hf_token":                   "Hugging Face",
	"sso_access_token":           "AWS",
	"active_claude_session":      "Anthropic",
	"active_claude_process":      "Anthropic",
	"claude_session_file":        "Anthropic",
	"live_oauth_session":         "Anthropic",
	"tmux_claude_session":        "Anthropic",
	"screen_claude_session":      "Anthropic",
	"claude_mcp_server_exposed":  "Anthropic",
}

type prefixEntry struct {
	prefix  string
	service string
}

// Sorted longest-first for correct matching.
var prefixToService = []prefixEntry{
	{"sk-ant-ort", "Anthropic"},
	{"sk-ant-oat", "Anthropic"},
	{"sk-ant-", "Anthropic"},
	{"github_pat_", "GitHub"},
	{"ghp_", "GitHub"},
	{"gho_", "GitHub"},
	{"ghu_", "GitHub"},
	{"ghs_", "GitHub"},
	{"xoxb-", "Slack"},
	{"xoxp-", "Slack"},
	{"xoxa-", "Slack"},
	{"AKIA", "AWS"},
	{"AIza", "Google AI"},
	{"ya29.", "Google AI"},
	{"hf_", "Hugging Face"},
	{"sk-", "OpenAI"},
}

var envVarToService = map[string]string{
	"ANTHROPIC_API_KEY": "Anthropic", "CLAUDE_API_KEY": "Anthropic",
	"OPENAI_API_KEY": "OpenAI", "OPENAI_ORG_ID": "OpenAI",
	"GITHUB_TOKEN": "GitHub", "GITHUB_COPILOT_TOKEN": "GitHub Copilot", "GH_TOKEN": "GitHub",
	"HUGGING_FACE_HUB_TOKEN": "Hugging Face", "HF_TOKEN": "Hugging Face", "HUGGINGFACE_TOKEN": "Hugging Face",
	"AWS_ACCESS_KEY_ID": "AWS", "AWS_SECRET_ACCESS_KEY": "AWS", "AWS_SESSION_TOKEN": "AWS",
	"GOOGLE_API_KEY": "Google AI", "GEMINI_API_KEY": "Google AI", "GOOGLE_APPLICATION_CREDENTIALS": "Google AI",
	"REPLICATE_API_TOKEN": "Replicate", "TOGETHER_API_KEY": "Together AI", "GROQ_API_KEY": "Groq",
	"OLLAMA_HOST": "Ollama", "COHERE_API_KEY": "Cohere", "MISTRAL_API_KEY": "Mistral",
	"DEEPSEEK_API_KEY": "DeepSeek", "PERPLEXITY_API_KEY": "Perplexity",
	"FIREWORKS_API_KEY": "Fireworks AI", "VOYAGE_API_KEY": "Voyage AI",
	"PINECONE_API_KEY": "Pinecone", "WEAVIATE_API_KEY": "Weaviate",
	"SLACK_BOT_TOKEN": "Slack", "SLACK_TOKEN": "Slack",
}

type dataStoreInfo struct {
	Type        string
	Name        string
	Sensitivity string
}

var serviceDataStores = map[string][]dataStoreInfo{
	"Anthropic":      {{"conversation_history", "Anthropic Conversation History", "high"}, {"billing", "Anthropic Billing & Usage", "medium"}},
	"OpenAI":         {{"conversation_history", "OpenAI Conversation History", "high"}, {"fine_tuning_data", "OpenAI Fine-Tuning Data", "high"}, {"file_storage", "OpenAI File Storage", "high"}, {"billing", "OpenAI Billing & Usage", "medium"}},
	"Hugging Face":   {{"model_repos", "HuggingFace Model Repositories", "high"}, {"datasets", "HuggingFace Datasets", "high"}, {"tokens", "HuggingFace Access Tokens", "medium"}},
	"AWS":            {{"bedrock_models", "AWS Bedrock Model Access", "high"}, {"sagemaker", "AWS SageMaker Endpoints", "high"}, {"s3_data", "AWS S3 Training Data", "high"}, {"cloudwatch", "AWS CloudWatch Logs", "medium"}},
	"Google AI":      {{"conversation_history", "Gemini Conversation History", "high"}, {"vertex_models", "Vertex AI Models", "high"}, {"gcs_data", "GCS Training Data", "high"}},
	"GitHub":         {{"repositories", "GitHub Repositories", "high"}, {"actions_secrets", "GitHub Actions Secrets", "critical"}},
	"GitHub Copilot": {{"code_completions", "Copilot Code Context", "medium"}},
	"Ollama":         {{"local_models", "Ollama Local Model Weights", "high"}, {"inference", "Ollama Inference API", "medium"}},
	"LM Studio":      {{"local_models", "LM Studio Local Model Weights", "high"}, {"inference", "LM Studio Inference API", "medium"}},
	"Jupyter":        {{"notebooks", "Jupyter Notebooks & Kernels", "high"}, {"shell_access", "Jupyter Terminal Access", "critical"}},
	"Replicate":      {{"models", "Replicate Models & Predictions", "medium"}, {"billing", "Replicate Billing", "medium"}},
	"Together AI":    {{"models", "Together AI Models & Fine-Tunes", "medium"}, {"billing", "Together AI Billing", "medium"}},
	"Groq":           {{"inference", "Groq Inference API", "medium"}, {"billing", "Groq Billing", "medium"}},
	"Slack":          {{"messages", "Slack Messages & Channels", "high"}, {"files", "Slack Files & Uploads", "high"}},
	"Pinecone":       {{"vector_db", "Pinecone Vector Database", "high"}},
	"Weaviate":       {{"vector_db", "Weaviate Vector Database", "high"}},
}

var networkServiceMap = map[string]string{
	"ollama": "Ollama", "lm studio": "LM Studio", "lm-studio": "LM Studio",
	"jupyter": "Jupyter", "gradio": "Gradio", "vllm": "vLLM",
	"localai": "LocalAI", "open webui": "Open WebUI", "comfyui": "ComfyUI",
	"text-generation-inference": "TGI",
}

var shellHistoryScanners = map[string]bool{"Shell History": true, "PowerShell Logs": true}
var browserScanners = map[string]bool{"Browser Sessions": true}
var dockerScanners = map[string]bool{"Docker": true}
var gitScanners = map[string]bool{"Git Credentials": true}
var jupyterScanners = map[string]bool{"Jupyter": true}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func nodeID(prefix string, parts ...string) string {
	key := strings.Join(parts, "|")
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s-%x", prefix, h[:8])
}

func isFilePath(location string) bool {
	if strings.HasPrefix(location, "process:") || strings.HasPrefix(location, "tmux:") ||
		strings.HasPrefix(location, "screen:") || strings.HasPrefix(location, "listening on ") {
		return false
	}
	return strings.Contains(location, "/") || strings.Contains(location, "\\")
}

func inferService(f core.CredentialFinding) string {
	ct := f.CredentialType

	// 1. MCP env var
	if strings.HasPrefix(ct, "mcp_env:") {
		envName := strings.SplitN(ct, ":", 2)[1]
		if svc, ok := envVarToService[envName]; ok {
			return svc
		}
	}

	// 2. Direct credential_type match
	if svc, ok := credTypeToService[ct]; ok {
		return svc
	}

	// 3. Env var name in credential_type
	ctLower := strings.ToLower(ct)
	for envVar, svc := range envVarToService {
		if strings.Contains(ctLower, strings.ToLower(envVar)) {
			return svc
		}
	}

	// 4. Value prefix
	if f.ValuePreview != "" {
		for _, pe := range prefixToService {
			if strings.HasPrefix(f.ValuePreview, pe.prefix) {
				return pe.service
			}
		}
	}

	// 5. Tool name fallback
	if svc, ok := toolToService[f.ToolName]; ok {
		return svc
	}

	return ""
}

func inferNetworkService(f core.CredentialFinding) string {
	for _, note := range f.Notes {
		lower := strings.ToLower(note)
		for pattern, service := range networkServiceMap {
			if strings.Contains(lower, pattern) {
				return service
			}
		}
	}
	return ""
}

func extractMCPServerName(f core.CredentialFinding) string {
	for _, note := range f.Notes {
		if strings.HasPrefix(note, "MCP server: ") {
			return strings.TrimPrefix(note, "MCP server: ")
		}
	}
	return ""
}

func storageNodeKind(f core.CredentialFinding) string {
	if shellHistoryScanners[f.ToolName] {
		return "ShellHistory"
	}
	if browserScanners[f.ToolName] {
		return "BrowserSession"
	}
	if dockerScanners[f.ToolName] {
		return "DockerConfig"
	}
	if gitScanners[f.ToolName] {
		return "GitCredential"
	}
	if jupyterScanners[f.ToolName] {
		return "JupyterInstance"
	}
	if f.StorageType == core.EnvironmentVar {
		return "EnvVariable"
	}
	if f.StorageType == core.StorageKeychain || f.StorageType == core.StorageCredentialManager {
		return "CredentialStore"
	}
	return "ConfigFile"
}

func inferGitService(ct string) string {
	if strings.Contains(ct, "github.com") {
		return "GitHub"
	}
	if strings.Contains(ct, "huggingface.co") {
		return "Hugging Face"
	}
	if strings.Contains(ct, "gitlab.com") {
		return "GitLab"
	}
	if strings.Contains(ct, "bitbucket.org") {
		return "Bitbucket"
	}
	return ""
}

// normalizeLoc strips :linenum suffixes from file paths.
func normalizeLoc(loc string) string {
	if len(loc) > 2 && loc[1:3] == ":\\" {
		return loc // Windows path like C:\...
	}
	if idx := strings.LastIndex(loc, ":"); idx > 0 {
		suffix := loc[idx+1:]
		allDigits := true
		for _, c := range suffix {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && len(suffix) > 0 {
			return loc[:idx]
		}
	}
	return loc
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

type openGraphBuilder struct {
	nodes     map[string]openGraphNode
	edges     []openGraphEdge
	seenEdges map[string]bool
}

func newOpenGraphBuilder() *openGraphBuilder {
	return &openGraphBuilder{
		nodes:     make(map[string]openGraphNode),
		edges:     nil,
		seenEdges: make(map[string]bool),
	}
}

func (b *openGraphBuilder) addNode(id string, kinds []string, props map[string]any) {
	if _, exists := b.nodes[id]; exists {
		return
	}
	// Ensure all keys are lowercase and values are primitives
	safe := make(map[string]any, len(props))
	for k, v := range props {
		key := strings.ToLower(k)
		if key == "objectid" || v == nil {
			continue
		}
		safe[key] = v
	}
	b.nodes[id] = openGraphNode{ID: id, Kinds: kinds, Properties: safe}
}

func (b *openGraphBuilder) addEdge(startID, endID, kind string, props map[string]any) {
	dedupKey := startID + "|" + endID + "|" + kind
	if b.seenEdges[dedupKey] {
		return
	}
	if _, ok := b.nodes[startID]; !ok {
		return
	}
	if _, ok := b.nodes[endID]; !ok {
		return
	}
	b.seenEdges[dedupKey] = true
	edge := openGraphEdge{
		Start: openGraphEndpoint{MatchBy: "id", Value: startID},
		End:   openGraphEndpoint{MatchBy: "id", Value: endID},
		Kind:  kind,
	}
	if len(props) > 0 {
		safe := make(map[string]any, len(props))
		for k, v := range props {
			safe[strings.ToLower(k)] = v
		}
		edge.Properties = safe
	}
	b.edges = append(b.edges, edge)
}

func (b *openGraphBuilder) createDataStoreEdges(svcID, service string) {
	stores := serviceDataStores[service]
	for _, store := range stores {
		dsID := nodeID("data", service, store.Type)
		b.addNode(dsID, []string{"DataStore"}, map[string]any{
			"name": store.Name, "store_type": store.Type,
			"service": service, "sensitivity": store.Sensitivity,
		})
		b.addEdge(svcID, dsID, "GrantsAccessTo", nil)
	}
}

func (b *openGraphBuilder) processFinding(f core.CredentialFinding) {
	if !f.Exists {
		return
	}

	// --- AICredential node ---
	credID := nodeID("aicred", f.ToolName, f.CredentialType, f.Location)
	credProps := map[string]any{
		"name":            f.ToolName + ": " + f.CredentialType,
		"tool":            f.ToolName,
		"credential_type": f.CredentialType,
		"risk_level":      f.RiskLevel.String(),
		"storage_type":    f.StorageType.String(),
		"location":        f.Location,
	}
	if f.ValuePreview != "" {
		credProps["value_preview"] = f.ValuePreview
	}
	if f.FilePermissions != "" {
		credProps["file_permissions"] = f.FilePermissions
	}
	if f.Expiry != "" {
		credProps["expiry"] = f.Expiry
	}
	if f.FileModified != "" {
		credProps["file_modified"] = f.FileModified
	}
	if f.Remediation != "" {
		credProps["remediation"] = f.Remediation
	}
	if len(f.Notes) > 0 {
		credProps["notes"] = strings.Join(f.Notes, " | ")
	}
	b.addNode(credID, []string{"AICredential"}, credProps)

	// --- Non-file locations (process PIDs, tmux sessions) ---
	if !isFilePath(f.Location) {
		toolID := nodeID("tool", f.ToolName)
		b.addNode(toolID, []string{"AITool"}, map[string]any{"name": f.ToolName})
		if svc := inferService(f); svc != "" {
			svcID := nodeID("svc", svc)
			b.addNode(svcID, []string{"AIService"}, map[string]any{"name": svc})
			b.addEdge(credID, svcID, "Authenticates", nil)
			b.createDataStoreEdges(svcID, svc)
		}
		return
	}

	// --- Storage node ---
	sKind := storageNodeKind(f)
	loc := normalizeLoc(f.Location)

	storageID := nodeID("stor", sKind, loc)
	storageProps := map[string]any{
		"name":       filepath.Base(loc),
		"path":       loc,
		"kind_label": sKind,
	}
	if f.FilePermissions != "" {
		storageProps["file_permissions"] = f.FilePermissions
	}
	if f.FileOwner != "" {
		storageProps["file_owner"] = f.FileOwner
	}
	b.addNode(storageID, []string{sKind}, storageProps)

	b.addEdge(credID, storageID, "StoredIn", nil)
	b.addEdge(storageID, credID, "ContainsCredential", nil)

	// --- AITool node ---
	toolID := nodeID("tool", f.ToolName)
	b.addNode(toolID, []string{"AITool"}, map[string]any{"name": f.ToolName})
	if sKind == "ConfigFile" || sKind == "ShellHistory" || sKind == "DockerConfig" || sKind == "GitCredential" || sKind == "JupyterInstance" {
		b.addEdge(toolID, storageID, "ReadsFrom", nil)
	}

	// --- Network exposure ---
	if f.CredentialType == "network_exposure" {
		netID := nodeID("net", f.Location)
		addrPort := f.ValuePreview
		if addrPort == "" {
			addrPort = f.Location
		}
		b.addNode(netID, []string{"NetworkEndpoint"}, map[string]any{
			"name": "Network: " + addrPort, "address": addrPort, "risk_level": f.RiskLevel.String(),
		})
		if netSvc := inferNetworkService(f); netSvc != "" {
			svcID := nodeID("svc", netSvc)
			b.addNode(svcID, []string{"AIService"}, map[string]any{"name": netSvc})
			b.addEdge(netID, svcID, "ExposesService", nil)
			b.createDataStoreEdges(svcID, netSvc)
		}
		return
	}

	// --- AIService node ---
	service := inferService(f)
	if service != "" {
		svcID := nodeID("svc", service)
		b.addNode(svcID, []string{"AIService"}, map[string]any{"name": service})
		b.addEdge(credID, svcID, "Authenticates", nil)
		b.createDataStoreEdges(svcID, service)
	}

	// --- MCP Server node ---
	if mcpName := extractMCPServerName(f); mcpName != "" {
		configPath := loc
		mcpID := nodeID("mcp", mcpName, configPath)
		b.addNode(mcpID, []string{"MCPServer"}, map[string]any{
			"name": "MCP: " + mcpName, "server_name": mcpName, "config_path": configPath,
		})
		b.addEdge(toolID, mcpID, "UsesMCPServer", nil)
		b.addEdge(mcpID, credID, "RequiresCredential", nil)
		cfgID := nodeID("stor", "ConfigFile", configPath)
		if _, ok := b.nodes[cfgID]; ok {
			b.addEdge(mcpID, cfgID, "ConfiguredBy", nil)
		}
		if strings.HasPrefix(f.CredentialType, "mcp_env:") {
			envName := strings.SplitN(f.CredentialType, ":", 2)[1]
			envID := nodeID("stor", "EnvVariable", envName)
			if _, ok := b.nodes[envID]; ok {
				b.addEdge(mcpID, envID, "InheritsEnv", nil)
			}
		}
	}

	// --- Specialized edges ---
	if sKind == "BrowserSession" && service != "" {
		b.addEdge(storageID, nodeID("svc", service), "BrowserAuthTo", nil)
	}
	if sKind == "DockerConfig" && service != "" {
		b.addEdge(storageID, nodeID("svc", service), "DockerRegistryAuth", nil)
	}
	if sKind == "GitCredential" {
		if gitSvc := inferGitService(f.CredentialType); gitSvc != "" {
			svcID := nodeID("svc", gitSvc)
			b.addNode(svcID, []string{"AIService"}, map[string]any{"name": gitSvc})
			b.addEdge(storageID, svcID, "GitAuthTo", nil)
		}
	}
}

func (b *openGraphBuilder) detectSameSecrets() {
	type credInfo struct {
		id      string
		preview string
	}
	var creds []credInfo
	for id, node := range b.nodes {
		if len(node.Kinds) == 0 || node.Kinds[0] != "AICredential" {
			continue
		}
		preview, _ := node.Properties["value_preview"].(string)
		if preview == "" || preview == "***REDACTED***" || len(preview) < 10 {
			continue
		}
		creds = append(creds, credInfo{id: id, preview: preview})
	}

	// Sort for deterministic output
	sort.Slice(creds, func(i, j int) bool { return creds[i].id < creds[j].id })

	// Bucket by preview
	buckets := make(map[string][]string)
	for _, c := range creds {
		buckets[c.preview] = append(buckets[c.preview], c.id)
	}

	for _, ids := range buckets {
		if len(ids) < 2 {
			continue
		}
		for i := 0; i < len(ids); i++ {
			for j := i + 1; j < len(ids); j++ {
				props := map[string]any{"confidence": "probable"}
				b.addEdge(ids[i], ids[j], "SameSecret", props)
				b.addEdge(ids[j], ids[i], "SameSecret", props)
			}
		}
	}
}

func (b *openGraphBuilder) build(results []core.ScanResult) openGraphDoc {
	for _, result := range results {
		for _, finding := range result.Findings {
			b.processFinding(finding)
		}
	}
	b.detectSameSecrets()

	nodes := make([]openGraphNode, 0, len(b.nodes))
	for _, n := range b.nodes {
		nodes = append(nodes, n)
	}
	// Sort nodes by ID for deterministic output
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	return openGraphDoc{
		Metadata: openGraphMeta{SourceKind: "AIHound"},
		Graph:    openGraphGraph{Nodes: nodes, Edges: b.edges},
	}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// WriteOpenGraph writes BloodHound CE OpenGraph JSON to a file.
func WriteOpenGraph(path string, results []core.ScanResult) error {
	builder := newOpenGraphBuilder()
	doc := builder.build(results)

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal opengraph: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create opengraph file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write opengraph: %w", err)
	}
	return nil
}
