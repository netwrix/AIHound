package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"aihound/core"
	"aihound/remediation"
)

type claudeSessionsScanner struct{}

func init() {
	Register(&claudeSessionsScanner{})
}

func (s *claudeSessionsScanner) Name() string      { return "Claude Sessions" }
func (s *claudeSessionsScanner) Slug() string       { return "claude-sessions" }
func (s *claudeSessionsScanner) IsApplicable() bool { return true }

func (s *claudeSessionsScanner) Scan(showSecrets bool) core.ScanResult {
	plat := core.DetectPlatform()
	result := core.ScanResult{ScannerName: s.Name(), Platform: plat.String()}

	// 1. Detect running claude processes
	s.scanProcesses(&result, plat, showSecrets)

	// 2. Check session files in ~/.claude/sessions/
	s.scanSessionFiles(&result, plat, showSecrets)

	// 3. Check for live (non-expired) OAuth tokens
	s.scanLiveTokens(&result, plat, showSecrets)

	// 4. Check for tmux/screen sessions hosting claude
	s.scanTerminalMultiplexers(&result, plat, showSecrets)

	// 5. Check for Claude MCP server listening (claude mcp serve)
	s.scanMCPServe(&result, plat, showSecrets)

	return result
}

// --------------------------------------------------------------------
// 1. Running process detection
// --------------------------------------------------------------------

func (s *claudeSessionsScanner) scanProcesses(result *core.ScanResult, plat core.Platform, showSecrets bool) {
	if plat == core.PlatformWindows {
		s.scanProcessesWindows(result, showSecrets)
	} else {
		s.scanProcessesUnix(result, plat, showSecrets)
	}
}

var claudeProcessRe = regexp.MustCompile(`\bclaude\b`)

func (s *claudeSessionsScanner) scanProcessesUnix(result *core.ScanResult, plat core.Platform, showSecrets bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proc := exec.CommandContext(ctx, "ps", "aux")
	output, err := proc.Output()
	if err != nil {
		return
	}

	sshSessions := s.getSSHSessions()

	for _, line := range strings.Split(string(output), "\n") {
		if !claudeProcessRe.MatchString(line) {
			continue
		}
		if strings.Contains(line, "grep") {
			continue
		}

		parts := strings.SplitN(line, " ", 11)
		// Collapse empty fields from multiple spaces
		fields := make([]string, 0, 11)
		for _, p := range parts {
			if p != "" {
				fields = append(fields, p)
			}
		}
		// Re-split properly: ps aux has USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
		// Use Fields to handle variable whitespace
		allFields := strings.Fields(line)
		if len(allFields) < 11 {
			continue
		}
		user := allFields[0]
		pid := allFields[1]
		cmd := strings.Join(allFields[10:], " ")
		if len(cmd) > 120 {
			cmd = cmd[:120]
		}

		isSSH := s.isPIDUnderSSH(pid, sshSessions)

		if isSSH {
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:       s.Name(),
				CredentialType: "active_claude_session",
				StorageType:    core.StorageUnknown,
				Location:       fmt.Sprintf("process:%s", pid),
				Exists:         true,
				RiskLevel:      core.RiskHigh,
				Notes: []string{
					fmt.Sprintf("PID %s running as user '%s'", pid, user),
					"Session originated from SSH (remote access)",
					fmt.Sprintf("Command: %s", cmd),
				},
				Remediation: fmt.Sprintf(
					"Review whether this remote Claude session is authorized. "+
						"Terminate with `kill %s` if unauthorized.", pid),
				RemediationHint: remediation.HintRunCommand(
					[]string{fmt.Sprintf("kill %s", pid)}, "bash"),
			})
		} else {
			rem := "Active Claude Code session detected. This has full filesystem " +
				"and shell access. Ensure the machine is physically secure."
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:       s.Name(),
				CredentialType: "active_claude_session",
				StorageType:    core.StorageUnknown,
				Location:       fmt.Sprintf("process:%s", pid),
				Exists:         true,
				RiskLevel:      core.RiskMedium,
				Notes: []string{
					fmt.Sprintf("PID %s running as user '%s'", pid, user),
					"Local Claude Code session with filesystem + bash access",
					fmt.Sprintf("Command: %s", cmd),
				},
				Remediation:     rem,
				RemediationHint: remediation.HintManual(rem),
			})
		}
	}
}

func (s *claudeSessionsScanner) scanProcessesWindows(result *core.ScanResult, showSecrets bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proc := exec.CommandContext(ctx, "tasklist.exe", "/FO", "CSV")
	output, err := proc.Output()
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(output), "\n") {
		lineLower := strings.ToLower(line)
		if !strings.Contains(lineLower, "claude") {
			continue
		}

		// CSV format: "ImageName","PID","SessionName","Session#","MemUsage"
		csvParts := strings.Split(line, "\",\"")
		if len(csvParts) < 2 {
			continue
		}
		imageName := strings.Trim(csvParts[0], "\"")
		pid := strings.Trim(csvParts[1], "\"")

		if strings.Contains(strings.ToLower(imageName), "claude") {
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:       s.Name(),
				CredentialType: "active_claude_process",
				StorageType:    core.StorageUnknown,
				Location:       fmt.Sprintf("process:%s", pid),
				Exists:         true,
				RiskLevel:      core.RiskInfo,
				Notes: []string{
					fmt.Sprintf("Windows process: %s (PID %s)", imageName, pid),
					"Claude Desktop or Claude Code running on this machine",
				},
				Remediation:     "Review whether this Claude process is expected",
				RemediationHint: remediation.HintManual("Review whether this Claude process is expected"),
			})
		}
	}
}

// --------------------------------------------------------------------
// 2. Session file detection
// --------------------------------------------------------------------

func (s *claudeSessionsScanner) scanSessionFiles(result *core.ScanResult, plat core.Platform, showSecrets bool) {
	sessionsDir := filepath.Join(core.GetHome(), ".claude", "sessions")
	info, err := os.Stat(sessionsDir)
	if err != nil || !info.IsDir() {
		return
	}

	livePIDs := s.getLivePIDs()

	matches, err := filepath.Glob(filepath.Join(sessionsDir, "*.json"))
	if err != nil {
		return
	}

	for _, sessionFile := range matches {
		raw, err := os.ReadFile(sessionFile)
		if err != nil {
			continue
		}

		var data map[string]interface{}
		if err := json.Unmarshal(raw, &data); err != nil {
			continue
		}

		pidVal := ""
		if p, ok := data["pid"]; ok {
			pidVal = fmt.Sprintf("%v", p)
			// Trim ".0" from float representation
			if strings.HasSuffix(pidVal, ".0") {
				pidVal = pidVal[:len(pidVal)-2]
			}
		}
		sessionID := "unknown"
		if sid, ok := data["sessionId"]; ok {
			sessionID = fmt.Sprintf("%v", sid)
		}
		cwd := "unknown"
		if c, ok := data["cwd"]; ok {
			cwd = fmt.Sprintf("%v", c)
		}

		_, isLive := livePIDs[pidVal]

		var risk core.RiskLevel
		var notes []string

		if isLive {
			risk = core.RiskMedium
			notes = []string{
				fmt.Sprintf("Active session: PID %s is running", pidVal),
				fmt.Sprintf("Session ID: %s", sessionID),
				fmt.Sprintf("Working directory: %s", cwd),
			}
			// Parse startedAt
			if startedAt, ok := data["startedAt"]; ok {
				if ms, ok := startedAt.(float64); ok {
					startDT := time.Unix(int64(ms/1000), 0).UTC()
					notes = append(notes, fmt.Sprintf("Started: %s", startDT.Format("2006-01-02 15:04 UTC")))
				}
			}
		} else {
			risk = core.RiskInfo
			notes = []string{
				fmt.Sprintf("Stale session file: PID %s is NOT running", pidVal),
				fmt.Sprintf("Session ID: %s", sessionID),
				fmt.Sprintf("Working directory: %s", cwd),
				"Session file exists but process has exited",
			}
		}

		mtime := core.GetFileMtime(sessionFile)
		mtimeTime := core.GetFileMtimeTime(sessionFile)
		if !mtimeTime.IsZero() {
			notes = append(notes, "File last modified: "+core.DescribeStaleness(mtimeTime))
		}

		var rem string
		var hint map[string]any
		if isLive {
			rem = "Active session — ensure machine is secure"
			hint = remediation.HintManual("Active Claude session with filesystem access — ensure machine is secure")
		} else {
			rem = fmt.Sprintf("Remove stale session file: rm %s", sessionFile)
			hint = remediation.HintRunCommand([]string{fmt.Sprintf("rm %s", sessionFile)}, "bash")
		}

		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:        s.Name(),
			CredentialType:  "claude_session_file",
			StorageType:     core.PlaintextJSON,
			Location:        sessionFile,
			Exists:          true,
			RiskLevel:       risk,
			FilePermissions: core.GetFilePermissions(sessionFile),
			FileOwner:       core.GetFileOwner(sessionFile),
			FileModified:    mtime,
			Notes:           notes,
			Remediation:     rem,
			RemediationHint: hint,
		})
	}
}

// --------------------------------------------------------------------
// 3. Live (non-expired) OAuth token check
// --------------------------------------------------------------------

func (s *claudeSessionsScanner) scanLiveTokens(result *core.ScanResult, plat core.Platform, showSecrets bool) {
	credsPath := filepath.Join(core.GetHome(), ".claude", ".credentials.json")
	raw, err := os.ReadFile(credsPath)
	if err != nil {
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return
	}

	oauthRaw, ok := data["claudeAiOauth"]
	if !ok {
		return
	}
	oauth, ok := oauthRaw.(map[string]interface{})
	if !ok {
		return
	}

	accessToken, _ := oauth["accessToken"].(string)
	if accessToken == "" {
		return
	}

	expiresAtRaw, _ := oauth["expiresAt"].(float64)
	now := time.Now().UTC()
	isLive := false
	expiryStr := ""

	if expiresAtRaw > 0 {
		expDT := time.Unix(int64(expiresAtRaw/1000), 0).UTC()
		isLive = expDT.After(now)
		expiryStr = expDT.Format("2006-01-02 15:04 UTC")
	}

	if !isLive {
		return
	}

	livePIDs := s.getLivePIDs()
	claudeRunning := false
	for _, cmd := range livePIDs {
		if strings.Contains(cmd, "claude") {
			claudeRunning = true
			break
		}
	}

	risk := core.RiskMedium
	if claudeRunning {
		risk = core.RiskHigh
	}

	notes := []string{
		fmt.Sprintf("OAuth access token is live (expires: %s)", expiryStr),
	}
	if claudeRunning {
		notes = append(notes, "Claude process IS running — session is actively authenticated")
	} else {
		notes = append(notes, "No claude process found — token is live but may be unused")
	}

	rawValue := ""
	if showSecrets {
		rawValue = accessToken
	}

	result.Findings = append(result.Findings, core.CredentialFinding{
		ToolName:        s.Name(),
		CredentialType:  "live_oauth_session",
		StorageType:     core.PlaintextJSON,
		Location:        credsPath,
		Exists:          true,
		RiskLevel:       risk,
		ValuePreview:    core.MaskValue(accessToken, showSecrets),
		RawValue:        rawValue,
		FilePermissions: core.GetFilePermissions(credsPath),
		FileOwner:       core.GetFileOwner(credsPath),
		FileModified:    core.GetFileMtime(credsPath),
		Notes:           notes,
		Remediation: "Token is actively in use. To revoke, log out of Claude Code " +
			"(`claude logout`) or wait for token expiry.",
		RemediationHint: remediation.HintRunCommand([]string{"claude logout"}, "bash"),
	})
}

// --------------------------------------------------------------------
// 4. tmux / screen session detection
// --------------------------------------------------------------------

func (s *claudeSessionsScanner) scanTerminalMultiplexers(result *core.ScanResult, plat core.Platform, showSecrets bool) {
	if plat == core.PlatformWindows {
		return
	}
	s.checkTmux(result, showSecrets)
	s.checkScreen(result, showSecrets)
}

func (s *claudeSessionsScanner) checkTmux(result *core.ScanResult, showSecrets bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proc := exec.CommandContext(ctx, "tmux", "list-sessions", "-F",
		"#{session_name}:#{session_id}:#{session_attached}")
	output, err := proc.Output()
	if err != nil {
		return
	}

	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		sessionName := parts[0]
		attached := parts[2] == "1"

		// Check if any pane in this session is running claude
		paneCtx, paneCancel := context.WithTimeout(context.Background(), 5*time.Second)
		paneProc := exec.CommandContext(paneCtx, "tmux", "list-panes", "-t", sessionName,
			"-F", "#{pane_current_command}")
		paneOutput, paneErr := paneProc.Output()
		paneCancel()
		if paneErr != nil {
			continue
		}

		hasClaude := false
		for _, cmd := range strings.Split(strings.TrimSpace(string(paneOutput)), "\n") {
			if strings.Contains(strings.ToLower(cmd), "claude") {
				hasClaude = true
				break
			}
		}
		if !hasClaude {
			continue
		}

		status := "attached"
		if !attached {
			status = "detached (accessible remotely)"
		}

		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:       s.Name(),
			CredentialType: "tmux_claude_session",
			StorageType:    core.StorageUnknown,
			Location:       fmt.Sprintf("tmux:%s", sessionName),
			Exists:         true,
			RiskLevel:      core.RiskHigh,
			Notes: []string{
				fmt.Sprintf("tmux session '%s' contains a Claude process", sessionName),
				fmt.Sprintf("Session status: %s", status),
				"A detached tmux session with Claude persists after SSH disconnect",
			},
			Remediation: fmt.Sprintf("Review tmux session '%s'. "+
				"Kill with: tmux kill-session -t %s", sessionName, sessionName),
			RemediationHint: remediation.HintRunCommand(
				[]string{fmt.Sprintf("tmux kill-session -t %s", sessionName)}, "bash"),
		})
	}
}

var screenSessionRe = regexp.MustCompile(`\s+(\d+)\.(\S+)\s+\((\w+)\)`)

func (s *claudeSessionsScanner) checkScreen(result *core.ScanResult, showSecrets bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proc := exec.CommandContext(ctx, "screen", "-ls")
	output, err := proc.CombinedOutput() // screen -ls returns exit 1 when sessions exist
	if err != nil && len(output) == 0 {
		return
	}

	for _, line := range strings.Split(string(output), "\n") {
		match := screenSessionRe.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		pid := match[1]
		sessionName := match[2]
		status := match[3]

		// Check if this screen session's children include claude
		childCtx, childCancel := context.WithTimeout(context.Background(), 5*time.Second)
		psProc := exec.CommandContext(childCtx, "ps", "--ppid", pid, "-o", "comm=")
		psOutput, psErr := psProc.Output()
		childCancel()
		if psErr != nil {
			continue
		}

		hasClaude := false
		for _, cmd := range strings.Split(strings.TrimSpace(string(psOutput)), "\n") {
			if strings.Contains(strings.ToLower(cmd), "claude") {
				hasClaude = true
				break
			}
		}
		if !hasClaude {
			continue
		}

		location := fmt.Sprintf("screen:%s.%s", pid, sessionName)
		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:       s.Name(),
			CredentialType: "screen_claude_session",
			StorageType:    core.StorageUnknown,
			Location:       location,
			Exists:         true,
			RiskLevel:      core.RiskHigh,
			Notes: []string{
				fmt.Sprintf("GNU Screen session '%s' (PID %s) contains Claude", sessionName, pid),
				fmt.Sprintf("Status: %s", status),
				"A detached screen session with Claude persists after SSH disconnect",
			},
			Remediation: fmt.Sprintf("Kill with: screen -S %s.%s -X quit", pid, sessionName),
			RemediationHint: remediation.HintRunCommand(
				[]string{fmt.Sprintf("screen -S %s.%s -X quit", pid, sessionName)}, "bash"),
		})
	}
}

// --------------------------------------------------------------------
// 5. Claude MCP server exposure (claude mcp serve)
// --------------------------------------------------------------------

func (s *claudeSessionsScanner) scanMCPServe(result *core.ScanResult, plat core.Platform, showSecrets bool) {
	if plat == core.PlatformWindows || plat == core.PlatformMacOS {
		return // ss not available
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proc := exec.CommandContext(ctx, "ss", "-tlnp")
	output, err := proc.Output()
	if err != nil {
		return
	}

	portRe := regexp.MustCompile(`(?:0\.0\.0\.0|:::|\*):(\d+)`)

	for _, line := range strings.Split(string(output), "\n") {
		lineLower := strings.ToLower(line)
		if !strings.Contains(lineLower, "claude") {
			continue
		}

		// Check if bound to 0.0.0.0 or a non-loopback address
		if !strings.Contains(line, "0.0.0.0:") && !strings.Contains(line, ":::") && !strings.Contains(line, "*:") {
			continue
		}

		portMatch := portRe.FindStringSubmatch(line)
		port := "unknown"
		if portMatch != nil {
			port = portMatch[1]
		}

		portNum := 0
		if port != "unknown" {
			if n, err := strconv.Atoi(port); err == nil {
				portNum = n
			}
		}

		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:       s.Name(),
			CredentialType: "claude_mcp_server_exposed",
			StorageType:    core.StorageUnknown,
			Location:       fmt.Sprintf("0.0.0.0:%s", port),
			Exists:         true,
			RiskLevel:      core.RiskCritical,
			Notes: []string{
				fmt.Sprintf("Claude MCP server listening on 0.0.0.0:%s", port),
				"Any machine on the network can connect to this Claude instance",
				"This grants remote code execution via Claude's tools",
			},
			Remediation:     "Bind Claude MCP server to 127.0.0.1 instead of 0.0.0.0",
			RemediationHint: remediation.HintNetworkBind("claude-mcp-serve", "", portNum),
		})
	}
}

// --------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------

type sshSession struct {
	user string
	tty  string
	ip   string
}

func (s *claudeSessionsScanner) getSSHSessions() []sshSession {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proc := exec.CommandContext(ctx, "who")
	output, err := proc.Output()
	if err != nil {
		return nil
	}

	ipRe := regexp.MustCompile(`\((.+)\)`)
	var sessions []sshSession

	for _, line := range strings.Split(string(output), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		match := ipRe.FindStringSubmatch(line)
		if match != nil {
			sessions = append(sessions, sshSession{
				user: parts[0],
				tty:  parts[1],
				ip:   match[1],
			})
		}
	}
	return sessions
}

func (s *claudeSessionsScanner) isPIDUnderSSH(pid string, sshSessions []sshSession) bool {
	if len(sshSessions) == 0 {
		return false
	}

	currentPID := pid
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		proc := exec.CommandContext(ctx, "ps", "-o", "ppid=,comm=", "-p", currentPID)
		output, err := proc.Output()
		cancel()
		if err != nil {
			break
		}

		parts := strings.SplitN(strings.TrimSpace(string(output)), " ", 2)
		if len(parts) < 2 {
			break
		}
		ppid := strings.TrimSpace(parts[0])
		comm := strings.TrimSpace(parts[1])

		if comm == "sshd" {
			return true
		}
		if ppid == "0" || ppid == "1" || ppid == currentPID {
			break
		}
		currentPID = ppid
	}
	return false
}

// getLivePIDs returns a map of pid -> command name for all running processes.
func (s *claudeSessionsScanner) getLivePIDs() map[string]string {
	pids := make(map[string]string)

	if runtime.GOOS == "windows" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proc := exec.CommandContext(ctx, "tasklist.exe", "/FO", "CSV")
		output, err := proc.Output()
		if err != nil {
			return pids
		}
		for _, line := range strings.Split(string(output), "\n") {
			csvParts := strings.Split(line, "\",\"")
			if len(csvParts) >= 2 {
				name := strings.Trim(csvParts[0], "\"")
				pid := strings.Trim(csvParts[1], "\"")
				pids[pid] = name
			}
		}
		return pids
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proc := exec.CommandContext(ctx, "ps", "-eo", "pid,comm")
	output, err := proc.Output()
	if err != nil {
		return pids
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines[1:] { // skip header
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			pids[parts[0]] = parts[1]
		}
	}
	return pids
}
