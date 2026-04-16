package scanners

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"aihound/core"
	"aihound/remediation"
)

// aiPorts defines AI services by port.
// Ports 11434 (Ollama) and 1234 (LM Studio) are intentionally excluded —
// those scanners perform their own network binding checks.
var aiPorts = []struct {
	Port    int
	Service string
}{
	{8888, "Jupyter Notebook/Lab"},
	{7860, "Gradio / text-generation-webui"},
	{8000, "vLLM"},
	{8080, "LocalAI"},
	{3000, "Open WebUI"},
	{8188, "ComfyUI"},
}

var networkAddrRe = regexp.MustCompile(`^[0-9a-fA-F.:\[\]*]+$`)

type networkExposureScanner struct{}

func init() {
	Register(&networkExposureScanner{})
}

func (s *networkExposureScanner) Name() string      { return "AI Network Exposure" }
func (s *networkExposureScanner) Slug() string      { return "network-exposure" }

func (s *networkExposureScanner) IsApplicable() bool {
	plat := core.DetectPlatform()
	return plat == core.PlatformLinux || plat == core.PlatformWSL
}

func (s *networkExposureScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}

	cmd := exec.Command("ss", "-tlnp")
	output, err := cmd.Output()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("ss command failed: %v", err))
		return result
	}

	for _, line := range strings.Split(string(output), "\n") {
		for _, p := range aiPorts {
			s.checkLineForPort(line, p.Port, p.Service, &result)
		}
	}

	return result
}

func (s *networkExposureScanner) checkLineForPort(line string, port int, service string, result *core.ScanResult) {
	// Find all "<addr>:<port>" tokens on this line ending with our port
	re := regexp.MustCompile(fmt.Sprintf(`(\S+):%d\b`, port))
	matches := re.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return
	}

	for _, m := range matches {
		addr := m[1]

		// Strip IPv6 brackets
		cleanAddr := strings.Trim(addr, "[]")

		// Ignore loopback
		if cleanAddr == "127.0.0.1" || cleanAddr == "::1" {
			continue
		}

		// Skip PID/fd-like references
		if strings.Contains(addr, "pid=") || strings.Contains(addr, "fd=") {
			continue
		}

		// Skip non-IP characters
		if !networkAddrRe.MatchString(addr) {
			continue
		}

		var risk core.RiskLevel
		var exposureNote string
		if cleanAddr == "0.0.0.0" || cleanAddr == "::" || cleanAddr == "*" {
			risk = core.RiskCritical
			exposureNote = fmt.Sprintf("%s listening on all interfaces (%s:%d)", service, cleanAddr, port)
		} else {
			risk = core.RiskHigh
			exposureNote = fmt.Sprintf("%s listening on %s:%d (non-loopback)", service, cleanAddr, port)
		}

		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:       s.Name(),
			CredentialType: "network_exposure",
			StorageType:    core.StorageUnknown,
			Location:       fmt.Sprintf("listening on %s:%d", cleanAddr, port),
			Exists:         true,
			RiskLevel:      risk,
			ValuePreview:   fmt.Sprintf("%s:%d", cleanAddr, port),
			Remediation:    fmt.Sprintf("Bind %s to 127.0.0.1 instead of 0.0.0.0, or use an authentication proxy", service),
			RemediationHint: remediation.HintNetworkBind(service, "", port),
			Notes: []string{
				exposureNote,
				"Most AI service web UIs have no built-in authentication",
				fmt.Sprintf("Port %d detected as %s", port, service),
			},
		})
	}
}
