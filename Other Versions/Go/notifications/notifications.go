// Package notifications sends cross-platform OS-native desktop notifications.
//
// Dispatches to the right backend based on detected platform:
//   - Linux / WSL: `notify-send` (from libnotify)
//   - macOS:       `osascript`
//   - Windows:     PowerShell using the built-in Windows.UI.Notifications APIs
//
// All backends shell out via os/exec — no external Go dependencies.
// If the OS backend is unavailable (e.g., no notify-send installed), a warning
// is logged on first use and all subsequent calls return false without error.
package notifications

import (
	"context"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"aihound/core"
)

// Urgency levels. These are Linux notify-send values; other backends map them
// as best they can.
const (
	UrgencyLow      = "low"
	UrgencyNormal   = "normal"
	UrgencyCritical = "critical"
)

var (
	capabilityOnce      sync.Once
	capabilityAvailable bool

	// Logger receives warnings about unavailable backends. Users who want to
	// silence logs can assign a discard logger.
	Logger = log.Default()
)

// checkCapability tests whether the current platform can send notifications.
// Cached after first call.
func checkCapability() bool {
	capabilityOnce.Do(func() {
		plat := core.DetectPlatform()
		switch plat {
		case core.PlatformLinux, core.PlatformWSL:
			if _, err := exec.LookPath("notify-send"); err == nil {
				capabilityAvailable = true
			} else {
				Logger.Print("desktop notifications unavailable: `notify-send` not found. " +
					"Install libnotify-bin (apt) / libnotify (dnf) / equivalent to enable.")
			}
		case core.PlatformMacOS:
			if _, err := exec.LookPath("osascript"); err == nil {
				capabilityAvailable = true
			} else {
				Logger.Print("desktop notifications unavailable: `osascript` not found.")
			}
		case core.PlatformWindows:
			if _, err := exec.LookPath("powershell.exe"); err == nil {
				capabilityAvailable = true
			} else if _, err := exec.LookPath("powershell"); err == nil {
				capabilityAvailable = true
			} else {
				Logger.Print("desktop notifications unavailable: PowerShell not found.")
			}
		default:
			capabilityAvailable = false
		}
	})
	return capabilityAvailable
}

// SendNotification sends a desktop notification. Returns true on success.
//
// Non-fatal: if the backend is unavailable or the command fails, returns false
// without panicking. Callers may ignore the return value.
func SendNotification(title, body, urgency string) bool {
	if !checkCapability() {
		return false
	}

	defer func() {
		// Defensive: never propagate a panic out of the notification path.
		_ = recover()
	}()

	plat := core.DetectPlatform()
	switch plat {
	case core.PlatformLinux, core.PlatformWSL:
		return notifyLinux(title, body, urgency)
	case core.PlatformMacOS:
		return notifyMacOS(title, body, urgency)
	case core.PlatformWindows:
		return notifyWindows(title, body, urgency)
	}
	return false
}

// runWithTimeout runs a command with a hard timeout and returns whether it
// succeeded. stderr is captured and logged at debug on failure.
func runWithTimeout(timeout time.Duration, name string, args ...string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		Logger.Printf("notification backend %s failed: %v (%s)", name, err, strings.TrimSpace(string(out)))
		return false
	}
	return true
}

func notifyLinux(title, body, urgency string) bool {
	if urgency == "" {
		urgency = UrgencyNormal
	}
	return runWithTimeout(
		5*time.Second,
		"notify-send",
		"--urgency="+urgency,
		"--app-name=AIHound",
		title,
		body,
	)
}

// applescriptSafe escapes a string for safe inclusion in AppleScript by
// splitting on double-quotes and rejoining with the AppleScript `quote` constant.
func applescriptSafe(s string) string {
	parts := strings.Split(s, `"`)
	quoted := make([]string, len(parts))
	for i, p := range parts {
		quoted[i] = `"` + p + `"`
	}
	return strings.Join(quoted, ` & quote & `)
}

func notifyMacOS(title, body, urgency string) bool {
	safeTitle := applescriptSafe(title)
	safeBody := applescriptSafe(body)
	script := `display notification ` + safeBody + ` with title "AIHound" subtitle ` + safeTitle
	if urgency == UrgencyCritical {
		script += ` sound name "Basso"`
	}
	return runWithTimeout(5*time.Second, "osascript", "-e", script)
}

// xmlEscape escapes characters that are special in XML content.
func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func notifyWindows(title, body, urgency string) bool {
	_ = urgency // Windows toast XML here doesn't plumb urgency; retained for API symmetry.

	// XML-escape title and body for safe insertion into the toast template.
	safeTitle := xmlEscape(title)
	safeBody := xmlEscape(body)

	// Build the PowerShell script using a single-quoted here-string (@'...'@)
	// which is non-expanding, then use -replace to inject the escaped values.
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	b.WriteString("[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]\n")
	b.WriteString("$template = @'\n")
	b.WriteString("<toast>\n")
	b.WriteString("  <visual>\n")
	b.WriteString("    <binding template=\"ToastGeneric\">\n")
	b.WriteString("      <text>TITLE_PLACEHOLDER</text>\n")
	b.WriteString("      <text>BODY_PLACEHOLDER</text>\n")
	b.WriteString("    </binding>\n")
	b.WriteString("  </visual>\n")
	b.WriteString("</toast>\n")
	b.WriteString("'@\n")
	// Use PowerShell -replace to substitute placeholders with the escaped values.
	// Single-quote the replacement strings and double any embedded single quotes.
	psSafeTitle := strings.ReplaceAll(safeTitle, "'", "''")
	psSafeBody := strings.ReplaceAll(safeBody, "'", "''")
	b.WriteString("$template = $template -replace 'TITLE_PLACEHOLDER', '" + psSafeTitle + "'\n")
	b.WriteString("$template = $template -replace 'BODY_PLACEHOLDER', '" + psSafeBody + "'\n")
	b.WriteString("$xml = [Windows.Data.Xml.Dom.XmlDocument]::new()\n")
	b.WriteString("$xml.LoadXml($template)\n")
	b.WriteString("$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)\n")
	b.WriteString("$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('AIHound')\n")
	b.WriteString("$notifier.Show($toast)\n")
	script := b.String()

	exeName := "powershell.exe"
	if _, err := exec.LookPath(exeName); err != nil {
		if _, err := exec.LookPath("powershell"); err == nil {
			exeName = "powershell"
		}
	}

	return runWithTimeout(
		10*time.Second,
		exeName,
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		script,
	)
}
