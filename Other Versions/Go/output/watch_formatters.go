package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"aihound/core"
	"aihound/notifications"
	"aihound/watch"
)

// ANSI codes for the watch-mode terminal sink. These match the existing
// palette in table.go and are kept separate because the event and event-type
// colors are orthogonal to the risk color.
const (
	watchReset = "\033[0m"
	watchBold  = "\033[1m"
	watchDim   = "\033[2m"
)

// riskWatchColor returns the per-risk ANSI color used by the watch sink.
// Uses the same red/yellow/orange/green/cyan palette as the Python version.
func riskWatchColor(r core.RiskLevel) string {
	switch r {
	case core.RiskCritical:
		return "\033[91m" // red
	case core.RiskHigh:
		return "\033[93m" // yellow
	case core.RiskMedium:
		return "\033[33m" // orange-ish
	case core.RiskLow:
		return "\033[92m" // green
	case core.RiskInfo:
		return "\033[36m" // cyan
	default:
		return ""
	}
}

// eventLabel returns a fixed-width, human-readable label for the event type.
func eventLabel(e watch.EventType) string {
	switch e {
	case watch.EventBaseline:
		return "BASELINE "
	case watch.EventNew:
		return "NEW      "
	case watch.EventRemoved:
		return "REMOVED  "
	case watch.EventPermissionChanged:
		return "PERM+    "
	case watch.EventContentChanged:
		return "CHANGED  "
	case watch.EventRiskEscalated:
		return "RISK+    "
	case watch.EventNetworkExposed:
		return "NETWORK  "
	default:
		return "UNKNOWN  "
	}
}

// eventColor returns the per-event-type ANSI color used by the watch sink.
func eventColor(e watch.EventType) string {
	switch e {
	case watch.EventBaseline:
		return "\033[90m" // gray
	case watch.EventNew:
		return "\033[95m" // magenta
	case watch.EventRemoved:
		return "\033[94m" // blue
	case watch.EventPermissionChanged:
		return "\033[93m" // yellow
	case watch.EventContentChanged:
		return "\033[36m" // cyan
	case watch.EventRiskEscalated:
		return "\033[91m" // red
	case watch.EventNetworkExposed:
		return "\033[91m" // red
	default:
		return ""
	}
}

// TerminalEventSink emits a colored one-line representation of each event to
// its Writer. Pair it with watch.WatchLoop.Sinks.
//
// Example line:
//
//	[10:42:17] NEW       CRITICAL  Claude Code CLI      oauth_access_token       /home/user/.claude/.credentials.json
type TerminalEventSink struct {
	Writer  io.Writer
	NoColor bool

	mu sync.Mutex
}

// color returns the given ANSI code, or empty when NoColor is true.
func (s *TerminalEventSink) color(code string) string {
	if s.NoColor {
		return ""
	}
	return code
}

// Emit writes the event to the sink's writer.
func (s *TerminalEventSink) Emit(event watch.WatchEvent) {
	if s.Writer == nil {
		s.Writer = os.Stdout
	}
	f := event.Finding
	risk := f.RiskLevel
	ts := event.Timestamp.Local().Format("15:04:05")

	label := eventLabel(event.EventType)
	evColor := s.color(eventColor(event.EventType))
	rColor := s.color(riskWatchColor(risk))
	bold := s.color(watchBold)
	dim := s.color(watchDim)
	reset := s.color(watchReset)

	riskStr := padRight(fmt.Sprintf("%s", toUpper(risk.String())), 9)

	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Fprintf(s.Writer,
		"%s[%s]%s %s%s%s %s%s%s%s %s %s %s\n",
		dim, ts, reset,
		evColor, label, reset,
		rColor, bold, riskStr, reset,
		padRight(truncate(f.ToolName, 20), 20),
		padRight(truncate(f.CredentialType, 24), 24),
		truncate(f.Location, 60),
	)

	// Sub-line: risk transition.
	if event.EventType == watch.EventRiskEscalated && event.PreviousFinding != nil {
		prev := toUpper(event.PreviousFinding.RiskLevel.String())
		now := toUpper(risk.String())
		fmt.Fprintf(s.Writer,
			"            %s\u2514\u2500 Risk escalated: %s \u2192 %s%s\n",
			dim, prev, now, reset,
		)
	}

	// Sub-line: permission transition.
	if event.EventType == watch.EventPermissionChanged && event.PreviousFinding != nil {
		oldP := event.PreviousFinding.FilePermissions
		if oldP == "" {
			oldP = "?"
		}
		newP := f.FilePermissions
		if newP == "" {
			newP = "?"
		}
		fmt.Fprintf(s.Writer,
			"            %s\u2514\u2500 Permissions: %s \u2192 %s%s\n",
			dim, oldP, newP, reset,
		)
	}
}

// toUpper is a small helper to avoid importing strings just for ToUpper.
func toUpper(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		b[i] = c
	}
	return string(b)
}

// NDJSONEventSink writes one JSON object per line to its underlying writer.
// Use NewNDJSONEventSinkFile to open an append-mode log file; that variant
// takes ownership of the file and must be Close()d.
type NDJSONEventSink struct {
	writer io.Writer
	file   *os.File // non-nil only when we own the underlying file
	mu     sync.Mutex
}

// NewNDJSONEventSink returns a sink that writes to the given writer.
// The caller retains ownership of w.
func NewNDJSONEventSink(w io.Writer) *NDJSONEventSink {
	return &NDJSONEventSink{writer: w}
}

// NewNDJSONEventSinkFile opens path in append mode and returns a sink that
// writes to it. The returned sink owns the file; callers must Close() it.
// Parent directories are created if needed. `~` is expanded to $HOME.
func NewNDJSONEventSinkFile(path string) (*NDJSONEventSink, error) {
	resolved, err := prepareOutputPath(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(resolved, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &NDJSONEventSink{writer: f, file: f}, nil
}

// Emit writes one JSON object per event, separated by a newline.
func (s *NDJSONEventSink) Emit(event watch.WatchEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writer == nil {
		return
	}
	data, err := json.Marshal(event.ToMap())
	if err != nil {
		// Shouldn't happen with our schema; drop rather than crash the loop.
		return
	}
	_, _ = s.writer.Write(data)
	_, _ = s.writer.Write([]byte{'\n'})
}

// Close closes the owned file, if any. Safe to call even when nothing was opened.
func (s *NDJSONEventSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	s.writer = nil
	return err
}

// NotificationEventSink fires OS-native desktop toasts for events at or above
// MinRisk. BASELINE events never notify (would be a toast storm on startup).
// REMOVED events notify regardless of severity.
type NotificationEventSink struct {
	MinRisk core.RiskLevel
}

// Emit sends a desktop notification for the event subject to filtering rules.
func (s *NotificationEventSink) Emit(event watch.WatchEvent) {
	if event.EventType == watch.EventBaseline {
		return
	}
	if event.EventType != watch.EventRemoved {
		if !watch.RiskAtOrAbove(event.Finding.RiskLevel, s.MinRisk) {
			return
		}
	}

	f := event.Finding
	risk := toUpper(f.RiskLevel.String())
	eventName := prettyEventName(event.EventType)
	title := fmt.Sprintf("AIHound \u2014 %s (%s)", eventName, risk)
	body := fmt.Sprintf("%s: %s\n%s", f.ToolName, f.CredentialType, truncate(f.Location, 80))

	var urgency string
	switch f.RiskLevel {
	case core.RiskCritical:
		urgency = notifications.UrgencyCritical
	case core.RiskHigh:
		urgency = notifications.UrgencyNormal
	default:
		urgency = notifications.UrgencyLow
	}

	notifications.SendNotification(title, body, urgency)
}

// prettyEventName returns the event type in Title Case, with underscores
// converted to spaces (matches Python's str.replace("_"," ").title()).
func prettyEventName(e watch.EventType) string {
	s := e.String()
	runes := []rune(s)
	capitalizeNext := true
	for i, r := range runes {
		if r == '_' {
			runes[i] = ' '
			capitalizeNext = true
			continue
		}
		if capitalizeNext && r >= 'a' && r <= 'z' {
			runes[i] = r - 32
			capitalizeNext = false
		} else {
			capitalizeNext = false
		}
	}
	return string(runes)
}
