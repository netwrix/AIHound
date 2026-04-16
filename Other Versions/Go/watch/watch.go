// Package watch implements continuous scanning with event-based alerting.
//
// Re-runs all registered scanners on a configurable interval, diffs findings
// against the previous snapshot, and emits events when credentials appear,
// disappear, change, or become more dangerous.
//
// Target audience: individual developers who want ongoing hygiene monitoring.
package watch

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"aihound/core"
)

// EventType enumerates the different kinds of watch events.
type EventType int

const (
	// EventBaseline is emitted once per finding on the first scan cycle.
	EventBaseline EventType = iota
	// EventNew is emitted when a credential appears since the last scan.
	EventNew
	// EventRemoved is emitted when a credential disappears since the last scan.
	EventRemoved
	// EventPermissionChanged is emitted when file permissions on a finding change.
	EventPermissionChanged
	// EventContentChanged is emitted when the finding's mtime or value preview changes.
	EventContentChanged
	// EventRiskEscalated is emitted when a finding's risk level has increased.
	EventRiskEscalated
	// EventNetworkExposed is emitted when a network-scanner finding appears at CRITICAL risk.
	EventNetworkExposed
)

// String returns the lowercase-underscore name of the event type, matching
// the Python implementation's values for cross-language compatibility.
func (e EventType) String() string {
	switch e {
	case EventBaseline:
		return "baseline"
	case EventNew:
		return "new"
	case EventRemoved:
		return "removed"
	case EventPermissionChanged:
		return "permission_changed"
	case EventContentChanged:
		return "content_changed"
	case EventRiskEscalated:
		return "risk_escalated"
	case EventNetworkExposed:
		return "network_exposed"
	default:
		return fmt.Sprintf("EventType(%d)", int(e))
	}
}

// WatchEvent describes one change detected by the watch loop.
type WatchEvent struct {
	EventType       EventType
	Timestamp       time.Time
	Finding         core.CredentialFinding
	// PreviousFinding is populated only for permission/content/risk-escalation events.
	PreviousFinding *core.CredentialFinding
}

// ToMap returns a serializable representation of the event suitable for JSON
// output. Mirrors the Python WatchEvent.to_dict() schema.
func (e WatchEvent) ToMap() map[string]any {
	out := map[string]any{
		"event_type": e.EventType.String(),
		"timestamp":  e.Timestamp.UTC().Format(time.RFC3339),
		"finding":    findingToMap(e.Finding),
	}
	if e.PreviousFinding != nil {
		out["previous_finding"] = findingToMap(*e.PreviousFinding)
	}
	return out
}

// findingToMap produces the same JSON-friendly representation used by
// output.JSONFinding. Kept internal so the watch package does not depend on
// the output package.
func findingToMap(f core.CredentialFinding) map[string]any {
	m := map[string]any{
		"tool_name":       f.ToolName,
		"credential_type": f.CredentialType,
		"storage_type":    f.StorageType.String(),
		"location":        f.Location,
		"exists":          f.Exists,
		"risk_level":      f.RiskLevel.String(),
	}
	if f.ValuePreview != "" {
		m["value_preview"] = f.ValuePreview
	}
	if f.FilePermissions != "" {
		m["file_permissions"] = f.FilePermissions
	}
	if f.FileOwner != "" {
		m["file_owner"] = f.FileOwner
	}
	if f.Expiry != "" {
		m["expiry"] = f.Expiry
	}
	if f.FileModified != "" {
		m["file_modified"] = f.FileModified
	}
	if f.Remediation != "" {
		m["remediation"] = f.Remediation
	}
	if len(f.Notes) > 0 {
		m["notes"] = f.Notes
	}
	return m
}

// FindingKey is a stable dedup key for a finding.
// Uses (tool_name, credential_type, location). For most scanners `location`
// is a file path; for the powershell scanner it includes a ":line_number"
// suffix which correctly identifies distinct credentials in the same history
// file.
type FindingKey struct {
	ToolName       string
	CredentialType string
	Location       string
}

// String returns "tool|type|location" for use in log messages.
func (k FindingKey) String() string {
	return k.ToolName + "|" + k.CredentialType + "|" + k.Location
}

// FindingKeyOf returns the stable dedup key for a finding.
func FindingKeyOf(f core.CredentialFinding) FindingKey {
	return FindingKey{
		ToolName:       f.ToolName,
		CredentialType: f.CredentialType,
		Location:       f.Location,
	}
}

// networkScanners holds the scanner names whose NEW events get reclassified
// as NETWORK_EXPOSED when risk is CRITICAL.
var networkScanners = map[string]bool{
	"Ollama":              true,
	"LM Studio":           true,
	"AI Network Exposure": true,
}

// riskOrder maps risk levels to an ordinal for comparison (highest is worst).
func riskOrder(r core.RiskLevel) int {
	switch r {
	case core.RiskInfo:
		return 0
	case core.RiskLow:
		return 1
	case core.RiskMedium:
		return 2
	case core.RiskHigh:
		return 3
	case core.RiskCritical:
		return 4
	default:
		return 0
	}
}

// RiskAtOrAbove reports whether findingRisk is at least as severe as minRisk.
func RiskAtOrAbove(findingRisk, minRisk core.RiskLevel) bool {
	return riskOrder(findingRisk) >= riskOrder(minRisk)
}

// FlattenToMap flattens a list of ScanResults into a map keyed by FindingKey.
// If two scanners produce findings with the same key, the later one wins
// (matches Python dict-insert semantics).
func FlattenToMap(results []core.ScanResult) map[FindingKey]core.CredentialFinding {
	out := make(map[FindingKey]core.CredentialFinding)
	for _, r := range results {
		for _, f := range r.Findings {
			out[FindingKeyOf(f)] = f
		}
	}
	return out
}

// DiffFindings returns the ordered list of WatchEvents describing the delta
// from old to new. Mirrors aihound/watch.py:diff_findings.
func DiffFindings(
	old, newMap map[FindingKey]core.CredentialFinding,
	now time.Time,
) []WatchEvent {
	var events []WatchEvent

	// NEW findings: in new but not in old.
	for key, finding := range newMap {
		if _, ok := old[key]; ok {
			continue
		}
		f := finding
		if networkScanners[f.ToolName] && f.RiskLevel == core.RiskCritical {
			events = append(events, WatchEvent{
				EventType: EventNetworkExposed,
				Timestamp: now,
				Finding:   f,
			})
		} else {
			events = append(events, WatchEvent{
				EventType: EventNew,
				Timestamp: now,
				Finding:   f,
			})
		}
	}

	// REMOVED findings: in old but not in new.
	for key, finding := range old {
		if _, ok := newMap[key]; ok {
			continue
		}
		events = append(events, WatchEvent{
			EventType: EventRemoved,
			Timestamp: now,
			Finding:   finding,
		})
	}

	// CHANGED findings: in both old and new.
	for key, newF := range newMap {
		oldF, ok := old[key]
		if !ok {
			continue
		}

		permChanged := oldF.FilePermissions != newF.FilePermissions
		contentChanged := oldF.FileModified != newF.FileModified ||
			oldF.ValuePreview != newF.ValuePreview
		riskEscalated := riskOrder(newF.RiskLevel) > riskOrder(oldF.RiskLevel)

		newCopy := newF
		oldCopy := oldF

		if permChanged {
			events = append(events, WatchEvent{
				EventType:       EventPermissionChanged,
				Timestamp:       now,
				Finding:         newCopy,
				PreviousFinding: &oldCopy,
			})
		} else if contentChanged {
			// Emit CONTENT_CHANGED only if no PERMISSION_CHANGED already covered this key.
			events = append(events, WatchEvent{
				EventType:       EventContentChanged,
				Timestamp:       now,
				Finding:         newCopy,
				PreviousFinding: &oldCopy,
			})
		}

		if riskEscalated {
			events = append(events, WatchEvent{
				EventType:       EventRiskEscalated,
				Timestamp:       now,
				Finding:         newCopy,
				PreviousFinding: &oldCopy,
			})
		}
	}

	return events
}

// FilterEvents drops events whose finding risk is below minRisk.
// REMOVED events are kept regardless of severity — they always indicate a
// state change worth knowing about.
func FilterEvents(events []WatchEvent, minRisk core.RiskLevel) []WatchEvent {
	out := make([]WatchEvent, 0, len(events))
	for _, ev := range events {
		if ev.EventType == EventRemoved {
			out = append(out, ev)
			continue
		}
		if RiskAtOrAbove(ev.Finding.RiskLevel, minRisk) {
			out = append(out, ev)
		}
	}
	return out
}

// EventSink is a callable that receives a WatchEvent.
type EventSink func(WatchEvent)

// debounceKey is the composite key used for per-(finding, event-type) debounce tracking.
type debounceKey struct {
	Finding   FindingKey
	EventType EventType
}

// DebounceTracker suppresses duplicate (key, event_type) events within a time window.
type DebounceTracker struct {
	Window time.Duration

	mu       sync.Mutex
	lastEmit map[debounceKey]time.Time
}

// NewDebounceTracker returns a DebounceTracker with the given suppression window.
// A window of 0 or less disables debouncing.
func NewDebounceTracker(window time.Duration) *DebounceTracker {
	return &DebounceTracker{
		Window:   window,
		lastEmit: make(map[debounceKey]time.Time),
	}
}

// Allow reports whether the event should be emitted given the debounce window.
// Updates internal state as a side effect when the event is allowed.
func (t *DebounceTracker) Allow(event WatchEvent) bool {
	if t == nil || t.Window <= 0 {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lastEmit == nil {
		t.lastEmit = make(map[debounceKey]time.Time)
	}
	key := debounceKey{
		Finding:   FindingKeyOf(event.Finding),
		EventType: event.EventType,
	}
	now := time.Now()
	last, ok := t.lastEmit[key]
	if !ok || now.Sub(last) >= t.Window {
		t.lastEmit[key] = now
		return true
	}
	return false
}

// WatchLoop is the main watch/monitor loop.
type WatchLoop struct {
	Scanners       []core.Scanner
	Sinks          []EventSink
	Interval       time.Duration
	MinRisk        core.RiskLevel
	DebounceWindow time.Duration
	ShowSecrets    bool

	// Logger receives verbose status messages. nil means "use the stdlib default".
	Logger *log.Logger

	debounce   *DebounceTracker
	eventCount int
}

// NewWatchLoop returns a WatchLoop with the given configuration.
func NewWatchLoop(
	scanners []core.Scanner,
	sinks []EventSink,
	interval time.Duration,
	minRisk core.RiskLevel,
	debounceWindow time.Duration,
	showSecrets bool,
) *WatchLoop {
	return &WatchLoop{
		Scanners:       scanners,
		Sinks:          sinks,
		Interval:       interval,
		MinRisk:        minRisk,
		DebounceWindow: debounceWindow,
		ShowSecrets:    showSecrets,
		debounce:       NewDebounceTracker(debounceWindow),
	}
}

// logf writes a debug message via the configured logger (if any).
func (l *WatchLoop) logf(format string, args ...any) {
	if l.Logger != nil {
		l.Logger.Printf(format, args...)
	}
}

// emit debounces and fans out an event to all registered sinks.
// Each sink is invoked under a recover guard so a panicking sink cannot kill the loop.
func (l *WatchLoop) emit(event WatchEvent) {
	if !l.debounce.Allow(event) {
		l.logf("debounced %s event for %s",
			event.EventType.String(),
			FindingKeyOf(event.Finding).String(),
		)
		return
	}
	l.eventCount++
	for _, sink := range l.Sinks {
		func(s EventSink) {
			defer func() {
				if r := recover(); r != nil {
					l.logf("sink panicked: %v", r)
				}
			}()
			s(event)
		}(sink)
	}
}

// scanOnce runs every configured scanner once and returns the raw ScanResults.
// Scanner panics are caught and converted into a ScanResult with an error entry,
// matching the main CLI's recover pattern.
func (l *WatchLoop) scanOnce() []core.ScanResult {
	results := make([]core.ScanResult, 0, len(l.Scanners))
	for _, scanner := range l.Scanners {
		l.logf("scanning: %s", scanner.Name())
		var result core.ScanResult
		func() {
			defer func() {
				if r := recover(); r != nil {
					result = core.ScanResult{
						ScannerName: scanner.Name(),
						Platform:    core.DetectPlatform().String(),
						Errors:      []string{fmt.Sprintf("panic: %v", r)},
					}
				}
			}()
			start := time.Now()
			result = scanner.Scan(l.ShowSecrets)
			result.ScanTime = time.Since(start).Seconds()
		}()
		results = append(results, result)
	}
	return results
}

// Run blocks until the given context is canceled. On each interval it scans,
// diffs against the previous snapshot, filters by MinRisk, debounces, and
// fans events out to all registered sinks. Returns the total number of
// emitted (post-debounce) events.
//
// Signal handling is the caller's responsibility: pass a context that is
// canceled on SIGINT/SIGTERM.
func (l *WatchLoop) Run(ctx context.Context) (int, error) {
	if l.Interval <= 0 {
		return 0, fmt.Errorf("watch: interval must be > 0")
	}
	if l.debounce == nil {
		l.debounce = NewDebounceTracker(l.DebounceWindow)
	}

	l.logf("watch mode starting: interval=%s, scanners=%d, min_risk=%s",
		l.Interval, len(l.Scanners), l.MinRisk.String())

	var prevState map[FindingKey]core.CredentialFinding
	firstRun := true

	// Immediate first tick without waiting for Interval.
	for {
		// Honor cancellation before kicking off a scan.
		select {
		case <-ctx.Done():
			return l.eventCount, nil
		default:
		}

		results := l.scanOnce()
		currState := FlattenToMap(results)
		now := time.Now().UTC()

		if firstRun {
			for _, f := range currState {
				if RiskAtOrAbove(f.RiskLevel, l.MinRisk) {
					l.emit(WatchEvent{
						EventType: EventBaseline,
						Timestamp: now,
						Finding:   f,
					})
				}
			}
			firstRun = false
		} else {
			events := DiffFindings(prevState, currState, now)
			events = FilterEvents(events, l.MinRisk)
			for _, e := range events {
				l.emit(e)
			}
		}
		prevState = currState

		// Wait for either the next tick or cancellation. We create the timer
		// per iteration so the interval is "time since scan finished", matching
		// the Python implementation's scan-then-sleep behavior.
		timer := time.NewTimer(l.Interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return l.eventCount, nil
		case <-timer.C:
			// proceed to next iteration
		}
	}
}
