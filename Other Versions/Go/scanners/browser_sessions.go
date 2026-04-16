package scanners

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"aihound/core"
	"aihound/remediation"
)

var browserAIDomains = []string{
	"claude.ai",
	"openai.com",
	"chatgpt.com",
	"gemini.google.com",
	"copilot.microsoft.com",
	"perplexity.ai",
	"huggingface.co",
}

var browserSessionCookieKeywords = []string{"session", "auth", "token"}

type browserSessionsScanner struct{}

func init() {
	Register(&browserSessionsScanner{})
}

func (s *browserSessionsScanner) Name() string        { return "Browser Sessions" }
func (s *browserSessionsScanner) Slug() string         { return "browser-sessions" }
func (s *browserSessionsScanner) IsApplicable() bool   { return true }

func (s *browserSessionsScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, root := range s.getFirefoxProfilesRoots(plat) {
		s.scanFirefoxRoot(root, &result, showSecrets)
	}

	for _, entry := range s.getChromiumLocalStorageDirs(plat) {
		s.recordChromiumStub(entry.browser, entry.path, &result)
	}

	return result
}

// ---- Firefox ----

func (s *browserSessionsScanner) getFirefoxProfilesRoots(plat core.Platform) []string {
	var roots []string
	home := core.GetHome()

	switch plat {
	case core.PlatformLinux:
		roots = append(roots, filepath.Join(home, ".mozilla", "firefox"))
	case core.PlatformMacOS:
		roots = append(roots, filepath.Join(home, "Library", "Application Support", "Firefox"))
	case core.PlatformWindows:
		if appdata := core.GetAppData(); appdata != "" {
			roots = append(roots, filepath.Join(appdata, "Mozilla", "Firefox"))
		}
	case core.PlatformWSL:
		roots = append(roots, filepath.Join(home, ".mozilla", "firefox"))
		if appdata := core.GetAppData(); appdata != "" {
			roots = append(roots, filepath.Join(appdata, "Mozilla", "Firefox"))
		}
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			roots = append(roots, filepath.Join(winHome, "AppData", "Roaming", "Mozilla", "Firefox"))
		}
	}

	seen := map[string]bool{}
	var unique []string
	for _, r := range roots {
		if !seen[r] {
			seen[r] = true
			unique = append(unique, r)
		}
	}
	return unique
}

func (s *browserSessionsScanner) scanFirefoxRoot(profilesRoot string, result *core.ScanResult, showSecrets bool) {
	if _, err := os.Stat(profilesRoot); err != nil {
		return
	}

	profilesINI := filepath.Join(profilesRoot, "profiles.ini")
	profileDirs := s.parseFirefoxProfilesINI(profilesINI, profilesRoot)

	if len(profileDirs) == 0 {
		// Fallback: scan subdirs that contain webappsstore.sqlite
		candidates := []string{profilesRoot, filepath.Join(profilesRoot, "Profiles")}
		for _, parent := range candidates {
			info, err := os.Stat(parent)
			if err != nil || !info.IsDir() {
				continue
			}
			entries, _ := os.ReadDir(parent)
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				child := filepath.Join(parent, entry.Name())
				if _, err := os.Stat(filepath.Join(child, "webappsstore.sqlite")); err == nil {
					profileDirs = append(profileDirs, child)
				}
			}
		}
	}

	for _, pd := range profileDirs {
		s.scanFirefoxProfile(pd, result, showSecrets)
	}
}

func (s *browserSessionsScanner) parseFirefoxProfilesINI(profilesINI, profilesRoot string) []string {
	data, err := os.ReadFile(profilesINI)
	if err != nil {
		return nil
	}

	sections := parseINI(string(data))
	var dirs []string
	for sectionName, kvs := range sections {
		if !strings.HasPrefix(strings.ToLower(sectionName), "profile") {
			continue
		}
		pathValue, ok := kvs["Path"]
		if !ok || pathValue == "" {
			continue
		}
		isRelative := kvs["IsRelative"]
		if isRelative == "" {
			isRelative = "1"
		}
		var profileDir string
		if strings.TrimSpace(isRelative) == "1" {
			profileDir = filepath.Join(profilesRoot, pathValue)
		} else {
			profileDir = pathValue
		}
		dirs = append(dirs, profileDir)
	}
	return dirs
}

func (s *browserSessionsScanner) scanFirefoxProfile(profileDir string, result *core.ScanResult, showSecrets bool) {
	if info, err := os.Stat(profileDir); err != nil || !info.IsDir() {
		return
	}

	s.scanFirefoxWebappsstore(profileDir, result, showSecrets)
	s.scanFirefoxCookies(profileDir, result, showSecrets)
}

func (s *browserSessionsScanner) scanFirefoxWebappsstore(profileDir string, result *core.ScanResult, showSecrets bool) {
	dbPath := filepath.Join(profileDir, "webappsstore.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		return
	}

	perms := core.GetFilePermissions(dbPath)
	owner := core.GetFileOwner(dbPath)
	mtime := core.GetFileMtime(dbPath)

	dsn := fmt.Sprintf("file:%s?mode=ro&_timeout=1000", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Firefox DB open failed: %s: %v", dbPath, err))
		return
	}
	defer db.Close()

	// Build WHERE clause
	var whereClauses []string
	var args []interface{}
	for _, domain := range browserAIDomains {
		reversed := reverseString(domain)
		whereClauses = append(whereClauses, "originKey LIKE ?")
		args = append(args, "%"+reversed+"%")
	}
	query := "SELECT originKey, key, value FROM webappsstore2 WHERE " + strings.Join(whereClauses, " OR ")

	rows, err := db.Query(query, args...)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Firefox webappsstore2 query failed on %s: %v", dbPath, err))
		return
	}
	defer rows.Close()

	stalenessNote := ""
	if mt := core.GetFileMtimeTime(dbPath); !mt.IsZero() {
		stalenessNote = "Database last modified: " + core.DescribeStaleness(mt)
	}

	for rows.Next() {
		var originKey, key, value sql.NullString
		if err := rows.Scan(&originKey, &key, &value); err != nil {
			continue
		}

		origin := originKey.String
		domain := domainFromOriginKey(origin)
		keyStr := key.String
		valueStr := value.String

		displayKey := keyStr
		if len(displayKey) > 120 {
			displayKey = displayKey[:120]
		}

		notes := []string{
			fmt.Sprintf("originKey: %s", origin),
			fmt.Sprintf("localStorage key: %s", displayKey),
		}
		if stalenessNote != "" {
			notes = append(notes, stalenessNote)
		}
		if browserLooksSessionLike(keyStr) {
			notes = append(notes, "Key name suggests a session/auth token")
		}

		preview := "(empty)"
		if valueStr != "" {
			preview = core.MaskValue(valueStr, showSecrets)
		}
		rawValue := ""
		if showSecrets {
			rawValue = valueStr
		}

		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:        fmt.Sprintf("Firefox: %s", domain),
			CredentialType:  "browser_localstorage",
			StorageType:     core.EncryptedDB,
			Location:        dbPath,
			Exists:          true,
			RiskLevel:       core.RiskMedium,
			ValuePreview:    preview,
			RawValue:        rawValue,
			FilePermissions: perms,
			FileOwner:       owner,
			FileModified:    mtime,
			Remediation:     "Ensure browser profile directory has restricted permissions (chmod 700). Clear site data to revoke local sessions.",
			RemediationHint: remediation.HintChmod("700", profileDir),
			Notes:           notes,
		})
	}
}

func (s *browserSessionsScanner) scanFirefoxCookies(profileDir string, result *core.ScanResult, showSecrets bool) {
	dbPath := filepath.Join(profileDir, "cookies.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		return
	}

	perms := core.GetFilePermissions(dbPath)
	owner := core.GetFileOwner(dbPath)
	mtime := core.GetFileMtime(dbPath)

	dsn := fmt.Sprintf("file:%s?mode=ro&_timeout=1000", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Firefox cookies DB open failed: %s: %v", dbPath, err))
		return
	}
	defer db.Close()

	var whereClauses []string
	var args []interface{}
	for _, domain := range browserAIDomains {
		whereClauses = append(whereClauses, "host LIKE ?")
		args = append(args, "%"+domain+"%")
	}
	query := "SELECT host, name, value FROM moz_cookies WHERE " + strings.Join(whereClauses, " OR ")

	rows, err := db.Query(query, args...)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Firefox moz_cookies query failed on %s: %v", dbPath, err))
		return
	}
	defer rows.Close()

	stalenessNote := ""
	if mt := core.GetFileMtimeTime(dbPath); !mt.IsZero() {
		stalenessNote = "Database last modified: " + core.DescribeStaleness(mt)
	}

	for rows.Next() {
		var host, name, value sql.NullString
		if err := rows.Scan(&host, &name, &value); err != nil {
			continue
		}
		nameStr := name.String
		if !browserLooksSessionLike(nameStr) {
			continue
		}
		valueStr := value.String
		hostStr := host.String

		notes := []string{
			fmt.Sprintf("Cookie host: %s", hostStr),
			fmt.Sprintf("Cookie name: %s", nameStr),
		}
		if stalenessNote != "" {
			notes = append(notes, stalenessNote)
		}

		preview := "(empty)"
		if valueStr != "" {
			preview = core.MaskValue(valueStr, showSecrets)
		}
		rawValue := ""
		if showSecrets {
			rawValue = valueStr
		}

		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:        fmt.Sprintf("Firefox cookie: %s", strings.TrimLeft(hostStr, ".")),
			CredentialType:  "browser_cookie",
			StorageType:     core.EncryptedDB,
			Location:        dbPath,
			Exists:          true,
			RiskLevel:       core.RiskMedium,
			ValuePreview:    preview,
			RawValue:        rawValue,
			FilePermissions: perms,
			FileOwner:       owner,
			FileModified:    mtime,
			Remediation:     "Ensure browser profile directory has restricted permissions (chmod 700). Clear site cookies to revoke this session.",
			RemediationHint: remediation.HintChmod("700", profileDir),
			Notes:           notes,
		})
	}
}

// ---- Chromium ----

type chromiumEntry struct {
	browser string
	path    string
}

func (s *browserSessionsScanner) getChromiumLocalStorageDirs(plat core.Platform) []chromiumEntry {
	var entries []chromiumEntry
	home := core.GetHome()

	linuxEntries := func() []chromiumEntry {
		return []chromiumEntry{
			{"Google Chrome", filepath.Join(home, ".config", "google-chrome", "Default", "Local Storage")},
			{"Brave", filepath.Join(home, ".config", "BraveSoftware", "Brave-Browser", "Default", "Local Storage")},
			{"Chromium", filepath.Join(home, ".config", "chromium", "Default", "Local Storage")},
			{"Microsoft Edge", filepath.Join(home, ".config", "microsoft-edge", "Default", "Local Storage")},
		}
	}

	macosEntries := func() []chromiumEntry {
		return []chromiumEntry{
			{"Google Chrome", filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "Default", "Local Storage")},
			{"Brave", filepath.Join(home, "Library", "Application Support", "BraveSoftware", "Brave-Browser", "Default", "Local Storage")},
			{"Microsoft Edge", filepath.Join(home, "Library", "Application Support", "Microsoft Edge", "Default", "Local Storage")},
		}
	}

	windowsEntries := func(localappdata string) []chromiumEntry {
		return []chromiumEntry{
			{"Google Chrome", filepath.Join(localappdata, "Google", "Chrome", "User Data", "Default", "Local Storage")},
			{"Microsoft Edge", filepath.Join(localappdata, "Microsoft", "Edge", "User Data", "Default", "Local Storage")},
			{"Brave", filepath.Join(localappdata, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Storage")},
		}
	}

	switch plat {
	case core.PlatformLinux:
		entries = append(entries, linuxEntries()...)
	case core.PlatformMacOS:
		entries = append(entries, macosEntries()...)
	case core.PlatformWindows:
		if lad := core.GetLocalAppData(); lad != "" {
			entries = append(entries, windowsEntries(lad)...)
		}
	case core.PlatformWSL:
		entries = append(entries, linuxEntries()...)
		if lad := core.GetLocalAppData(); lad != "" {
			entries = append(entries, windowsEntries(lad)...)
		}
	}
	return entries
}

func (s *browserSessionsScanner) recordChromiumStub(browserName, localStorageDir string, result *core.ScanResult) {
	info, err := os.Stat(localStorageDir)
	if err != nil || !info.IsDir() {
		return
	}
	entries, err := os.ReadDir(localStorageDir)
	if err != nil || len(entries) == 0 {
		return
	}

	mtime := core.GetFileMtime(localStorageDir)
	notes := []string{
		"Chromium LevelDB requires optional dependency to parse",
		"AI session tokens may exist in this storage",
	}
	if mt := core.GetFileMtimeTime(localStorageDir); !mt.IsZero() {
		notes = append(notes, "Directory last modified: "+core.DescribeStaleness(mt))
	}

	result.Findings = append(result.Findings, core.CredentialFinding{
		ToolName:       fmt.Sprintf("%s (not scanned)", browserName),
		CredentialType: "browser_localstorage",
		StorageType:    core.EncryptedDB,
		Location:       localStorageDir,
		Exists:         true,
		RiskLevel:      core.RiskInfo,
		FileModified:   mtime,
		Remediation:    "Review browser storage manually or use dedicated Chromium LevelDB tools.",
		RemediationHint: remediation.HintManual("Review browser storage manually or use dedicated Chromium LevelDB tools."),
		Notes:          notes,
	})
}

// ---- helpers ----

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func domainFromOriginKey(originKey string) string {
	if originKey == "" {
		return "unknown"
	}
	parts := strings.Split(originKey, ":")
	reversedDomain := parts[0]
	reversedDomain = strings.TrimRight(reversedDomain, ".")
	if reversedDomain == "" {
		return "unknown"
	}
	return reverseString(reversedDomain)
}

func browserLooksSessionLike(name string) bool {
	lowered := strings.ToLower(name)
	for _, kw := range browserSessionCookieKeywords {
		if strings.Contains(lowered, kw) {
			return true
		}
	}
	return false
}
