package output

import (
	"encoding/base64"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aihound/core"
)

type htmlData struct {
	BannerURI  string
	Platform   string
	Timestamp  string
	Version    string
	TotalCount int
	Badges     []htmlBadge
	Rows       []htmlRow
	Errors     []string
}

type htmlBadge struct {
	Color string
	Label string
}

type htmlRow struct {
	BgColor      string
	ToolName     string
	CredType     string
	Storage      string
	Location     string
	ValuePrev    string
	RiskColor    string
	RiskLabel    string
	Notes        []string
	Perms        string
	Expiry       string
	FileModified string
	Staleness    string
	Remediation  string
}

func riskHTMLColor(r core.RiskLevel) string {
	switch r {
	case core.RiskCritical:
		return "#e74c3c"
	case core.RiskHigh:
		return "#e67e22"
	case core.RiskMedium:
		return "#f1c40f"
	case core.RiskLow:
		return "#2ecc71"
	case core.RiskInfo:
		return "#3498db"
	default:
		return "#95a5a6"
	}
}

func riskHTMLBg(r core.RiskLevel) string {
	switch r {
	case core.RiskCritical:
		return "rgba(231,76,60,0.15)"
	case core.RiskHigh:
		return "rgba(230,126,34,0.15)"
	case core.RiskMedium:
		return "rgba(241,196,15,0.10)"
	case core.RiskLow:
		return "rgba(46,204,113,0.10)"
	case core.RiskInfo:
		return "rgba(52,152,219,0.10)"
	default:
		return "transparent"
	}
}

func encodeBanner(bannerPath string) string {
	if bannerPath == "" {
		return ""
	}
	data, err := os.ReadFile(bannerPath)
	if err != nil {
		return ""
	}
	ext := strings.ToLower(filepath.Ext(bannerPath))
	mime := "image/png"
	switch ext {
	case ".jpg", ".jpeg":
		mime = "image/jpeg"
	case ".gif":
		mime = "image/gif"
	case ".svg":
		mime = "image/svg+xml"
	case ".webp":
		mime = "image/webp"
	}
	b64 := base64.StdEncoding.EncodeToString(data)
	return "data:" + mime + ";base64," + b64
}

// WriteHTMLReport generates a self-contained HTML report file.
func WriteHTMLReport(path string, results []core.ScanResult, bannerPath string, version string) error {
	var allFindings []core.CredentialFinding
	var allErrors []string

	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
		allErrors = append(allErrors, r.Errors...)
	}

	// Sort by risk
	sort.Slice(allFindings, func(i, j int) bool {
		return riskSortKey(allFindings[i].RiskLevel) < riskSortKey(allFindings[j].RiskLevel)
	})

	// Risk counts
	counts := make(map[core.RiskLevel]int)
	for _, f := range allFindings {
		counts[f.RiskLevel]++
	}

	// Platform
	platform := "unknown"
	if len(results) > 0 && results[0].Platform != "" {
		platform = results[0].Platform
	}

	// Badges
	var badges []htmlBadge
	for _, level := range []core.RiskLevel{core.RiskCritical, core.RiskHigh, core.RiskMedium, core.RiskLow, core.RiskInfo} {
		if c, ok := counts[level]; ok && c > 0 {
			badges = append(badges, htmlBadge{
				Color: riskHTMLColor(level),
				Label: strings.ToUpper(level.String()),
			})
		}
	}

	// Rows
	var rows []htmlRow
	for _, f := range allFindings {
		row := htmlRow{
			BgColor:   riskHTMLBg(f.RiskLevel),
			ToolName:  f.ToolName,
			CredType:  f.CredentialType,
			Storage:   f.StorageType.String(),
			Location:  f.Location,
			ValuePrev: f.ValuePreview,
			RiskColor: riskHTMLColor(f.RiskLevel),
			RiskLabel: strings.ToUpper(f.RiskLevel.String()),
			Notes:     f.Notes,
		}
		if f.FilePermissions != "" {
			desc := core.DescribePermissions(f.FilePermissions)
			row.Perms = f.FilePermissions + " (" + desc + ")"
		}
		if f.Expiry != "" {
			row.Expiry = f.Expiry
		}
		if f.FileModified != "" {
			if t, err := time.Parse(time.RFC3339, f.FileModified); err == nil {
				row.FileModified = t.Format("2006-01-02")
				row.Staleness = core.DescribeStaleness(t)
			} else {
				row.FileModified = f.FileModified
			}
		}
		if f.Remediation != "" {
			row.Remediation = f.Remediation
		}
		rows = append(rows, row)
	}

	data := htmlData{
		BannerURI:  encodeBanner(bannerPath),
		Platform:   platform,
		Timestamp:  time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Version:    version,
		TotalCount: len(allFindings),
		Badges:     badges,
		Rows:       rows,
		Errors:     allErrors,
	}

	resolved, err := prepareOutputPath(path)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(resolved, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	return htmlTmpl.Execute(f, data)
}

var htmlTmpl = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AIHound Scan Report</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        background: #0a0e1a;
        color: #e0e6f0;
        line-height: 1.6;
    }
    .banner {
        text-align: center;
        padding: 30px 20px 10px;
        background: linear-gradient(135deg, #0d1224 0%, #1a1f3a 100%);
    }
    .banner img {
        max-width: 600px;
        width: 100%;
        height: auto;
        border-radius: 12px;
    }
    .container {
        max-width: 1400px;
        margin: 0 auto;
        padding: 20px;
    }
    .meta {
        display: flex;
        gap: 20px;
        flex-wrap: wrap;
        margin: 20px 0;
        padding: 15px 20px;
        background: rgba(255,255,255,0.05);
        border-radius: 8px;
        border: 1px solid rgba(255,255,255,0.08);
        font-size: 14px;
    }
    .meta span { color: #8892b0; }
    .meta strong { color: #ccd6f6; }
    .summary {
        margin: 20px 0;
        display: flex;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
    }
    .summary h2 {
        font-size: 20px;
        color: #ccd6f6;
        margin-right: 8px;
    }
    .badge {
        display: inline-block;
        padding: 4px 14px;
        border-radius: 20px;
        font-size: 13px;
        font-weight: 700;
        color: #fff;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        font-size: 13px;
    }
    th {
        background: rgba(255,255,255,0.08);
        color: #8892b0;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 11px;
        letter-spacing: 0.05em;
        padding: 12px 14px;
        text-align: left;
        border-bottom: 2px solid rgba(255,255,255,0.1);
        position: sticky;
        top: 0;
    }
    td {
        padding: 10px 14px;
        border-bottom: 1px solid rgba(255,255,255,0.05);
        vertical-align: top;
    }
    tr:hover { background: rgba(255,255,255,0.03) !important; }
    .tool { font-weight: 600; color: #ccd6f6; white-space: nowrap; }
    .cred-type { color: #a8b2d1; }
    .storage { color: #8892b0; font-size: 12px; }
    .location {
        font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
        font-size: 12px;
        color: #64ffda;
        max-width: 350px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .value {
        font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
        font-size: 12px;
        color: #e6db74;
        max-width: 220px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .risk { text-align: center; font-size: 12px; white-space: nowrap; }
    .details { font-size: 11px; color: #8892b0; }
    .note { display: block; }
    .perms, .expiry { display: block; color: #5a6580; }
    .file-modified { display: block; color: #b0b0b0; font-size: 0.85em; margin-top: 2px; }
    .remediation { display: block; color: #2ecc71; font-style: italic; margin-top: 4px; }
    .errors {
        margin: 20px 0;
        padding: 15px 20px;
        background: rgba(231,76,60,0.1);
        border: 1px solid rgba(231,76,60,0.3);
        border-radius: 8px;
    }
    .errors h3 { color: #e74c3c; margin-bottom: 8px; font-size: 14px; }
    .errors li { font-size: 13px; color: #e0a8a1; margin-left: 20px; }
    .footer {
        text-align: center;
        padding: 30px;
        color: #5a6580;
        font-size: 12px;
        border-top: 1px solid rgba(255,255,255,0.05);
        margin-top: 40px;
    }
    @media (max-width: 900px) {
        .location, .value { max-width: 180px; }
        td, th { padding: 8px 8px; }
    }
</style>
</head>
<body>
    {{if .BannerURI}}<div class="banner"><img src="{{.BannerURI}}" alt="AIHound"></div>{{end}}
    <div class="container">
        <div class="meta">
            <span>Platform: <strong>{{.Platform}}</strong></span>
            <span>Scan Time: <strong>{{.Timestamp}}</strong></span>
            <span>Version: <strong>AIHound {{.Version}}</strong></span>
            <span>Total Findings: <strong>{{.TotalCount}}</strong></span>
        </div>

        <div class="summary">
            <h2>Findings</h2>
            {{range .Badges}}<span class="badge" style="background:{{.Color}}">{{.Label}}</span> {{end}}
        </div>

        <table>
            <thead>
                <tr>
                    <th>Tool</th>
                    <th>Credential Type</th>
                    <th>Storage</th>
                    <th>Location</th>
                    <th>Value Preview</th>
                    <th>Risk</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {{range .Rows}}
                <tr style="background:{{.BgColor}}">
                    <td class="tool">{{.ToolName}}</td>
                    <td class="cred-type">{{.CredType}}</td>
                    <td class="storage">{{.Storage}}</td>
                    <td class="location" title="{{.Location}}">{{.Location}}</td>
                    <td class="value">{{.ValuePrev}}</td>
                    <td class="risk" style="color:{{.RiskColor}};font-weight:700">{{.RiskLabel}}</td>
                    <td class="details">{{range .Notes}}<span class="note">{{.}}</span>{{end}}{{if .Perms}}<span class="perms">Perms: {{.Perms}}</span>{{end}}{{if .Expiry}}<span class="expiry">Expires: {{.Expiry}}</span>{{end}}{{if .FileModified}}<span class="file-modified">Modified: {{.FileModified}}{{if .Staleness}} ({{.Staleness}}){{end}}</span>{{end}}{{if .Remediation}}<span class="remediation">Fix: {{.Remediation}}</span>{{end}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>

        {{if .Errors}}
        <div class="errors">
            <h3>Errors</h3>
            <ul>{{range .Errors}}<li>{{.}}</li>{{end}}</ul>
        </div>
        {{end}}
    </div>

    <div class="footer">
        Generated by AIHound {{.Version}} &mdash; AI Credential &amp; Secrets Scanner
    </div>
</body>
</html>`))
