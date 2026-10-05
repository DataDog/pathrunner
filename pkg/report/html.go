// Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
// This product includes software developed at Datadog (https://www.datadoghq.com/)
// Copyright 2026 Datadog, Inc.

package report

import (
	"bytes"
	"html/template"
)

// RenderHTML produces a self-contained HTML workspace report with inline CSS and JS.
// All content is safely escaped via html/template to prevent XSS.
func RenderHTML(data ReportData) (string, error) {
	// Pre-compute per-resource display values to keep the template simple.
	type resourceWithCmd struct {
		Resource
		CleanupCmd  string
		DisplayName string // principal "name (type)" for modified resources, or just Name
		PolicyARN   string // for iam:attached-policy and similar
	}

	enrichResource := func(res Resource) resourceWithCmd {
		displayName := res.Name
		if pn := res.Metadata["principal_name"]; pn != "" {
			displayName = pn + " (" + res.Metadata["principal_type"] + ")"
		}
		return resourceWithCmd{
			Resource:    res,
			CleanupCmd:  CleanupCommand(res),
			DisplayName: displayName,
			PolicyARN:   res.Metadata["policy_arn"],
		}
	}

	createdWithCmds := make([]resourceWithCmd, len(data.Created))
	for i, res := range data.Created {
		createdWithCmds[i] = enrichResource(res)
	}
	modifiedWithCmds := make([]resourceWithCmd, len(data.Modified))
	for i, res := range data.Modified {
		modifiedWithCmds[i] = enrichResource(res)
	}

	tmplData := struct {
		ReportData
		CreatedWithCmds  []resourceWithCmd
		ModifiedWithCmds []resourceWithCmd
		GeneratedAtStr   string
		TotalResources   int
	}{
		ReportData:       data,
		CreatedWithCmds:  createdWithCmds,
		ModifiedWithCmds: modifiedWithCmds,
		GeneratedAtStr:   data.GeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		TotalResources:   len(data.Created) + len(data.Modified),
	}

	t, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, tmplData); err != nil {
		return "", err
	}
	return buf.String(), nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="generator" content="pathrunner">
<meta name="workspace" content="{{.WorkspaceName}}">
<meta name="generated" content="{{.GeneratedAtStr}}">
<title>Pathrunner Report — {{.WorkspaceName}}</title>
<style>
:root {
  --bg: #f8f9fa;
  --bg-card: #ffffff;
  --bg-code: #f1f3f5;
  --text: #1a1d23;
  --text-muted: #5c6370;
  --border: #d0d7de;
  --accent: #c0392b;
  --accent-soft: #fdecea;
  --created: #1a7f37;
  --created-soft: #dafbe1;
  --modified: #9a6700;
  --modified-soft: #fff8c5;
  --events: #0550ae;
  --events-soft: #ddf4ff;
  --mono: 'SF Mono', 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  --radius: 8px;
  --shadow: 0 1px 3px rgba(0,0,0,.08), 0 1px 2px rgba(0,0,0,.06);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117;
    --bg-card: #161b22;
    --bg-code: #1c2128;
    --text: #e6edf3;
    --text-muted: #8b949e;
    --border: #30363d;
    --accent: #f85149;
    --accent-soft: #3d1a1a;
    --created: #3fb950;
    --created-soft: #0f2e17;
    --modified: #d29922;
    --modified-soft: #2e1f00;
    --events: #58a6ff;
    --events-soft: #0c1f3d;
    --shadow: 0 1px 3px rgba(0,0,0,.3);
  }
}
*,*::before,*::after { box-sizing: border-box; }
body {
  margin: 0;
  padding: 24px 20px 48px;
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  font-size: 14px;
  line-height: 1.6;
}
a { color: var(--events); }
.container { max-width: 1100px; margin: 0 auto; }

/* Header */
.report-header {
  border-bottom: 2px solid var(--accent);
  padding-bottom: 20px;
  margin-bottom: 28px;
}
.report-header h1 {
  margin: 0 0 4px;
  font-size: 22px;
  font-weight: 700;
  letter-spacing: -.3px;
}
.report-header .meta {
  color: var(--text-muted);
  font-size: 13px;
}
.report-header .meta span { margin-right: 20px; }

/* Stat tiles */
.stats {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 32px;
}
.stat {
  flex: 1;
  min-width: 140px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px 20px;
  box-shadow: var(--shadow);
}
.stat .label { font-size: 11px; text-transform: uppercase; letter-spacing: .6px; color: var(--text-muted); margin-bottom: 4px; }
.stat .value { font-size: 28px; font-weight: 700; line-height: 1; }
.stat.created .value { color: var(--created); }
.stat.modified .value { color: var(--modified); }
.stat.events .value { color: var(--events); }

/* Section headings */
.section { margin-bottom: 32px; }
.section-heading {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 15px;
  font-weight: 600;
  margin: 0 0 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}
.badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 600;
}
.badge.created { background: var(--created-soft); color: var(--created); }
.badge.modified { background: var(--modified-soft); color: var(--modified); }
.badge.events  { background: var(--events-soft);  color: var(--events); }

/* Resource cards */
.resource-grid {
  display: grid;
  gap: 12px;
}
.resource-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 14px 18px;
  box-shadow: var(--shadow);
}
.resource-card .type-name {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text-muted);
  margin-bottom: 4px;
}
.resource-card .res-name {
  font-weight: 600;
  font-size: 14px;
  margin-bottom: 10px;
  word-break: break-all;
}
.resource-card .fields {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 3px 16px;
  font-size: 13px;
}
.resource-card .field-key { color: var(--text-muted); white-space: nowrap; }
.resource-card .field-val { font-family: var(--mono); font-size: 12px; word-break: break-all; }
.resource-card .field-val.plain { font-family: var(--sans); font-size: 13px; }

/* Inline cleanup command inside a resource card */
.card-cmd-label {
  margin-top: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .5px;
  color: var(--text-muted);
}
pre.card-cmd {
  margin: 10px 0 0;
  padding: 10px 12px;
  font-family: var(--mono);
  font-size: 11px;
  line-height: 1.6;
  background: var(--bg-code);
  border-radius: 4px;
  overflow-x: auto;
  white-space: pre;
  color: var(--text);
}

/* Events table */
.events-wrap {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  box-shadow: var(--shadow);
}
.table-scroll { overflow-x: auto; }
table.events {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
table.events thead tr {
  background: var(--bg-code);
  text-align: left;
}
table.events th {
  padding: 9px 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .5px;
  color: var(--text-muted);
  white-space: nowrap;
  cursor: pointer;
  user-select: none;
  border-bottom: 1px solid var(--border);
}
table.events th:hover { color: var(--text); }
table.events th .sort-indicator { margin-left: 4px; opacity: .5; }
table.events td {
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  word-break: break-word;
}
table.events tbody tr:last-child td { border-bottom: none; }
table.events tbody tr:hover { background: var(--bg-code); }
table.events td.ts { font-family: var(--mono); white-space: nowrap; color: var(--text-muted); }
table.events td.module { font-family: var(--mono); color: var(--events); }
table.events td.service { font-family: var(--mono); }
table.events td.operation { font-family: var(--mono); font-weight: 600; }
table.events td.principal { font-family: var(--mono); font-size: 11px; color: var(--text-muted); }
.events-count { padding: 8px 16px; font-size: 12px; color: var(--text-muted); border-top: 1px solid var(--border); }

/* Filter bar */
.filter-bar {
  display: flex;
  gap: 8px;
  padding: 10px 12px;
  background: var(--bg-code);
  border-bottom: 1px solid var(--border);
}
.filter-bar input {
  flex: 1;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 5px 10px;
  font-size: 12px;
  color: var(--text);
  outline: none;
}
.filter-bar input:focus { border-color: var(--events); }
.filter-bar input::placeholder { color: var(--text-muted); }

/* Empty state */
.empty { color: var(--text-muted); font-style: italic; font-size: 13px; padding: 8px 0; }

/* Print */
@media print {
  body { padding: 0; background: #fff; color: #000; }
  .filter-bar { display: none; }
  .events-wrap, .resource-card { box-shadow: none; }
  table.events tbody tr:hover { background: none; }
}
</style>
</head>
<body>
<div class="container">

<header class="report-header">
  <h1>Pathrunner Workspace Report</h1>
  <div class="meta">
    <span>Workspace: <strong>{{.WorkspaceName}}</strong></span>
    <span>Generated: <strong>{{.GeneratedAtStr}}</strong></span>
    {{if .ModuleFilter}}<span>Module filter: <strong>{{.ModuleFilter}}</strong></span>{{end}}
  </div>
</header>

<div class="stats">
  <div class="stat created">
    <div class="label">Created Resources</div>
    <div class="value">{{len .Created}}</div>
  </div>
  <div class="stat modified">
    <div class="label">Modified Resources</div>
    <div class="value">{{len .Modified}}</div>
  </div>
  <div class="stat events">
    <div class="label">CloudTrail Events</div>
    <div class="value">{{len .Events}}</div>
  </div>
</div>

{{if .CreatedWithCmds}}
<section class="section">
  <h2 class="section-heading">
    Created Resources
    <span class="badge created">delete to clean up</span>
  </h2>
  <div class="resource-grid">
    {{range .CreatedWithCmds}}
    <div class="resource-card">
      <div class="type-name">{{.Type}}</div>
      <div class="res-name">{{.DisplayName}}</div>
      <div class="fields">
        {{if .ARN}}<span class="field-key">ARN</span><span class="field-val">{{.ARN}}</span>{{end}}
        {{if .Region}}<span class="field-key">Region</span><span class="field-val">{{.Region}}</span>{{end}}
        {{if .ModuleID}}<span class="field-key">Module</span><span class="field-val">{{.ModuleID}}</span>{{end}}
        <span class="field-key">Cleanup</span><span class="field-val plain">{{.CleanupMethod}}</span>
        {{if .Created}}<span class="field-key">Created</span><span class="field-val plain">{{.Created}}</span>{{end}}
      </div>
      {{if .CleanupCmd}}<div class="card-cmd-label">Manual cleanup command</div><pre class="card-cmd">{{.CleanupCmd}}</pre>{{end}}
    </div>
    {{end}}
  </div>
</section>
{{end}}

{{if .ModifiedWithCmds}}
<section class="section">
  <h2 class="section-heading">
    Modified Resources
    <span class="badge modified">revert to clean up</span>
  </h2>
  <div class="resource-grid">
    {{range .ModifiedWithCmds}}
    <div class="resource-card">
      <div class="type-name">{{.Type}}</div>
      <div class="res-name">{{.DisplayName}}</div>
      <div class="fields">
        {{if .PolicyARN}}<span class="field-key">Policy</span><span class="field-val">{{.PolicyARN}}</span>{{end}}
        {{if .Region}}<span class="field-key">Region</span><span class="field-val">{{.Region}}</span>{{end}}
        {{if .ModuleID}}<span class="field-key">Module</span><span class="field-val">{{.ModuleID}}</span>{{end}}
        <span class="field-key">Reversal</span><span class="field-val plain">{{.CleanupMethod}}</span>
      </div>
      {{if .CleanupCmd}}<div class="card-cmd-label">Manual cleanup command</div><pre class="card-cmd">{{.CleanupCmd}}</pre>{{end}}
    </div>
    {{end}}
  </div>
</section>
{{end}}


{{if .Events}}
<section class="section">
  <h2 class="section-heading">
    CloudTrail Events
    <span class="badge events">blue team detection reference</span>
  </h2>
  <div class="events-wrap">
    <div class="filter-bar">
      <input type="text" id="event-filter" placeholder="Filter events by service, operation, principal…" oninput="filterEvents()">
    </div>
    <div class="table-scroll">
      <table class="events" id="events-table">
        <thead>
          <tr>
            <th onclick="sortTable(0)">Timestamp <span class="sort-indicator">↕</span></th>
            <th onclick="sortTable(1)">Module <span class="sort-indicator">↕</span></th>
            <th onclick="sortTable(2)">Service <span class="sort-indicator">↕</span></th>
            <th onclick="sortTable(3)">Operation <span class="sort-indicator">↕</span></th>
            <th onclick="sortTable(4)">Principal <span class="sort-indicator">↕</span></th>
            <th onclick="sortTable(5)">Description <span class="sort-indicator">↕</span></th>
          </tr>
        </thead>
        <tbody id="events-body">
          {{range .Events}}
          <tr>
            <td class="ts">{{.Timestamp}}</td>
            <td class="module">{{.ModuleID}}</td>
            <td class="service">{{.Service}}</td>
            <td class="operation">{{.Operation}}</td>
            <td class="principal">{{.Principal}}</td>
            <td>{{.Description}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>
    <div class="events-count" id="events-count">{{len .Events}} events</div>
  </div>
</section>
{{end}}

</div>

<script>
let sortCol = -1, sortAsc = true;
function sortTable(col) {
  const tbody = document.getElementById('events-body');
  const rows = Array.from(tbody.querySelectorAll('tr:not([hidden])'));
  if (sortCol === col) { sortAsc = !sortAsc; } else { sortCol = col; sortAsc = true; }
  rows.sort(function(a, b) {
    const av = a.cells[col].textContent.trim();
    const bv = b.cells[col].textContent.trim();
    return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  rows.forEach(function(r) { tbody.appendChild(r); });
  document.querySelectorAll('th .sort-indicator').forEach(function(s, i) {
    s.textContent = i === col ? (sortAsc ? '↑' : '↓') : '↕';
    s.style.opacity = i === col ? '1' : '.5';
  });
}

function filterEvents() {
  const q = document.getElementById('event-filter').value.toLowerCase();
  const rows = document.getElementById('events-body').querySelectorAll('tr');
  let visible = 0;
  rows.forEach(function(r) {
    const match = !q || r.textContent.toLowerCase().includes(q);
    r.hidden = !match;
    if (match) visible++;
  });
  const total = rows.length;
  document.getElementById('events-count').textContent = q
    ? visible + ' of ' + total + ' events'
    : total + ' events';
}
</script>

</body>
</html>`
