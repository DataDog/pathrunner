# pathfinding.cloud/pathrunner — site integration brief

This is a self-contained implementation brief for building the **pathrunner reference
section** at `pathfinding.cloud/pathrunner`. It is written to be handed to an agent
or developer working **in the `pathfinding.cloud` repo**. You should not need any
other document from the pathrunner side.

- **Direction:** pathrunner produces artifacts and commits them to its own repo;
  pathfinding.cloud **pulls** them. This mirrors the existing labs pipeline
  (`generate-labs-json.py` already fetches from the `pathfinding-labs` repo) and
  preserves the one-directional, read-only dependency. Do **not** make the
  pathrunner repo depend on pathfinding.cloud.
- **End result:** a NetExec-wiki-style multi-page docs section (landing page with
  nav cards, grouped left sidebar, search, dedicated per-page routes). The
  individual command/module **entry** layout follows the cloudfox AWS-Commands
  wiki (metadata table + description + examples + text output + GIF).

---

## 1. The artifact (what pathrunner publishes)

Produced by the `cmd/gendocs` binary in the pathrunner repo (`make docs`) and
committed under `pathrunner/docs/reference/`:

```
docs/reference/
  pathrunner-reference.json     <- THE file to pull (commands + modules + payloads + counts)
  commands/<name>.md            <- human-readable per-command pages (optional to use)
  modules/<id>.md               <- human-readable per-module pages (optional to use)
  gifs/<name>.gif               <- rendered command GIFs (see §5)
```

Consume `pathrunner-reference.json` as the data source. The `.md` files are a
convenience/fallback; prefer rendering from the JSON so you control the markup.

### 1.1 JSON schema (`pathrunner-reference.json`)

The artifact carries a `generator.schemaVersion` (currently **`1.0.0`**); check it
and fail loudly on a major mismatch. Shape (Go source of truth:
`pathrunner/pkg/docs/reference.go`):

```jsonc
{
  "generator": {
    "schemaVersion": "1.0.0",
    "pathrunnerVersion": "0.2.3",
    "gitCommit": "abc1234",
    "generatedAt": ""               // usually empty (kept blank for reproducible builds)
  },
  "counts": { "commands": 25, "modules": 81, "payloads": 65, "services": 22 },

  "commands": [
    {
      "name": "attacker",
      "path": "pathrunner attacker",         // full invocation path
      "group": "core",                       // "core" | "module" | "" (subcommands)
      "short": "…", "long": "…",
      "usage": "pathrunner attacker [flags]",
      "aliases": ["…"],
      "flags": [
        { "name": "output", "shorthand": "o", "usage": "…", "default": "…", "type": "string" }
      ],
      "subcommands": [ { /* same Command shape, recursive */ } ]
    }
  ],

  "modules": [
    {
      "id": "lambda-001",                    // {service}-{NNN}; the cross-project join key
      "name": "iam:PassRole + lambda:CreateFunction",
      "description": "…",
      "category": "new-passrole",
      "services": ["iam", "lambda"],
      "primaryService": "iam",               // services[0]; use for sidebar grouping
      "aliases": ["lambda-passrole"],
      "author": "…",
      "pathfindingCloudUrl": "https://pathfinding.cloud/paths/lambda-001",
      "permissions": {
        "required":   [ { "permission": "iam:PassRole", "description": "on target role" } ],
        "additional": [ { "permission": "…", "description": "…" } ]
      },
      "prerequisites": { "admin": ["…"], "lateral": ["…"] },
      "references": [ { "title": "…", "url": "…" } ],
      "relatedPaths": ["lambda-002"],
      "mitre": { "tactics": ["…"], "techniques": ["…"] },
      "options":  [ { "name": "ROLE_ARN", "description": "…", "required": true, "default": "" } ],
      "payloads": [ { "name": "exfil/response", "description": "…" } ]
    }
  ],

  "payloads": [
    {
      "name": "exfil/response",
      "qualifiedName": "lambda:exfil/response",  // service:name; "" if service unknown
      "service": "lambda",                        // "" => group under "other"
      "description": "…",
      "tags": ["lambda", "python", "exfil"],
      "options": [ { "name": "…", "description": "…", "required": false, "default": "" } ]
    }
  ]
}
```

Notes:
- All list fields may be absent/empty — render defensively.
- `counts` are registry-derived and authoritative; use them for the landing page
  ("80+ modules") instead of hardcoding.
- `modules[].id` is the `{service}-{NNN}` key — the join to existing pages (see §4).

---

## 2. Pull mechanism (`scripts/generate-pathrunner-json.py`)

Model this on the existing `scripts/generate-labs-json.py` (same repo). It should:

1. Fetch `docs/reference/pathrunner-reference.json` from the `DataDog/pathrunner`
   repo via the GitHub API (raw content), with a `--source-dir ../pathrunner`
   local-clone fallback exactly like the labs script's `--source-dir`.
2. Also fetch the GIFs under `docs/reference/gifs/` (list the dir via the API, or
   copy from `--source-dir`).
3. Emit, under the site's `docs/` web root:
   - `docs/pathrunner.json` — a lightweight index (counts + command names +
     module ids/names/primaryService + payload names/services) for the landing
     page and sidebar/search, to avoid shipping the full detail on first paint.
   - `docs/pathrunner/data/<kind>/<id>.json` — per-entry detail lazily fetched by
     the page (e.g. `data/modules/lambda-001.json`, `data/commands/attacker.json`).
   - `docs/pathrunner/gifs/<name>.gif` — copied GIFs.
4. Be idempotent and safe to run in the deploy workflow.

Wire it into `.github/workflows/deploy.yml` as a build step **before** the Pages
upload (the workflow already uploads the whole `docs/` dir), alongside the existing
`generate-json.py` / `generate-labs-json.py` steps, and add a `Makefile` target
mirroring the labs one.

---

## 3. Frontend — NetExec-style multi-page section

The site is **hand-rolled static HTML served from `docs/`** (GitHub Pages, no SSG).
Shared chrome is copy-pasted per page; `docs/js/sidebar.js` already auto-activates
the sidebar item whose `href` is the longest prefix of the current path. **Do not
introduce a new SSG** — replicate the NetExec feel with the existing chrome + a JS
router, like `docs/labs/` does.

### 3.1 Files to create

- `docs/pathrunner/index.html` — the landing/welcome page. Reuse the exact shared
  chrome from an existing page (e.g. `docs/labs/index.html`): the `<head>` RUM/GTM/
  theme anti-flicker block, `<link rel="stylesheet" href="/css/style.css?v=NN">`,
  the `<header>` nav, the mobile menu, and the `<aside class="site-sidebar">`. Wrap
  content in `<div class="page-body"><main class="container">…`. Use the existing
  `--accent-purple` theme and the existing card styles (the labs landing uses a
  card grid — reuse it for NetExec-style nav cards: Getting Started, Commands,
  Exploit Modules, Payloads, Attacker Infrastructure, Integrations).
- `docs/js/pathrunner.js` — the SPA logic (see 3.3).
- Optionally `docs/css` additions scoped under a `.pathrunner-*` prefix if needed;
  prefer reusing existing classes.

### 3.2 Information architecture (sidebar groups)

- **Getting Started** — install, quick start, core concepts (identities,
  workspaces, attacker infra, the audit-log report). Prose; can be static HTML or
  driven from a small hand-authored JSON.
- **Commands** — one page per top-level command (from `commands[]`), subcommands
  rendered within the page. Group by the command's `group` field
  (`core` vs `module`).
- **Exploit Modules** — one page per module (from `modules[]`), grouped by
  `primaryService`. This is the large, searchable catalog.
- **Payloads** — grouped by `service` (empty service => "other").
- **Attacker Infrastructure / Integrations** — the `attacker`, `pmapper`,
  `cloudfox`/`resources` command pages, surfaced prominently.

### 3.3 Router + search (`docs/js/pathrunner.js`)

- On load, `fetch('/pathrunner.json')` for the index; build the grouped sidebar and
  a client-side search box (filter across command names, module id/name/services,
  payload names).
- Routes via `history.pushState`, e.g. `/pathrunner/commands/{name}`,
  `/pathrunner/modules/{id}`, `/pathrunner/payloads/{service}/{name}`. Parse the
  path on load and on `popstate` (copy the `routeFromURL()` pattern from
  `docs/js/labs.js`).
- Lazy-load per-entry detail from `/pathrunner/data/...` and render the
  **cloudfox-style entry**: a metadata table (ID, category, services, author,
  pathfinding.cloud link), the description, permissions, prerequisites, options
  table, compatible payloads, references, MITRE — then the example block + GIF
  (§5) when present.
- For crawler/unfurl friendliness, consider generating static stub pages per route
  the way `generate-lab-stubs.py` does for labs (optional for v1).

### 3.4 Chrome wiring

Add a **Pathrunner** entry to the shared header nav and a `sidebar-group` to the
copy-pasted sidebar block across pages (same edit applied to each page that carries
the chrome). `sidebar.js` handles active-state by href prefix, so no JS change is
needed for highlighting.

---

## 4. Deep-linking via `{service}-{NNN}`

Each module's `id` is the shared cross-project key. On a module page, link:

- **Path definition:** use `module.pathfindingCloudUrl` (already
  `https://pathfinding.cloud/paths/{id}`), or build the in-site route to
  `/paths/{id}`.
- **Lab:** link to `/labs/{slug}` when a matching lab exists. The lab slug is the
  pathfinding.cloud lab URL slug (see how `labs.json` / `generate-labs-json.py`
  derive slugs from `pathfinding-labs` scenario ids, e.g. `lambda-001-to-admin`
  → `lambda-001`). Cross-reference `module.id` against the already-built
  `labs.json` index to decide whether to show the lab link.

This ties the three surfaces (path ↔ lab ↔ automated module) together.

---

## 5. Examples & GIFs (what to expect in the artifacts)

Two kinds of command media are produced on the pathrunner side (see
`pathrunner/docs/reference/tapes/README.md`):

- **CI-safe GIFs** for AWS-free + local-state commands (help, modules list,
  payloads, search, identity list, attacker identity show), rendered from committed
  VHS tapes over synthetic fixtures. These arrive in `docs/reference/gifs/`.
- **Exploit / AWS-calling command output** is captured against a deployed lab and
  redacted (reusing `scripts/test-module.sh` + `pathfinding-labs/scripts/
  redact_transcripts.py`), so it is safe to publish. These may arrive as redacted
  text transcripts and/or GIFs.

Render a GIF when one exists for an entry (match by command/module name); otherwise
show the text example/usage from the JSON. Treat all example text as **already
redacted** — but do not assume every entry has a GIF.

---

## 6. Acceptance checklist

- [ ] `scripts/generate-pathrunner-json.py` fetches the reference (API + `--source-dir`
      fallback) and emits `docs/pathrunner.json` + `docs/pathrunner/data/**` + gifs.
- [ ] Wired into `deploy.yml` (before Pages upload) and a `Makefile` target.
- [ ] `docs/pathrunner/index.html` renders with the shared chrome, `--accent-purple`
      theme, NetExec-style nav cards, and a working search box.
- [ ] Grouped sidebar (Getting Started / Commands / Exploit Modules / Payloads /
      Attacker Infra / Integrations) with active-state via `sidebar.js`.
- [ ] Per-entry routes resolve and render cloudfox-style entries; module pages
      deep-link to `/paths/{id}` and (when present) `/labs/{slug}`.
- [ ] Counts on the landing page come from `counts`, not hardcoded.
- [ ] `schemaVersion` is checked.
- [ ] `make preview` (http://localhost:8888) shows `/pathrunner` end-to-end.
