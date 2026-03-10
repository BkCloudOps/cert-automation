# GitGuardian Suppression Migration

Migrate secret incident statuses (resolved / ignored) from a source GitGuardian org to a target org. Incidents are matched across orgs by **commit SHA + filepath + detector name**, then the source status is applied to the target — so if a secret was resolved or ignored in the source, the matching incident in the target is updated accordingly.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Workflow — Issue-Driven](#workflow--issue-driven)
- [Scripts](#scripts)
- [GitHub Actions Workflows](#github-actions-workflows)
- [Scenarios Tested](#scenarios-tested)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Running Locally](#running-locally)

---

## How It Works

The utility operates in **three phases**, orchestrated via GitHub Issues and slash commands:

```
┌─────────────────────────────────────────────────────────────────┐
│  1. Create Issue (Migration Request template)                   │
│     ↓ auto-labels: gitguardian, migration                       │
│  2. Bot posts slash-command instructions                        │
│     ↓                                                           │
│  3. /export-incidents  →  dispatches export per repo            │
│     ↓                     commits JSON to output/<org>/<repo>   │
│  4. /migrate-incidents →  dry-run migration per repo            │
│     ↓                     matches by SHA + filepath + detector  │
│  5. /migrate-incidents --apply →  applies changes               │
│     ↓                     verifies results, queues cleanup      │
│  6. Scheduled cleanup  →  deletes output files weekly           │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 1 — Export Incidents

1. Looks up the GitGuardian **source ID** for the given `org/repo`.
2. Fetches all secret incidents for that source (paginated, 100 per page).
3. Retrieves the commit SHA and filepath for each incident via the occurrences API.
4. Outputs a JSON file to `output/<org>/<repo>.json` with incidents grouped by status (`TRIGGERED`, `RESOLVED`, `IGNORED`) and a summary.

### Phase 2 — Migrate Incidents

1. Reads the exported JSON from Phase 1.
2. For each incident, searches for matching occurrences in the **target org** by SHA.
3. Matches by filepath and detector name to find the correct target incident.
4. Applies the source status to the target:
   - **RESOLVED** → resolves the target incident (with `secret_revoked` flag preserved)
   - **IGNORED** → ignores the target incident (with the original `ignore_reason`)
   - **TRIGGERED** → reopens the target incident if it was previously resolved/ignored
5. If the target incident is already in the desired state, it is skipped.
6. Supports `--dry-run` to preview all matches and actions without modifying anything.
7. After a successful apply run, re-exports target incidents and verifies the migration (PASS / WARN / FAIL per repo).
8. Adds migrated files to `output/cleanup-queue.json` for scheduled deletion.

### Phase 3 — Scheduled Cleanup

1. Runs every **Saturday at 11 PM UTC** (also supports manual trigger).
2. Reads `output/cleanup-queue.json`, deletes queued output files and empty org directories.
3. Resets the queue and commits.

---

## Architecture

```
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   └── migration-request.yml        # Issue form for new migration requests
│   └── workflows/
│       ├── issue-opened.yaml            # Auto-posts slash-command instructions
│       ├── slash-export-incidents.yaml   # /export-incidents slash command handler
│       ├── slash-migrate-incidents.yaml  # /migrate-incidents slash command handler
│       ├── export-incidents.yaml         # Single-repo export workflow
│       ├── bulk-export.yaml              # Multi-repo export workflow
│       ├── migrate-incidents.yaml        # Migration workflow (dry-run + apply)
│       └── cleanup-output.yaml           # Scheduled cleanup of output files
├── scripts/
│   ├── export-incidents.sh              # Export script — fetches incidents from GG API
│   └── migrate-suppresion.sh            # Migration script — matches and applies statuses
└── output/
    ├── <org>/
    │   └── <repo>.json                  # Exported incident data
    └── cleanup-queue.json               # Queue of files pending cleanup
```

---

## Workflow — Issue-Driven

### Step 1: Create a Migration Request

Go to **Issues → New Issue → Suppression Migration Request** and fill in:

| Field | Description | Example |
|-------|-------------|---------|
| **Source Org** | GitHub org owning the source repo in GitGuardian | `manulife-ets-sandbox` |
| **Source Repo(s)** | One per line or comma-separated | `repo-one`<br>`repo-two` |
| **Target Org** | Target org to migrate suppressions into | `mfc-ca` |
| **Priority** | Low / Medium / High | `Medium` |
| **Pre-flight Checklist** | Confirm source exists, target onboarded, target scanned | ✅ ✅ ✅ |

The issue is auto-labeled `gitguardian` + `migration`, which triggers a bot comment with instructions.

### Step 2: Export Incidents

Comment on the issue:

```
/export-incidents
```

This dispatches an **Export Incidents** workflow run for each repo listed in the issue. A comment is posted with links to each run.

### Step 3: Dry-Run Migration

Comment on the issue:

```
/migrate-incidents
```

This dispatches a **Migrate Incidents** workflow in **dry-run mode** for each repo. No changes are made — the run logs show what _would_ happen: matches found, statuses that would be applied, and any repos with no matches.

### Step 4: Apply Migration

If the dry-run looks good, comment:

```
/migrate-incidents --apply
```

This runs the actual migration. For each repo, the workflow:
1. Applies status changes via the GitGuardian API
2. Re-exports target incidents to verify the migration
3. Reports PASS / WARN / FAIL per repo
4. Queues the output file for cleanup

---

## Scripts

### `scripts/export-incidents.sh`

Exports GitGuardian incidents for a single org/repo to JSON.

```
Usage: ./export-incidents.sh <org> <repo>
```

**Features:**
- Paginated source lookup and incident fetching (100 per page)
- URL-encoded search queries
- HTTP status code validation on every API call
- JSON response validation
- Rate limiting with configurable delay (`API_DELAY`, default 0.5s)
- Progress indicator (`[N/TOTAL]` per incident)
- Consolidated jq processing for efficiency
- Handles `secret_revoked` as proper JSON boolean
- Outputs consistent schema even when no incidents found

**Environment variables:**

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GG_TOKEN` | Yes | — | GitGuardian API token |
| `GG_BASE_URL` | No | `https://api.gitguardian.com/v1` | API base URL |
| `API_DELAY` | No | `0.5` | Seconds between API calls |

### `scripts/migrate-suppresion.sh`

Migrates incident statuses from a source export to the target org.

```
Usage: ./migrate-suppresion.sh --input-file <file.json> --target-org <org> [--dry-run]
```

**Features:**
- Matches incidents by SHA + filepath + detector name
- Supports all three status transitions: RESOLVED, IGNORED, TRIGGERED
- Preserves `secret_revoked` flag and `ignore_reason` (validated against allowed values)
- Dry-run mode for safe preview
- Handles status conflicts (e.g., target is RESOLVED but source is IGNORED — reopens first, then ignores)
- Paginated occurrence lookup with in-memory SHA cache
- Rate limiting with configurable delay (`API_DELAY`, default 0.5s)
- Detailed error extraction from API responses
- Summary counters: Total / Matched / Updated / Skipped / No Match / Failed

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Success (all processed, no failures) |
| `1` | Configuration error (missing args, bad input file, no token) |
| `2` | Partial failure (some incidents failed to migrate) |

**Environment variables:**

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GG_TOKEN` | Yes | — | GitGuardian API token |
| `BASE_URL` | No | `https://api.gitguardian.com/v1` | API base URL |
| `PER_PAGE` | No | `100` | Page size for occurrence lookup (max 100) |
| `API_DELAY` | No | `0.5` | Seconds between API calls |

---

## GitHub Actions Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| **Export Incidents** | `workflow_dispatch` | Exports incidents for a single org/repo, commits output |
| **Bulk Export Incidents** | `workflow_dispatch` | Exports incidents for multiple repos (comma-separated), commits outputs |
| **Bulk Migrate Incidents v2** | `workflow_dispatch` | Migrates one or more repos with dry-run/apply, verifies, tracks cleanup |
| **Cleanup Output** | Schedule (Sat 11 PM UTC) + manual | Deletes completed output files, resets cleanup queue |
| **Issue Opened** | Issue labeled `migration` | Posts slash-command instructions as a comment |
| **Slash — Export** | `/export-incidents` comment | Parses issue, dispatches export per repo, posts run links |
| **Slash — Migrate** | `/migrate-incidents` comment | Parses issue, dispatches migration per repo, posts run links |

All workflows run on self-hosted runners: `[self-hosted, linux, ubuntu-22.04, provisioning-essentials, prod]`

---

## Scenarios Tested

### Export

| Scenario | Result |
|----------|--------|
| Single repo with incidents (TRIGGERED, RESOLVED, IGNORED) | ✅ Exports all incidents grouped by status with SHA, filepath, detector, secret_revoked, ignore_reason |
| Repo with no incidents | ✅ Outputs valid JSON with empty arrays and `total: 0` |
| Repo not found in GitGuardian | ✅ Exits with error "No source found" |
| Large repo with 100+ incidents (pagination) | ✅ Paginates correctly across multiple pages |
| Multi-repo export via slash command | ✅ Dispatches one workflow run per repo |
| Special characters in repo name | ✅ URL-encoded via `jq @uri` |
| API returns non-2xx HTTP status | ✅ Fails with descriptive error message |
| API returns non-JSON response | ✅ Fails with validation error |

### Migration

| Scenario | Result |
|----------|--------|
| Dry-run — matches found | ✅ Logs what would be resolved/ignored/reopened, no API mutations |
| Apply — RESOLVED incidents | ✅ Resolves target incidents with `secret_revoked` flag preserved |
| Apply — IGNORED incidents | ✅ Ignores target with correct `ignore_reason` (test_credential, false_positive, low_risk, invalid) |
| Apply — TRIGGERED incidents | ✅ Reopens target incidents to TRIGGERED |
| Target already in desired status | ✅ Skipped (no redundant API call) |
| Target in different non-TRIGGERED status (e.g., RESOLVED→IGNORED) | ✅ Reopens first, then applies desired status |
| IGNORED with invalid/empty ignore_reason | ✅ Fails with descriptive error, counted as FAILED |
| No matching SHA in target org | ✅ Counted as NO_MATCH, logged |
| Multiple occurrences with same SHA | ✅ Disambiguates by filepath, then by detector name |
| Multi-repo migration via slash command | ✅ Dispatches one workflow run per repo |
| Post-migration verification (apply mode) | ✅ Re-exports target, diffs statuses, reports PASS/WARN/FAIL |
| Output files queued for cleanup after successful apply | ✅ Added to cleanup-queue.json with timestamp |

### Slash Commands

| Scenario | Result |
|----------|--------|
| `/export-incidents` on labeled issue | ✅ Parses org + repos from issue body, dispatches exports, posts run links |
| `/migrate-incidents` (dry-run) | ✅ Dispatches dry-run migration per repo, posts links |
| `/migrate-incidents --apply` | ✅ Dispatches apply migration per repo, posts links |
| Comment on issue without required labels | ✅ Skipped (guard condition not met) |
| Issue body with `\r\n` line endings | ✅ Normalized before parsing |
| Multiple repos (newline or comma-separated) | ✅ Parsed correctly |

---

## Prerequisites

- **GitGuardian API token** (`GG_TOKEN`) with permissions:
  - `incidents:read` — fetch incident data
  - `incidents:write` — resolve, ignore, reopen incidents
  - `sources:read` — look up source IDs
  - `scan:read` — query occurrences by SHA
- **GitHub PAT** (`REPO_PAT`) with permissions:
  - `actions:write` — dispatch workflows
  - `contents:write` — commit output files
  - `issues:write` — post comments
- **Tools** (pre-installed on runners): `jq`, `curl`, `bash`

---

## Configuration

| Secret | Where Used | Purpose |
|--------|-----------|---------|
| `GG_TOKEN` | Export + migrate scripts | GitGuardian API authentication |
| `REPO_PAT` | All workflows | GitHub API (dispatch, commit, comment) |

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `GG_BASE_URL` | `https://api.gitguardian.com/v1` | GitGuardian API base (export script) |
| `BASE_URL` | `https://api.gitguardian.com/v1` | GitGuardian API base (migrate script) |
| `API_DELAY` | `0.5` | Seconds between API calls (both scripts) |
| `PER_PAGE` | `100` | Page size for occurrence queries (migrate script) |

---

## Running Locally

```bash
export GG_TOKEN="your-gitguardian-api-token"

# Phase 1: Export incidents for a single repo
./scripts/export-incidents.sh my-source-org my-repo > output/my-source-org/my-repo.json

# Phase 2: Dry-run migration
./scripts/migrate-suppresion.sh \
  --input-file output/my-source-org/my-repo.json \
  --target-org my-target-org \
  --dry-run

# Phase 2: Apply migration
./scripts/migrate-suppresion.sh \
  --input-file output/my-source-org/my-repo.json \
  --target-org my-target-org
```

> **Tip:** Always run with `--dry-run` first to verify matches before applying changes.

For the **EU region**, set the base URL:

```bash
export GG_BASE_URL="https://api.eu1.gitguardian.com/v1"
```

## Output Format

The exported JSON has the following structure:

```json
{
  "source": "org/repo",
  "source_id": 12345,
  "total": 6,
  "incidents": {
    "TRIGGERED": [{ "id": 111, "sha": "abc123...", "status": "TRIGGERED", "secret_revoked": false }],
    "RESOLVED":  [{ "id": 222, "sha": "def456...", "status": "RESOLVED", "secret_revoked": true }],
    "IGNORED":   [{ "id": 333, "sha": "789ghi...", "status": "IGNORED", "secret_revoked": false, "ignore_reason": "test_credential" }]
  },
  "summary": {
    "open": 3,
    "resolved": 2,
    "ignored": 1
  }
}
```

## Project Structure

```
├── .github/workflows/
│   ├── export-incidents.yml    # Workflow to export incidents from source org
│   ├── migrate-incidents.yml   # Workflow to migrate statuses to target org
│   └── cleanup-output.yml      # Cron job to delete migrated output files
├── scripts/
│   ├── get_source_id.sh        # Exports incidents + SHAs for a repo
│   └── find_sha_dupes.sh       # Finds SHA matches in target org and migrates status
├── output/                     # Exported incident JSON files (committed by workflow)
│   └── cleanup-queue.json      # Tracks files pending deletion (auto-managed)
└── README.md
```

## API Reference

All API calls use the base URL `https://api.gitguardian.com/v1` (override with `GG_BASE_URL` for EU region).

### 1. Look up source ID by repo name

```bash
curl -s -H "Authorization: Token $GG_TOKEN" \
     -H "Accept: application/json" \
     "https://api.gitguardian.com/v1/sources?per_page=100&search=my-repo"
```

Returns an array of sources. Filter by `.full_name` to get the matching source ID.

### 2. List incidents for a source

```bash
curl -s -H "Authorization: Token $GG_TOKEN" \
     -H "Accept: application/json" \
     "https://api.gitguardian.com/v1/sources/{source_id}/incidents/secrets?per_page=100"
```

Returns all secret incidents for the given source, including `status`, `secret_revoked`, and `ignore_reason`.

### 3. Get occurrence (commit SHA) for an incident

```bash
curl -s -H "Authorization: Token $GG_TOKEN" \
     -H "Accept: application/json" \
     "https://api.gitguardian.com/v1/occurrences/secrets?incident_id={incident_id}&per_page=1"
```

Returns occurrences for the incident. The `.sha` field contains the commit SHA.

### 4. Search occurrences by SHA (find matching incidents in target org)

```bash
curl -s -H "Authorization: Token $GG_TOKEN" \
     -H "Accept: application/json" \
     "https://api.gitguardian.com/v1/occurrences/secrets?sha={commit_sha}&per_page=100"
```

Returns all occurrences matching the SHA. Filter by `.source.full_name` to find matches in the target org. Each occurrence includes an `incident_id`.

### 5. Get incident status

```bash
curl -s -H "Authorization: Token $GG_TOKEN" \
     -H "Accept: application/json" \
     "https://api.gitguardian.com/v1/incidents/secrets/{incident_id}" | jq '.status'
```

Returns the full incident details. Use `.status` to check current state.

### 6. Resolve an incident

```bash
curl -s -H "Authorization: Token $GG_TOKEN" \
     -H "Accept: application/json" \
     -H "Content-Type: application/json" \
     -X POST "https://api.gitguardian.com/v1/incidents/secrets/{incident_id}/resolve" \
     -d '{"secret_revoked": false}'
```

`secret_revoked` is required (`true` or `false`). Returns the updated incident or `{"detail": "Incident is already resolved."}` if already resolved.

### 7. Ignore an incident

```bash
curl -s -H "Authorization: Token $GG_TOKEN" \
     -H "Accept: application/json" \
     -H "Content-Type: application/json" \
     -X POST "https://api.gitguardian.com/v1/incidents/secrets/{incident_id}/ignore" \
     -d '{"secret_revoked": false, "ignore_reason": "test_credential"}'
```

`secret_revoked` is required. `ignore_reason` accepts: `test_credential`, `low_risk`, `false_positive`, `invalid_secret`. Returns the updated incident or `{"detail": "Incident is already ignored."}` if already ignored.
