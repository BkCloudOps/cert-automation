#!/usr/bin/env bash

set -uo pipefail

BASE_URL="${BASE_URL:-https://api.gitguardian.com/v1}"
PER_PAGE="${PER_PAGE:-100}"
DRY_RUN=false
INPUT_FILE=""
TARGET_ORG=""

# Counters
TOTAL=0
MATCHED=0
SKIPPED=0
FAILED=0
NO_MATCH=0
UPDATED=0

# Simple in-memory caches
LAST_SHA=""
LAST_OCCURRENCES='[]'

usage() {
  cat <<USAGE
Usage:
  $(basename "$0") --input-file <file.json> --target-org <org-prefix> [--dry-run]

Required:
  --input-file   JSON export file containing incidents.TRIGGERED / RESOLVED / IGNORED
  --target-org   Target org/repo prefix, e.g. mfc-ca/

Optional:
  --dry-run      Print actions only, do not call mutating endpoints
  --base-url     Override API base URL (default: ${BASE_URL})
  --per-page     Page size for occurrence lookup (default: ${PER_PAGE}, max 100)
USAGE
}

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

err() {
  printf 'ERROR: %s\n' "$*" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input-file)
      INPUT_FILE="$2"
      shift 2
      ;;
    --target-org)
      TARGET_ORG="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --base-url)
      BASE_URL="$2"
      shift 2
      ;;
    --per-page)
      PER_PAGE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      err "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$INPUT_FILE" || -z "$TARGET_ORG" ]]; then
  err "--input-file and --target-org are required"
  usage
  exit 1
fi

if [[ ! -f "$INPUT_FILE" ]]; then
  err "Input file not found: $INPUT_FILE"
  exit 1
fi

if ! [[ "$PER_PAGE" =~ ^[0-9]+$ ]] || (( PER_PAGE < 1 || PER_PAGE > 100 )); then
  err "--per-page must be an integer between 1 and 100"
  exit 1
fi

if [[ -z "${GG_TOKEN:-}" ]]; then
  err "GG_TOKEN is required"
  exit 1
fi

if [[ "$TARGET_ORG" != */ ]]; then
  TARGET_ORG="${TARGET_ORG}/"
fi

api_request() {
  local method="$1"
  local url="$2"
  local payload="${3:-}"
  local headers_file body_file status

  headers_file=$(mktemp)
  body_file=$(mktemp)

  if [[ -n "$payload" ]]; then
    status=$(curl -sS -D "$headers_file" -o "$body_file" -w '%{http_code}' \
      -H "Authorization: Token ${GG_TOKEN}" \
      -H "Accept: application/json" \
      -H "Content-Type: application/json" \
      -X "$method" "$url" \
      --data "$payload")
  else
    status=$(curl -sS -D "$headers_file" -o "$body_file" -w '%{http_code}' \
      -H "Authorization: Token ${GG_TOKEN}" \
      -H "Accept: application/json" \
      -X "$method" "$url")
  fi

  API_STATUS="$status"
  API_HEADERS=$(cat "$headers_file")
  API_BODY=$(cat "$body_file")

  rm -f "$headers_file" "$body_file"

  if [[ ! "$API_STATUS" =~ ^[0-9]{3}$ ]]; then
    err "Invalid HTTP status received for ${method} ${url}: ${API_STATUS}"
    return 1
  fi

  if (( API_STATUS < 200 || API_STATUS >= 300 )); then
    return 1
  fi

  return 0
}

api_get_json() {
  local url="$1"
  if ! api_request GET "$url"; then
    return 1
  fi
  if ! echo "$API_BODY" | jq -e . >/dev/null 2>&1; then
    err "Response was not valid JSON for GET ${url}"
    return 1
  fi
  return 0
}

api_post_json() {
  local url="$1"
  local payload="$2"
  if ! api_request POST "$url" "$payload"; then
    return 1
  fi
  if ! echo "$API_BODY" | jq -e . >/dev/null 2>&1; then
    err "Response was not valid JSON for POST ${url}"
    return 1
  fi
  return 0
}

extract_error_detail() {
  local body="$1"
  local detail=""
  detail=$(echo "$body" | jq -r '
    if type == "object" then
      .detail // .message // (.errors // empty | tostring) // empty
    else
      empty
    end
  ' 2>/dev/null)
  printf '%s' "$detail"
}

normalize_ignore_reason() {
  local raw="${1:-}"
  case "$raw" in
    test_credential|false_positive|low_risk|invalid)
      printf '%s' "$raw"
      return 0
      ;;
    "")
      return 1
      ;;
    *)
      return 1
      ;;
  esac
}

get_incident_detail() {
  local incident_id="$1"
  local url="${BASE_URL}/incidents/secrets/${incident_id}"

  if ! api_get_json "$url"; then
    local detail
    detail=$(extract_error_detail "$API_BODY")
    err "Failed to fetch incident ${incident_id} (HTTP ${API_STATUS})${detail:+: ${detail}}"
    return 1
  fi

  printf '%s' "$API_BODY"
}

reopen_incident() {
  local incident_id="$1"
  local url="${BASE_URL}/incidents/secrets/${incident_id}/reopen"

  if ! api_post_json "$url" ""; then
    local detail
    detail=$(extract_error_detail "$API_BODY")
    err "Failed to reopen incident ${incident_id} (HTTP ${API_STATUS})${detail:+: ${detail}}"
    return 1
  fi

  log "    Reopened successfully."
  return 0
}

resolve_incident() {
  local incident_id="$1"
  local secret_revoked="$2"
  local payload url

  payload=$(jq -nc --argjson secret_revoked "$secret_revoked" '{secret_revoked: $secret_revoked}')
  url="${BASE_URL}/incidents/secrets/${incident_id}/resolve"

  if ! api_post_json "$url" "$payload"; then
    local detail
    detail=$(extract_error_detail "$API_BODY")
    err "Failed to resolve incident ${incident_id} (HTTP ${API_STATUS})${detail:+: ${detail}}"
    return 1
  fi

  log "    Result: $(echo "$API_BODY" | jq -r '.status // "UNKNOWN"')"
  return 0
}

ignore_incident() {
  local incident_id="$1"
  local ignore_reason="$2"
  local payload url

  payload=$(jq -nc --arg ignore_reason "$ignore_reason" '{ignore_reason: $ignore_reason}')
  url="${BASE_URL}/incidents/secrets/${incident_id}/ignore"

  if ! api_post_json "$url" "$payload"; then
    local detail
    detail=$(extract_error_detail "$API_BODY")
    err "Failed to ignore incident ${incident_id} (HTTP ${API_STATUS})${detail:+: ${detail}}"
    return 1
  fi

  log "    Result: $(echo "$API_BODY" | jq -r '.status // "UNKNOWN"')"
  return 0
}

get_target_occurrences() {
  local sha="$1"
  local page=1
  local first=1
  local all='[]'
  local url count page_json filtered

  if [[ "$sha" == "$LAST_SHA" ]]; then
    printf '%s' "$LAST_OCCURRENCES"
    return 0
  fi

  while :; do
    url="${BASE_URL}/occurrences/secrets?sha=${sha}&per_page=${PER_PAGE}&page=${page}"

    if ! api_get_json "$url"; then
      local detail
      detail=$(extract_error_detail "$API_BODY")
      err "Failed to list occurrences for SHA ${sha} (HTTP ${API_STATUS})${detail:+: ${detail}}"
      return 1
    fi

    page_json="$API_BODY"

    if ! echo "$page_json" | jq -e 'type == "array"' >/dev/null 2>&1; then
      err "Occurrences response for SHA ${sha} was not an array"
      return 1
    fi

    filtered=$(echo "$page_json" | jq -c --arg org "$TARGET_ORG" '[.[] | select((.source.full_name // "") | startswith($org))]')
    all=$(jq -cn --argjson a "$all" --argjson b "$filtered" '$a + $b')

    count=$(echo "$page_json" | jq 'length')
    if (( count < PER_PAGE )); then
      break
    fi

    ((page++))
  done

  LAST_SHA="$sha"
  LAST_OCCURRENCES="$all"
  printf '%s' "$all"
  return 0
}

find_target_match() {
  local occurrences_json="$1"
  local filepath="$2"
  local detector="$3"
  local candidate_ids count cid target_detector

  candidate_ids=$(echo "$occurrences_json" | jq -r --arg fp "$filepath" '
    [.[] | select(.filepath == $fp) | .incident_id] | unique | .[]
  ')

  if [[ -z "$candidate_ids" ]]; then
    return 1
  fi

  count=$(printf '%s\n' "$candidate_ids" | sed '/^$/d' | wc -l | tr -d ' ')
  if [[ "$count" -eq 1 ]]; then
    printf '%s' "$candidate_ids"
    return 0
  fi

  while IFS= read -r cid; do
    [[ -z "$cid" ]] && continue
    if ! target_detector=$(get_incident_detail "$cid" | jq -r '.detector.name // "unknown"' 2>/dev/null); then
      continue
    fi
    if [[ "$target_detector" == "$detector" ]]; then
      printf '%s' "$cid"
      return 0
    fi
  done <<< "$candidate_ids"

  return 1
}

process_entry() {
  local entry="$1"
  local sha filepath desired_status detector revoked ignore_reason src_id occurrences target_match
  local target_detail current_status current_ignore_reason normalized_ignore_reason

  ((TOTAL+=1))

  sha=$(echo "$entry" | jq -r '.sha')
  filepath=$(echo "$entry" | jq -r '.filepath // "N/A"')
  desired_status=$(echo "$entry" | jq -r '.status')
  detector=$(echo "$entry" | jq -r '.detector // "unknown"')
  revoked=$(echo "$entry" | jq -r '.secret_revoked // false')
  ignore_reason=$(echo "$entry" | jq -r '.ignore_reason // empty')
  src_id=$(echo "$entry" | jq -r '.id')

  if [[ "$desired_status" == "IGNORED" ]]; then
    if ! normalized_ignore_reason=$(normalize_ignore_reason "$ignore_reason"); then
      ((FAILED+=1))
      err "[IGNORED] Source #${src_id} SHA: ${sha} File: ${filepath} -> invalid ignore_reason: ${ignore_reason:-<empty>}"
      return 0
    fi
    ignore_reason="$normalized_ignore_reason"
  fi

  if ! occurrences=$(get_target_occurrences "$sha"); then
    ((FAILED+=1))
    err "[${desired_status}] Source #${src_id} SHA: ${sha} File: ${filepath} -> could not fetch target occurrences"
    return 0
  fi

  if ! target_match=$(find_target_match "$occurrences" "$filepath" "$detector"); then
    ((NO_MATCH+=1))
    log "  [${desired_status}] SHA: ${sha}  File: ${filepath}  Detector: ${detector}  -> No match in ${TARGET_ORG}"
    return 0
  fi

  ((MATCHED+=1))

  if [[ "$DRY_RUN" == true ]]; then
    case "$desired_status" in
      RESOLVED)
        log "  [RESOLVED] SHA: ${sha}  File: ${filepath}"
        log "    Source: #${src_id}  Target: #${target_match}  -> [DRY RUN] Would resolve (secret_revoked: ${revoked})"
        ;;
      IGNORED)
        log "  [IGNORED] SHA: ${sha}  File: ${filepath}"
        log "    Source: #${src_id}  Target: #${target_match}  -> [DRY RUN] Would ignore (reason: ${ignore_reason})"
        ;;
      TRIGGERED)
        log "  [TRIGGERED] SHA: ${sha}  File: ${filepath}"
        log "    Source: #${src_id}  Target: #${target_match}  -> [DRY RUN] Would reopen to TRIGGERED"
        ;;
      *)
        ((FAILED+=1))
        err "Unknown desired status for source #${src_id}: ${desired_status}"
        ;;
    esac
    return 0
  fi

  if ! target_detail=$(get_incident_detail "$target_match"); then
    ((FAILED+=1))
    err "  [${desired_status}] SHA: ${sha}  File: ${filepath}  -> failed to retrieve target incident ${target_match}"
    return 0
  fi

  current_status=$(echo "$target_detail" | jq -r '.status // "UNKNOWN"')
  current_ignore_reason=$(echo "$target_detail" | jq -r '.ignore_reason // empty')

  log "  [${desired_status}] SHA: ${sha}  File: ${filepath}"
  log "    Source: #${src_id}  Target: #${target_match}  Current: ${current_status}  -> Desired: ${desired_status}"

  if [[ "$current_status" == "$desired_status" ]]; then
    if [[ "$desired_status" == "IGNORED" && "$current_ignore_reason" != "$ignore_reason" ]]; then
      log "    Status matches but ignore_reason differs (${current_ignore_reason:-none} != ${ignore_reason}) — re-applying..."
    else
      ((SKIPPED+=1))
      log "    Already ${desired_status} — skipping."
      return 0
    fi
  fi

  if [[ "$current_status" != "TRIGGERED" && "$desired_status" != "TRIGGERED" ]]; then
    log "    Status mismatch (${current_status} != ${desired_status}) — reopening first..."
    if ! reopen_incident "$target_match"; then
      ((FAILED+=1))
      err "    Failed to reopen incident ${target_match}; continuing."
      return 0
    fi
  fi

  case "$desired_status" in
    TRIGGERED)
      log "    Reopening to TRIGGERED..."
      if reopen_incident "$target_match"; then
        ((UPDATED+=1))
        log "    Result: TRIGGERED"
      else
        ((FAILED+=1))
        err "    Failed to reopen incident ${target_match}; continuing."
      fi
      ;;
    RESOLVED)
      log "    Resolving (secret_revoked: ${revoked})."
      if resolve_incident "$target_match" "$revoked"; then
        ((UPDATED+=1))
      else
        ((FAILED+=1))
        err "    Failed to resolve incident ${target_match}; continuing."
      fi
      ;;
    IGNORED)
      log "    Ignoring (reason: ${ignore_reason})."
      if ignore_incident "$target_match" "$ignore_reason"; then
        ((UPDATED+=1))
      else
        ((FAILED+=1))
        err "    Failed to ignore incident ${target_match}; continuing."
      fi
      ;;
    *)
      ((FAILED+=1))
      err "    Unsupported desired status: ${desired_status}"
      ;;
  esac
}

log "=== Processing ALL incidents - Matching by SHA + filepath ==="

if ! jq -e . "$INPUT_FILE" >/dev/null 2>&1; then
  err "Input file is not valid JSON: $INPUT_FILE"
  exit 1
fi

FOUND_ANY=0
while IFS= read -r entry; do
  FOUND_ANY=1
  process_entry "$entry"
done < <(jq -c '(.incidents.TRIGGERED[]?), (.incidents.RESOLVED[]?), (.incidents.IGNORED[]?)' "$INPUT_FILE")

if [[ "$FOUND_ANY" -eq 0 ]]; then
  log "  (none)"
fi

log ""
log "=== Summary ==="
log "Total processed : ${TOTAL}"
log "Matched         : ${MATCHED}"
log "Updated         : ${UPDATED}"
log "Skipped         : ${SKIPPED}"
log "No match        : ${NO_MATCH}"
log "Failed          : ${FAILED}"

if (( FAILED > 0 )); then
  exit 2
fi

exit 0
