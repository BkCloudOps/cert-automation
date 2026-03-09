#!/bin/bash
# Usage: ./find_sha_dupes.sh <output.json> <target_org> [--dry-run]
# Reads incident data from the JSON output file.
# For each incident, finds the matching target incident
# by SHA + filepath and applies the exact source status
# (TRIGGERED, RESOLVED, or IGNORED).
# Use --dry-run to preview without making changes.
# Requires: GG_TOKEN environment variable set

INPUT_FILE="${1:?Usage: $0 <output.json> <target_org> [--dry-run]}"
TARGET_ORG="${2:?Usage: $0 <output.json> <target_org> [--dry-run]}"
DRY_RUN=false
if [ "${3}" = "--dry-run" ]; then
  DRY_RUN=true
fi
BASE_URL="${GG_BASE_URL:-https://api.gitguardian.com/v1}"

if [ ! -f "$INPUT_FILE" ]; then
  echo "Error: File not found: ${INPUT_FILE}"
  exit 1
fi

echo "Source: $(jq -r '.source' "$INPUT_FILE")"
if [ "$DRY_RUN" = true ]; then
  echo "Mode: DRY RUN (no changes will be made)"
fi
echo "Checking ${TARGET_ORG} for matching SHAs..."
echo ""

# Function to get current status of a target incident
get_incident_detail() {
  local INC_ID="$1"
  curl -s -H "Authorization: Token $GG_TOKEN" \
       -H "Accept: application/json" \
       "${BASE_URL}/incidents/secrets/${INC_ID}"
}

# Function to reopen an incident
reopen_incident() {
  local INC_ID="$1"
  local RESP
  RESP=$(curl -s -H "Authorization: Token $GG_TOKEN" \
       -H "Accept: application/json" \
       -H "Content-Type: application/json" \
       -X POST "${BASE_URL}/incidents/secrets/${INC_ID}/reopen")
  local DETAIL
  DETAIL=$(echo "$RESP" | jq -r '.detail // empty')
  if [ -n "$DETAIL" ]; then
    echo "    Reopen error: ${DETAIL}"
    return 1
  fi
  echo "    Reopened successfully."
  return 0
}

# Cache for SHA lookups to avoid repeated API calls for the same SHA
LAST_SHA=""
LAST_OCCURRENCES=""

# Function to get all target occurrences for a SHA (with caching)
get_target_occurrences() {
  local SHA="$1"
  if [ "$SHA" = "$LAST_SHA" ]; then
    echo "$LAST_OCCURRENCES"
    return
  fi
  LAST_SHA="$SHA"
  LAST_OCCURRENCES=$(curl -s -H "Authorization: Token $GG_TOKEN" \
       -H "Accept: application/json" \
       "${BASE_URL}/occurrences/secrets?sha=${SHA}&per_page=100" \
    | jq -r --arg org "$TARGET_ORG" \
      '[.[] | select(.source.full_name // "" | startswith($org))]')
  echo "$LAST_OCCURRENCES"
}

echo "=== Processing ALL incidents - Matching by SHA + filepath ==="

# Process all incidents (TRIGGERED, RESOLVED, IGNORED), matching each to its specific target
ALL_ACTIONABLE=$(jq -c '(.incidents.TRIGGERED[] // empty), (.incidents.RESOLVED[] // empty), (.incidents.IGNORED[] // empty)' "$INPUT_FILE" 2>/dev/null)
if [ -z "$ALL_ACTIONABLE" ]; then
  echo "  (none)"
else
  while IFS= read -r entry; do
    SHA=$(echo "$entry" | jq -r '.sha')
    FILEPATH=$(echo "$entry" | jq -r '.filepath // "N/A"')
    DESIRED_STATUS=$(echo "$entry" | jq -r '.status')
    DETECTOR=$(echo "$entry" | jq -r '.detector // "unknown"')
    REVOKED=$(echo "$entry" | jq -r '.secret_revoked // false')
    IGNORE_REASON=$(echo "$entry" | jq -r '.ignore_reason // empty')
    SRC_ID=$(echo "$entry" | jq -r '.id')

    # Find target incidents matching this SHA + filepath
    OCCURRENCES=$(get_target_occurrences "$SHA")
    CANDIDATE_IDS=$(echo "$OCCURRENCES" | jq -r --arg fp "$FILEPATH" \
      '[.[] | select(.filepath == $fp) | .incident_id] | unique | .[]')

    if [ -z "$CANDIDATE_IDS" ]; then
      echo "  [${DESIRED_STATUS}] SHA: ${SHA}  File: ${FILEPATH}  -> No match in ${TARGET_ORG}"
      continue
    fi

    # If multiple candidates for same filepath, match by detector name
    TARGET_MATCH=""
    CANDIDATE_COUNT=$(echo "$CANDIDATE_IDS" | wc -l | tr -d ' ')
    if [ "$CANDIDATE_COUNT" -eq 1 ]; then
      TARGET_MATCH="$CANDIDATE_IDS"
    else
      # Multiple incidents on same filepath — match by detector
      for CID in $CANDIDATE_IDS; do
        TARGET_DETECTOR=$(curl -s -H "Authorization: Token $GG_TOKEN" \
             -H "Accept: application/json" \
             "${BASE_URL}/incidents/secrets/${CID}" \
          | jq -r '.detector.name // "unknown"')
        if [ "$TARGET_DETECTOR" = "$DETECTOR" ]; then
          TARGET_MATCH="$CID"
          break
        fi
      done
    fi

    if [ -z "$TARGET_MATCH" ]; then
      echo "  [${DESIRED_STATUS}] SHA: ${SHA}  File: ${FILEPATH}  Detector: ${DETECTOR}  -> No detector match in ${TARGET_ORG}"
      continue
    fi

    if [ "$DRY_RUN" = true ]; then
      if [ "$DESIRED_STATUS" = "RESOLVED" ]; then
        echo "  [RESOLVED] SHA: ${SHA}  File: ${FILEPATH}"
        echo "    Source: #${SRC_ID}  Target: #${TARGET_MATCH}  -> [DRY RUN] Would resolve (secret_revoked: ${REVOKED})"
      elif [ "$DESIRED_STATUS" = "IGNORED" ]; then
        echo "  [IGNORED] SHA: ${SHA}  File: ${FILEPATH}"
        echo "    Source: #${SRC_ID}  Target: #${TARGET_MATCH}  -> [DRY RUN] Would ignore (secret_revoked: ${REVOKED}, reason: ${IGNORE_REASON:-none})"
      else
        echo "  [TRIGGERED] SHA: ${SHA}  File: ${FILEPATH}"
        echo "    Source: #${SRC_ID}  Target: #${TARGET_MATCH}  -> [DRY RUN] Would reopen to TRIGGERED"
      fi
      continue
    fi

    # Check current status of target incident
    TARGET_DETAIL=$(get_incident_detail "$TARGET_MATCH")
    CURRENT_STATUS=$(echo "$TARGET_DETAIL" | jq -r '.status // "UNKNOWN"')
    CURRENT_IGNORE_REASON=$(echo "$TARGET_DETAIL" | jq -r '.ignore_reason // empty')
    echo "  [${DESIRED_STATUS}] SHA: ${SHA}  File: ${FILEPATH}"
    echo "    Source: #${SRC_ID}  Target: #${TARGET_MATCH}  Current: ${CURRENT_STATUS}  -> Desired: ${DESIRED_STATUS}"

    # Already matches — skip (for IGNORED, also check ignore_reason)
    if [ "$CURRENT_STATUS" = "$DESIRED_STATUS" ]; then
      if [ "$DESIRED_STATUS" = "IGNORED" ] && [ "$IGNORE_REASON" != "$CURRENT_IGNORE_REASON" ]; then
        echo "    Status matches but ignore_reason differs (${CURRENT_IGNORE_REASON} != ${IGNORE_REASON}) — re-applying..."
      else
        echo "    Already ${DESIRED_STATUS} — skipping."
        continue
      fi
    fi

    # Reopen if in a different non-open state
    if [ "$CURRENT_STATUS" != "TRIGGERED" ] && [ "$DESIRED_STATUS" != "TRIGGERED" ]; then
      echo "    Status mismatch (${CURRENT_STATUS} != ${DESIRED_STATUS}) — reopening first..."
      if ! reopen_incident "$TARGET_MATCH"; then
        echo "    ERROR: Failed to reopen incident ${TARGET_MATCH}"
        exit 1
      fi
    fi

    # Apply the desired status
    if [ "$DESIRED_STATUS" = "TRIGGERED" ]; then
      # Need to reopen to get back to TRIGGERED
      echo "    Reopening to TRIGGERED..."
      if ! reopen_incident "$TARGET_MATCH"; then
        echo "    ERROR: Failed to reopen incident ${TARGET_MATCH}"
        exit 1
      fi
      echo "    Result: TRIGGERED"
    elif [ "$DESIRED_STATUS" = "RESOLVED" ]; then
      echo "    Resolving (secret_revoked: ${REVOKED})..."
      RESP=$(curl -s -H "Authorization: Token $GG_TOKEN" \
           -H "Accept: application/json" \
           -H "Content-Type: application/json" \
           -X POST "${BASE_URL}/incidents/secrets/${TARGET_MATCH}/resolve" \
           -d "{\"secret_revoked\": ${REVOKED}}")
      DETAIL=$(echo "$RESP" | jq -r '.detail // empty')
      if [ -n "$DETAIL" ]; then
        echo "    ERROR: ${DETAIL}"
        exit 1
      fi
      echo "    Result: $(echo "$RESP" | jq -r '.status // "ERROR"')"
    else
      BODY="{\"secret_revoked\": ${REVOKED}"
      if [ -n "$IGNORE_REASON" ]; then
        BODY="${BODY}, \"ignore_reason\": \"${IGNORE_REASON}\""
      fi
      BODY="${BODY}}"
      echo "    Ignoring (secret_revoked: ${REVOKED}, reason: ${IGNORE_REASON:-none})..."
      RESP=$(curl -s -H "Authorization: Token $GG_TOKEN" \
           -H "Accept: application/json" \
           -H "Content-Type: application/json" \
           -X POST "${BASE_URL}/incidents/secrets/${TARGET_MATCH}/ignore" \
           -d "${BODY}")
      DETAIL=$(echo "$RESP" | jq -r '.detail // empty')
      if [ -n "$DETAIL" ]; then
        echo "    ERROR: ${DETAIL}"
        exit 1
      fi
      echo "    Result: $(echo "$RESP" | jq -r '.status // "ERROR"')"
    fi

  done <<< "$ALL_ACTIONABLE"
fi
