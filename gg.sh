#!/usr/bin/env python3
"""
GitGuardian Incident Migration Helper (commit-id mapping)

Scenario:
- OLD GitHub org: manulife-ca
- NEW GitHub org: mfc-ca
- Same GitGuardian workspace
- Git history preserved (commit SHAs stable)

Actions:
1) OLD repo: tag OPEN incidents with "legacy-github"
2) NEW repo: for each OLD incident:
   - if OLD is IGNORED => ignore matching NEW incident
   - if OLD is CLOSED  => close matching NEW incident
   - if OLD is OPEN    => do nothing (leave NEW open)

Matching key (commit-id based + safety):
- repo_name (without org)
- commit_sha
- file_path
- detector name/type
- line_start, line_end (if available)

Run with --dry-run first.
"""

import os
import json
import time
import argparse
from dataclasses import dataclass
from typing import Dict, Any, Optional, Iterable, List, Tuple
import requests

DEFAULT_BASE_URL = os.getenv("GG_BASE_URL", "https://api.gitguardian.com/v1").rstrip("/")
DEFAULT_PER_PAGE = 100

# ---------- Helpers: pagination ----------
def _headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Token {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "gg-inc-migration/1.0",
    }

def _parse_next_link(link_header: Optional[str]) -> Optional[str]:
    # Link: <url>; rel="next"
    if not link_header:
        return None
    for part in link_header.split(","):
        part = part.strip()
        if 'rel="next"' in part:
            url_part = part.split(";")[0].strip()
            if url_part.startswith("<") and url_part.endswith(">"):
                return url_part[1:-1]
            return url_part
    return None

def paged_get(url: str, token: str, params: Dict[str, Any]) -> Iterable[List[Dict[str, Any]]]:
    s = requests.Session()
    next_url = url
    next_params = dict(params)

    while True:
        r = s.get(next_url, headers=_headers(token), params=next_params, timeout=60)
        if r.status_code >= 400:
            raise RuntimeError(f"GET {next_url} failed {r.status_code}: {r.text}")

        data = r.json()
        if isinstance(data, list):
            items = data
        else:
            items = data.get("items") or data.get("results") or data.get("data") or []

        yield items

        nxt = _parse_next_link(r.headers.get("Link"))
        if not nxt:
            break
        next_url = nxt
        next_params = {}  # already embedded in next link


# ---------- Incident field extraction (best-effort; tenant-safe) ----------
def get_repo_full_name(inc: Dict[str, Any]) -> str:
    repo = inc.get("repository_full_name") or inc.get("repository") or inc.get("repo") or ""
    if isinstance(repo, dict):
        return repo.get("full_name") or repo.get("name") or ""
    return repo

def repo_name_only(repo_full: str) -> str:
    return repo_full.split("/", 1)[1] if "/" in repo_full else repo_full

def get_status(inc: Dict[str, Any]) -> str:
    # normalize to: triggered/open, closed, ignored
    st = (inc.get("status") or inc.get("state") or "").lower()
    # common normalizations
    if st in {"ignored", "ignore"}:
        return "ignored"
    if st in {"closed", "resolved", "fixed"}:
        return "closed"
    # treat anything else as open/triggered
    return "open"

def best_effort_fields(inc: Dict[str, Any]) -> Tuple[str, str, str, str, int, int]:
    repo_full = get_repo_full_name(inc)

    commit_sha = (
        inc.get("commit_sha")
        or (inc.get("commit") or {}).get("sha")
        or (inc.get("occurrence") or {}).get("commit_sha")
        or ""
    )

    file_path = (
        inc.get("file_path")
        or inc.get("path")
        or (inc.get("occurrence") or {}).get("file_path")
        or (inc.get("occurrence") or {}).get("path")
        or ""
    )

    detector = (
        inc.get("detector_name")
        or ((inc.get("detector") or {}).get("name") if isinstance(inc.get("detector"), dict) else "")
        or inc.get("detector_group_name")
        or ""
    )

    line_start = (
        inc.get("line_start")
        or inc.get("start_line")
        or (inc.get("occurrence") or {}).get("line_start")
        or (inc.get("occurrence") or {}).get("start_line")
        or 0
    )
    line_end = (
        inc.get("line_end")
        or inc.get("end_line")
        or (inc.get("occurrence") or {}).get("line_end")
        or (inc.get("occurrence") or {}).get("end_line")
        or 0
    )

    return repo_full, str(commit_sha), str(file_path), str(detector or ""), int(line_start or 0), int(line_end or 0)


@dataclass(frozen=True)
class MatchKey:
    repo_name: str
    commit_sha: str
    file_path: str
    detector: str
    line_start: int
    line_end: int


def build_key(inc: Dict[str, Any]) -> Optional[MatchKey]:
    repo_full, commit_sha, file_path, detector, ls, le = best_effort_fields(inc)
    if not repo_full or not commit_sha or not file_path:
        return None
    return MatchKey(
        repo_name=repo_name_only(repo_full),
        commit_sha=commit_sha,
        file_path=file_path,
        detector=detector,
        line_start=ls,
        line_end=le,
    )


# ---------- Actions: ignore / close / tag ----------
def api_post(url: str, token: str, payload: Optional[Dict[str, Any]] = None) -> requests.Response:
    return requests.post(url, headers=_headers(token), json=payload or {}, timeout=60)

def ignore_incident(base_url: str, token: str, incident_id: int, reason: str) -> None:
    # Common pattern: POST /incidents/secrets/{id}/ignore
    url = f"{base_url}/incidents/secrets/{incident_id}/ignore"
    r = api_post(url, token, {"ignore_reason": reason})
    if r.status_code >= 400:
        raise RuntimeError(f"IGNORE failed for {incident_id} ({r.status_code}): {r.text}")

def close_incident(base_url: str, token: str, incident_id: int) -> None:
    """
    Close endpoint varies by tenant.
    Try a couple common patterns; keep the first that works.
    """
    candidates = [
        (f"{base_url}/incidents/secrets/{incident_id}/close", {}),
        (f"{base_url}/incidents/secrets/{incident_id}/resolve", {}),
        (f"{base_url}/incidents/secrets/{incident_id}/status", {"status": "closed"}),
    ]
    last_err = None
    for url, payload in candidates:
        r = api_post(url, token, payload)
        if r.status_code < 400:
            return
        last_err = f"{url} -> {r.status_code}: {r.text}"
    raise RuntimeError(f"CLOSE failed for {incident_id}. Tried endpoints; last error: {last_err}")

def add_tag_to_incident(base_url: str, token: str, incident_id: int, tag: str) -> None:
    """
    Tagging endpoint varies by tenant.
    We try common patterns; you may need to adjust THIS function only.
    """
    candidates = [
        (f"{base_url}/incidents/secrets/{incident_id}/tags", {"tags": [tag]}),
        (f"{base_url}/incidents/secrets/{incident_id}/tag", {"tag": tag}),
        (f"{base_url}/incidents/secrets/{incident_id}/labels", {"labels": [tag]}),
        (f"{base_url}/incidents/secrets/{incident_id}", {"tags": [tag]}),  # PATCH-like via POST (some APIs accept)
    ]
    last_err = None
    for url, payload in candidates:
        r = api_post(url, token, payload)
        if r.status_code < 400:
            return
        last_err = f"{url} -> {r.status_code}: {r.text}"
    raise RuntimeError(f"TAG failed for {incident_id}. Tried endpoints; last error: {last_err}")


# ---------- Main workflow ----------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", default=os.getenv("GG_TOKEN"), help="GitGuardian API token (or env GG_TOKEN)")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL, help="e.g. https://api.gitguardian.com/v1")
    ap.add_argument("--old-org", default="manulife-ca")
    ap.add_argument("--new-org", default="mfc-ca")
    ap.add_argument("--repo", required=True, help="Repo name only, e.g. my-service (no org)")
    ap.add_argument("--per-page", type=int, default=DEFAULT_PER_PAGE)
    ap.add_argument("--sleep", type=float, default=0.15, help="Delay between writes to avoid rate limits")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--ignore-reason", default="false_positive")
    ap.add_argument("--legacy-tag", default="legacy-github")
    args = ap.parse_args()

    if not args.token:
        print("ERROR: provide --token or set GG_TOKEN.")
        return 2

    base_url = args.base_url.rstrip("/")
    list_url = f"{base_url}/incidents/secrets"

    old_repo_full = f"{args.old_org}/{args.repo}"
    new_repo_full = f"{args.new_org}/{args.repo}"

    # 1) Pull OLD incidents (all statuses) for old repo
    # We list by status buckets to avoid relying on repo filter params (tenant differences).
    status_params_list = [
        ("open",   {"status": "triggered", "per_page": args.per_page}),
        ("closed", {"status": "closed", "per_page": args.per_page}),
        ("ignored",{"status": "ignored", "per_page": args.per_page}),
    ]

    old_by_key: Dict[MatchKey, Dict[str, Any]] = {}
    old_status_by_key: Dict[MatchKey, str] = {}
    old_counts = {"open": 0, "closed": 0, "ignored": 0}

    print(f"\n[1] Export OLD incidents for {old_repo_full}")
    for normalized_status, params in status_params_list:
        for items in paged_get(list_url, args.token, params):
            for inc in items:
                if get_repo_full_name(inc) != old_repo_full:
                    continue
                key = build_key(inc)
                if not key:
                    continue
                old_by_key.setdefault(key, inc)
                old_status_by_key[key] = normalized_status
                old_counts[normalized_status] += 1

    print(f"OLD counts: {old_counts} | unique match keys: {len(old_by_key)}")

    # 1a) Tag OLD OPEN incidents with legacy-github
    print(f"\n[2] Tag OLD OPEN incidents with tag='{args.legacy_tag}' (on OLD incidents only)")
    tag_attempted = 0
    tag_done = 0
    tag_failed = 0

    for key, old_inc in old_by_key.items():
        if old_status_by_key.get(key) != "open":
            continue
        old_id = old_inc.get("id")
        if not old_id:
            continue

        tag_attempted += 1
        if args.dry_run:
            continue

        try:
            add_tag_to_incident(base_url, args.token, int(old_id), args.legacy_tag)
            tag_done += 1
            time.sleep(args.sleep)
        except Exception as e:
            tag_failed += 1
            print(f"TAG FAILED old_incident_id={old_id}: {e}")

    print(f"Tag summary: attempted={tag_attempted}, applied={tag_done}, failed={tag_failed}, dry_run={args.dry_run}")

    # 2) Pull NEW incidents (open + closed + ignored) for new repo, build lookup
    print(f"\n[3] Export NEW incidents for {new_repo_full}")
    new_by_key: Dict[MatchKey, Dict[str, Any]] = {}
    new_counts = {"open": 0, "closed": 0, "ignored": 0}

    for normalized_status, params in status_params_list:
        for items in paged_get(list_url, args.token, params):
            for inc in items:
                if get_repo_full_name(inc) != new_repo_full:
                    continue
                key = build_key(inc)
                if not key:
                    continue
                new_by_key.setdefault(key, inc)
                new_counts[normalized_status] += 1

    print(f"NEW counts: {new_counts} | unique match keys: {len(new_by_key)}")

    # 3) Apply OLD statuses to NEW by commit-id mapping (key includes commit_sha)
    print(f"\n[4] Apply OLD statuses to NEW (close/ignore). OPEN stays OPEN in NEW.")
    mapped = 0
    not_found = 0
    ignored_applied = 0
    closed_applied = 0
    errors = 0

    for key, old_inc in old_by_key.items():
        old_status = old_status_by_key.get(key, "open")
        new_inc = new_by_key.get(key)
        if not new_inc:
            not_found += 1
            continue

        new_id = new_inc.get("id")
        if not new_id:
            not_found += 1
            continue

        mapped += 1

        if old_status == "ignored":
            if args.dry_run:
                continue
            try:
                ignore_incident(base_url, args.token, int(new_id), args.ignore_reason)
                ignored_applied += 1
                time.sleep(args.sleep)
            except Exception as e:
                errors += 1
                print(f"IGNORE FAILED new_incident_id={new_id}: {e}")

        elif old_status == "closed":
            if args.dry_run:
                continue
            try:
                close_incident(base_url, args.token, int(new_id))
                closed_applied += 1
                time.sleep(args.sleep)
            except Exception as e:
                errors += 1
                print(f"CLOSE FAILED new_incident_id={new_id}: {e}")

        else:
            # open -> do nothing on NEW
            pass

    print("\n=== RESULT ===")
    print(f"Mapped old->new: {mapped}")
    print(f"Not found in new: {not_found}")
    print(f"Applied ignores on NEW: {ignored_applied}")
    print(f"Applied closes on NEW: {closed_applied}")
    print(f"Errors: {errors}")
    print(f"Dry-run: {args.dry_run}")
    print("\nTip: If TAG failed, paste the error here; I’ll adjust ONLY the tagging endpoint for your tenant.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
