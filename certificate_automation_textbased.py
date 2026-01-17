#!/usr/bin/env python3
"""
Certificate Automation Script - Text-based version
Manages DNS names using pure text manipulation to preserve formatting
"""

import argparse
import json
import re
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple


DOCUMENT_SEPARATOR_PATTERN = re.compile(r"^\s*---\s*$", re.MULTILINE)
NAMESPACE_PREFIX_PATTERN = re.compile(r"^[^/]+/")


def read_text(path: str) -> str:
    with open(path, "r") as file:
        return file.read()


def write_text(path: str, content: str) -> None:
    with open(path, "w") as file:
        file.write(content)


def split_documents(content: str) -> Tuple[List[str], List[str]]:
    documents: List[str] = []
    separators: List[str] = []
    last_end = 0

    for match in DOCUMENT_SEPARATOR_PATTERN.finditer(content):
        documents.append(content[last_end:match.start()])
        separators.append(content[match.start():match.end()])
        last_end = match.end()

    documents.append(content[last_end:])
    return documents, separators


def join_documents(documents: List[str], separators: List[str]) -> str:
    if not documents:
        return ""

    combined = documents[0]
    for index, separator in enumerate(separators):
        combined += separator + documents[index + 1]
    return combined


def unique_list(items: List[str]) -> List[str]:
    seen = set()
    ordered = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def get_wildcard_patterns(dns_name: str) -> List[str]:
    """Generate wildcard patterns for a DNS name"""
    parts = dns_name.split(".")
    patterns = []
    for i in range(1, len(parts) - 1):
        patterns.append("*." + ".".join(parts[i:]))
    return patterns


def strip_namespace_prefix(host: str) -> str:
    return NAMESPACE_PREFIX_PATTERN.sub("", host)


def is_covered_by_wildcard(dns_name: str, existing_hosts: List[str]) -> Tuple[bool, str]:
    """Check if a DNS name is covered by existing wildcard patterns"""
    clean_hosts = [strip_namespace_prefix(host) for host in existing_hosts]
    wildcard_hosts = [host for host in clean_hosts if host.startswith("*.")]

    for pattern in wildcard_hosts:
        pattern_suffix = pattern[2:]
        if dns_name.endswith("." + pattern_suffix):
            return True, f"Covered by existing wildcard pattern '{pattern}'"

    for candidate in get_wildcard_patterns(dns_name):
        if candidate in clean_hosts:
            return True, f"Covered by existing wildcard pattern '{candidate}'"

    return False, "No matching host or wildcard pattern found"


def detect_quote_style(lines: List[str], start: int, end: int, namespace: str) -> str:
    for index in range(start, min(end, len(lines))):
        line = lines[index]
        if namespace not in line:
            continue
        if '"' in line:
            return '"'
        if "'" in line:
            return "'"
    return ""


def find_gateway_namespace_hosts(lines: List[str], namespace: str) -> Optional[Tuple[int, int, int]]:
    namespace_pattern = re.compile(rf"^\s*-\s*['\"]?{re.escape(namespace)}/")
    start_idx = None
    list_indent = None

    for i, line in enumerate(lines):
        if namespace_pattern.search(line):
            start_idx = i
            list_indent = len(line) - len(line.lstrip())
            break

    if start_idx is None:
        return None

    end_idx = start_idx
    for i in range(start_idx + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())

        if stripped.startswith("- ") and indent == list_indent:
            end_idx = i
            continue
        if stripped == "":
            continue
        if indent <= list_indent and not stripped.startswith("- "):
            break
        if indent < list_indent:
            break

    return start_idx, end_idx, list_indent


def add_dns_to_gateway_text(
    gateway_file: str, namespace: str, dns_names: List[str]
) -> Tuple[bool, List[Dict[str, str]]]:
    """Add DNS names to gateway using pure text manipulation"""
    results: List[Dict[str, str]] = []
    lines = read_text(gateway_file).splitlines(True)

    host_section = find_gateway_namespace_hosts(lines, namespace)
    if host_section is None:
        for dns_name in dns_names:
            results.append(
                {
                    "dns_name": dns_name,
                    "added": False,
                    "reason": f"Could not find namespace section for '{namespace}'",
                }
            )
        return False, results

    start_idx, end_idx, list_indent = host_section
    existing_hosts = []

    for i in range(start_idx, end_idx + 1):
        stripped = lines[i].strip()
        if stripped.startswith("- "):
            host = stripped[2:].strip().strip("\"").strip("'")
            existing_hosts.append(host)

    insert_idx = end_idx + 1
    modified = False
    quote_style = detect_quote_style(lines, start_idx, end_idx + 1, namespace)

    print(f"  Found {len(existing_hosts)} existing hosts in namespace section:")
    for host in existing_hosts:
        print(f"    - {host}")
    print()

    for dns_name in unique_list(dns_names):
        full_host = f"{namespace}/{dns_name}"
        if full_host in existing_hosts:
            print(f"  ○ Skipping (already exists): {dns_name}")
            results.append(
                {
                    "dns_name": dns_name,
                    "added": False,
                    "reason": "Already exists in gateway",
                }
            )
            continue

        is_covered, reason = is_covered_by_wildcard(dns_name, existing_hosts)
        if is_covered:
            print(f"  ○ Skipping (covered by wildcard): {dns_name}")
            results.append({"dns_name": dns_name, "added": False, "reason": reason})
            continue

        if quote_style:
            new_line = f"{' ' * list_indent}- {quote_style}{full_host}{quote_style}\n"
        else:
            new_line = f"{' ' * list_indent}- {full_host}\n"

        lines.insert(insert_idx, new_line)
        insert_idx += 1
        modified = True
        existing_hosts.append(full_host)
        print(f"  ✓ Adding host to gateway: {dns_name}")
        results.append({"dns_name": dns_name, "added": True, "reason": reason})

    if modified:
        write_text(gateway_file, "".join(lines))

    return modified, results


def find_dns_section(lines: List[str]) -> Optional[Tuple[int, int, int]]:
    dns_section_idx = None
    list_indent = None

    for i, line in enumerate(lines):
        if line.strip() == "dnsNames:":
            dns_section_idx = i
            for j in range(i + 1, len(lines)):
                if lines[j].strip().startswith("- "):
                    list_indent = len(lines[j]) - len(lines[j].lstrip())
                    break
            if list_indent is None:
                list_indent = (len(line) - len(line.lstrip())) + 2
            break

    if dns_section_idx is None:
        return None

    last_dns_idx = dns_section_idx
    for i in range(dns_section_idx + 1, len(lines)):
        stripped = lines[i].strip()
        indent = len(lines[i]) - len(lines[i].lstrip())

        if stripped.startswith("- ") and indent >= list_indent:
            last_dns_idx = i
            continue
        if stripped == "":
            continue
        if indent < list_indent:
            break

    return dns_section_idx, last_dns_idx, list_indent


def ensure_dns_section(lines: List[str]) -> Tuple[int, int, int]:
    section = find_dns_section(lines)
    if section:
        return section

    spec_idx = None
    spec_indent = None
    for i, line in enumerate(lines):
        if line.strip() == "spec:":
            spec_idx = i
            spec_indent = len(line) - len(line.lstrip())
            break

    if spec_idx is None:
        raise ValueError("Could not find 'spec:' section in certificate document")

    insert_idx = spec_idx + 1
    dns_indent = spec_indent + 2
    lines.insert(insert_idx, f"{' ' * dns_indent}dnsNames:\n")
    return insert_idx, insert_idx, dns_indent + 2


def add_dns_to_certificate_text(
    cert_file: str, credential_name: str, dns_names: List[str]
) -> Tuple[bool, List[Dict[str, str]]]:
    """Add DNS names to certificate using pure text manipulation"""
    results: List[Dict[str, str]] = []
    content = read_text(cert_file)
    documents, separators = split_documents(content)
    modified = False

    for doc_idx, doc in enumerate(documents):
        if not re.search(rf"^\s*secretName:\s*['\"]?{re.escape(credential_name)}['\"]?\s*$", doc, re.MULTILINE):
            continue

        lines = doc.split("\n")
        try:
            dns_section_idx, last_dns_idx, list_indent = ensure_dns_section(lines)
        except ValueError:
            for dns_name in dns_names:
                results.append(
                    {
                        "dns_name": dns_name,
                        "added": False,
                        "reason": "Certificate spec section missing",
                    }
                )
            continue

        existing_dns = []
        for i in range(dns_section_idx + 1, last_dns_idx + 1):
            stripped = lines[i].strip()
            if stripped.startswith("- "):
                existing_dns.append(stripped[2:].strip().strip("\"").strip("'"))

        quote_style = '"' if any('"' in lines[i] for i in range(dns_section_idx + 1, last_dns_idx + 1)) else ""
        insert_idx = last_dns_idx + 1

        for dns_name in unique_list(dns_names):
            if dns_name in existing_dns:
                print(f"  ○ Skipping (already in certificate): {dns_name}")
                results.append(
                    {
                        "dns_name": dns_name,
                        "added": False,
                        "reason": "Already exists in certificate",
                    }
                )
                continue

            if quote_style:
                new_line = f"{' ' * list_indent}- {quote_style}{dns_name}{quote_style}"
            else:
                new_line = f"{' ' * list_indent}- {dns_name}"

            lines.insert(insert_idx, new_line)
            insert_idx += 1
            modified = True
            existing_dns.append(dns_name)
            print(f"  ✓ Adding DNS to certificate: {dns_name}")
            results.append(
                {
                    "dns_name": dns_name,
                    "added": True,
                    "reason": "DNS name must be explicitly listed in certificate for TLS validation",
                }
            )

        documents[doc_idx] = "\n".join(lines)

    if modified:
        write_text(cert_file, join_documents(documents, separators))

    return modified, results


def get_credential_name_for_namespace_text(gateway_file: str, namespace: str) -> Optional[str]:
    """Get credential name by reading gateway file as text"""
    lines = read_text(gateway_file).split("\n")
    namespace_pattern = re.compile(rf"^\s*-\s*['\"]?{re.escape(namespace)}/")

    for i, line in enumerate(lines):
        if not namespace_pattern.search(line):
            continue

        host_indent = len(line) - len(line.lstrip())
        for j in range(i + 1, len(lines)):
            next_line = lines[j]
            stripped = next_line.strip()
            indent = len(next_line) - len(next_line.lstrip())

            if indent < host_indent and stripped.startswith("-"):
                break
            if stripped.startswith("credentialName:"):
                return stripped.split("credentialName:", 1)[1].strip().strip("\"").strip("'")

    return None


def credential_exists_in_certificate(cert_file: str, credential_name: str) -> bool:
    content = read_text(cert_file)
    pattern = rf"^\s*secretName:\s*['\"]?{re.escape(credential_name)}['\"]?\s*$"
    return re.search(pattern, content, re.MULTILINE) is not None


def generate_audit_log(
    namespace: str,
    dns_names: List[str],
    gateway_results: List[Dict[str, str]],
    cert_results: List[Dict[str, str]],
    repo_name: Optional[str] = None,
) -> str:
    """Generate audit log entry"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    log = f"\n## Automation Run - {timestamp}\n\n"
    if repo_name:
        log += f"**Repository:** `{repo_name}`\n\n"
    log += f"**Namespace:** `{namespace}`\n\n"
    log += "**DNS Names Requested:**\n"
    for i, dns in enumerate(dns_names, 1):
        log += f"{i}. `{dns}`\n"

    log += "\n### Gateway Changes\n\n"
    gateway_added = [r for r in gateway_results if r["added"]]
    if gateway_added:
        log += "**Added to Gateway:**\n"
        for r in gateway_added:
            log += f"- ✅ `{r['dns_name']}`\n"
            log += f"  - Reason: {r['reason']}\n"

    gateway_skipped = [r for r in gateway_results if not r["added"]]
    if gateway_skipped:
        log += "\n**Skipped (Gateway):**\n"
        for r in gateway_skipped:
            log += f"- ⏭️ `{r['dns_name']}`\n"
            log += f"  - Reason: {r['reason']}\n"

    log += "\n### Certificate Changes\n\n"
    cert_added = [r for r in cert_results if r["added"]]
    if cert_added:
        log += "**Added to Certificate:**\n"
        for r in cert_added:
            log += f"- ✅ `{r['dns_name']}`\n"
            log += f"  - Reason: {r['reason']}\n"

    cert_skipped = [r for r in cert_results if not r["added"]]
    if cert_skipped:
        log += "\n**Skipped (Certificate):**\n"
        for r in cert_skipped:
            log += f"- ⏭️ `{r['dns_name']}`\n"
            log += f"  - Reason: {r['reason']}\n"

    log += "\n---\n"
    return log


def generate_pr_description(
    namespace: str,
    dns_names: List[str],
    gateway_results: List[Dict[str, str]],
    cert_results: List[Dict[str, str]],
    repo_name: Optional[str] = None,
) -> str:
    """Generate PR description"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    desc = "## 🔐 Certificate Automation - DNS Names Update\n\n"
    if repo_name:
        desc += f"**Repository:** `{repo_name}`\n"
    desc += f"**Namespace:** `{namespace}`\n"
    desc += f"**Automation Run:** {timestamp}\n\n"

    desc += "### 📋 DNS Names Requested\n\n"
    for i, dns in enumerate(dns_names, 1):
        desc += f"{i}. `{dns}`\n"

    gateway_added = [r for r in gateway_results if r["added"]]
    gateway_skipped = [r for r in gateway_results if not r["added"]]

    desc += "\n### 🌐 Gateway Changes\n\n"
    desc += f"**Summary:** {len(gateway_added)} added, {len(gateway_skipped)} skipped\n\n"

    if gateway_added:
        desc += "#### ✅ Added to Gateway\n\n"
        for r in gateway_added:
            desc += f"- **`{r['dns_name']}`**\n"
            desc += f"  - 💡 {r['reason']}\n"

    cert_added = [r for r in cert_results if r["added"]]
    cert_skipped = [r for r in cert_results if not r["added"]]

    desc += "\n### 📜 Certificate Changes\n\n"
    desc += f"**Summary:** {len(cert_added)} added, {len(cert_skipped)} skipped\n\n"

    if cert_added:
        desc += "#### ✅ Added to Certificate\n\n"
        for r in cert_added:
            desc += f"- **`{r['dns_name']}`**\n"
            desc += f"  - 💡 {r['reason']}\n"

    desc += "\n---\n\n"
    desc += "### ℹ️  Key Information\n\n"
    desc += "- Gateway uses wildcards (`*.domain.com`) to route traffic efficiently\n"
    desc += "- Certificates must list each DNS name explicitly for TLS validation\n"
    desc += "- Even if a DNS is covered by a wildcard in the gateway, it still needs to be in the certificate\n\n"
    desc += "---\n\n"
    desc += "🤖 *This PR was automatically generated by the Certificate Automation workflow*\n"

    return desc


def generate_audit_log_multi(
    namespaces: List[str],
    all_dns_names: List[str],
    gateway_results: List[Dict[str, str]],
    cert_results: List[Dict[str, str]],
    repo_name: Optional[str] = None,
) -> str:
    """Generate audit log entry for multi-namespace requests"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    log = f"\n## Automation Run - {timestamp}\n\n"
    if repo_name:
        log += f"**Repository:** `{repo_name}`\n\n"
    log += f"**Namespaces:** {', '.join([f'`{ns}`' for ns in namespaces])}\n\n"
    log += f"**Total DNS Names:** {len(all_dns_names)}\n\n"

    log += "### Gateway Changes\n\n"
    gateway_added = [r for r in gateway_results if r["added"]]
    if gateway_added:
        log += "**Added to Gateway:**\n"
        for r in gateway_added:
            log += f"- ✅ `{r['dns_name']}`\n"
            log += f"  - Reason: {r['reason']}\n"

    gateway_skipped = [r for r in gateway_results if not r["added"]]
    if gateway_skipped:
        log += "\n**Skipped (Gateway):**\n"
        for r in gateway_skipped:
            log += f"- ⏭️ `{r['dns_name']}`\n"
            log += f"  - Reason: {r['reason']}\n"

    log += "\n### Certificate Changes\n\n"
    cert_added = [r for r in cert_results if r["added"]]
    if cert_added:
        log += "**Added to Certificate:**\n"
        for r in cert_added:
            log += f"- ✅ `{r['dns_name']}`\n"
            log += f"  - Reason: {r['reason']}\n"

    cert_skipped = [r for r in cert_results if not r["added"]]
    if cert_skipped:
        log += "\n**Skipped (Certificate):**\n"
        for r in cert_skipped:
            log += f"- ⏭️ `{r['dns_name']}`\n"
            log += f"  - Reason: {r['reason']}\n"

    log += "\n---\n"
    return log


def generate_pr_description_multi(
    namespaces: List[str],
    all_dns_names: List[str],
    gateway_results: List[Dict[str, str]],
    cert_results: List[Dict[str, str]],
    repo_name: Optional[str] = None,
) -> str:
    """Generate PR description for multi-namespace requests"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    desc = "## 🔐 Certificate Automation - DNS Names Update\n\n"
    if repo_name:
        desc += f"**Repository:** `{repo_name}`\n"
    desc += f"**Namespaces:** {', '.join([f'`{ns}`' for ns in namespaces])}\n"
    desc += f"**Automation Run:** {timestamp}\n\n"

    desc += f"### 📋 Total DNS Names: {len(all_dns_names)}\n\n"

    gateway_added = [r for r in gateway_results if r["added"]]
    gateway_skipped = [r for r in gateway_results if not r["added"]]

    desc += "\n### 🌐 Gateway Changes\n\n"
    desc += f"**Summary:** {len(gateway_added)} added, {len(gateway_skipped)} skipped\n\n"

    if gateway_added:
        desc += "#### ✅ Added to Gateway\n\n"
        for r in gateway_added:
            desc += f"- **`{r['dns_name']}`**\n"
            desc += f"  - 💡 {r['reason']}\n"

    cert_added = [r for r in cert_results if r["added"]]
    cert_skipped = [r for r in cert_results if not r["added"]]

    desc += "\n### 📜 Certificate Changes\n\n"
    desc += f"**Summary:** {len(cert_added)} added, {len(cert_skipped)} skipped\n\n"

    if cert_added:
        desc += "#### ✅ Added to Certificate\n\n"
        for r in cert_added:
            desc += f"- **`{r['dns_name']}`**\n"
            desc += f"  - 💡 {r['reason']}\n"

    desc += "\n---\n\n"
    desc += "### ℹ️  Key Information\n\n"
    desc += "- Gateway uses wildcards (`*.domain.com`) to route traffic efficiently\n"
    desc += "- Certificates must list each DNS name explicitly for TLS validation\n"
    desc += "- Even if a DNS is covered by a wildcard in the gateway, it still needs to be in the certificate\n\n"
    desc += "---\n\n"
    desc += "🤖 *This PR was automatically generated by the Certificate Automation workflow*\n"

    return desc


def load_requests_from_json(input_path: str, default_repo: Optional[str]) -> Tuple[List[Dict[str, List[str]]], str, str, Optional[str]]:
    try:
        input_data = json.loads(read_text(input_path))
    except FileNotFoundError:
        print(f"ERROR: Input file not found: {input_path}")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in input file: {exc}")
        sys.exit(1)

    gateway_file = input_data.get("gateway_file", "gateway.yaml")
    cert_file = input_data.get("certificate_file", "ingress-gateway-certificate.yaml")
    repo_name = input_data.get("repo_name", default_repo)

    if "requests" in input_data:
        requests = input_data["requests"]
        if not requests:
            print("ERROR: 'requests' array is empty in input file")
            sys.exit(1)
    else:
        if "namespace" not in input_data:
            print("ERROR: 'namespace' is required in input file")
            sys.exit(1)
        if "dns_names" not in input_data or not input_data["dns_names"]:
            print("ERROR: 'dns_names' is required and must not be empty")
            sys.exit(1)
        requests = [
            {"namespace": input_data["namespace"], "dns_names": input_data["dns_names"]}
        ]

    return requests, gateway_file, cert_file, repo_name


def validate_cli_args(args: argparse.Namespace) -> None:
    if not args.namespace:
        print("ERROR: --namespace is required when not using --input")
        sys.exit(1)
    if not args.dns:
        print("ERROR: --dns is required when not using --input")
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Certificate Automation - Text-based")
    parser.add_argument("--input", help="JSON input file path")
    parser.add_argument("--gateway", default="gateway.yaml", help="Gateway YAML file")
    parser.add_argument(
        "--certificate",
        default="ingress-gateway-certificate.yaml",
        help="Certificate YAML file",
    )
    parser.add_argument("--namespace", help="Kubernetes namespace")
    parser.add_argument("--dns", nargs="+", help="DNS names to add")
    parser.add_argument("--repo-name", help="Repository name for audit")
    parser.add_argument("--create-audit", action="store_true", help="Create/update audit log")
    parser.add_argument("--audit-file", default="AUDIT.md", help="Audit log file path")

    args = parser.parse_args()

    if args.input:
        requests, gateway_file, cert_file, repo_name = load_requests_from_json(
            args.input, args.repo_name
        )
    else:
        validate_cli_args(args)
        gateway_file = args.gateway
        cert_file = args.certificate
        repo_name = args.repo_name
        requests = [{"namespace": args.namespace, "dns_names": args.dns or []}]

    print(f"\n{'='*80}")
    print("Certificate Automation - Text-Based Processing")
    print(f"{'='*80}")
    if repo_name:
        print(f"Repository: {repo_name}")
    print(f"Processing {len(requests)} namespace request(s)")
    print(f"{'='*80}\n")

    for path_label, path in (("Gateway", gateway_file), ("Certificate", cert_file)):
        try:
            read_text(path)
        except FileNotFoundError:
            print(f"ERROR: {path_label} file not found: {path}")
            sys.exit(1)

    all_gateway_results: List[Dict[str, str]] = []
    all_cert_results: List[Dict[str, str]] = []
    all_dns_names: List[str] = []
    namespaces_processed: List[str] = []

    for idx, request in enumerate(requests, 1):
        namespace = request.get("namespace")
        dns_names = request.get("dns_names", [])

        if not namespace:
            print(f"\n{'─'*80}")
            print(f"ERROR: Request {idx} missing 'namespace' field, skipping...")
            print(f"{'─'*80}\n")
            continue

        if not dns_names:
            print(f"\n{'─'*80}")
            print(f"ERROR: Request {idx} (namespace: {namespace}) has empty 'dns_names', skipping...")
            print(f"{'─'*80}\n")
            continue

        dns_names = unique_list(dns_names)

        print(f"\n{'─'*80}")
        print(f"Request {idx}/{len(requests)}: Namespace '{namespace}'")
        print(f"{'─'*80}")
        print("DNS Names to add:")
        for i, dns in enumerate(dns_names, 1):
            print(f"  {i}. {dns}")
        print()

        namespaces_processed.append(namespace)
        all_dns_names.extend(dns_names)

        print("Finding TLS credential...")
        credential_name = get_credential_name_for_namespace_text(gateway_file, namespace)
        if not credential_name:
            print(f"ERROR: Could not find credential for namespace '{namespace}'")
            print("Skipping this namespace...\n")
            continue
        if not credential_exists_in_certificate(cert_file, credential_name):
            print(f"WARNING: No certificate document found for credential '{credential_name}'")
            print("Skipping this namespace...\n")
            continue
        print(f"  Found credential: {credential_name}\n")

        print("Processing gateway hosts...")
        _, gateway_results = add_dns_to_gateway_text(gateway_file, namespace, dns_names)
        all_gateway_results.extend(gateway_results)

        print("\nProcessing certificate DNS names...")
        _, cert_results = add_dns_to_certificate_text(cert_file, credential_name, dns_names)
        all_cert_results.extend(cert_results)

        print(f"\n  Namespace '{namespace}' Summary:")
        print(f"    Gateway: {len([r for r in gateway_results if r['added']])} added")
        print(f"    Certificate: {len([r for r in cert_results if r['added']])} added")

    print(f"\n{'='*80}")
    print("OVERALL SUMMARY")
    print(f"{'='*80}")
    print(f"Namespaces processed: {len(namespaces_processed)}")
    print(f"Total DNS names: {len(all_dns_names)}")
    print(
        f"Gateway hosts added: {len([r for r in all_gateway_results if r['added']])} / {len(all_gateway_results)}"
    )
    print(
        f"Certificate DNS added: {len([r for r in all_cert_results if r['added']])} / {len(all_cert_results)}"
    )
    print(f"{'='*80}\n")

    if args.create_audit:
        audit_content = generate_audit_log_multi(
            namespaces_processed,
            all_dns_names,
            all_gateway_results,
            all_cert_results,
            repo_name,
        )

        try:
            existing = read_text(args.audit_file)
        except FileNotFoundError:
            existing = (
                "# Certificate Automation Audit Log\n\n"
                "This file tracks all automated changes to gateway and certificate configurations.\n\n"
                "---\n"
            )

        write_text(args.audit_file, existing + audit_content)
        print(f"✓ Updated audit log: {args.audit_file}")

        write_text("PR_DESCRIPTION.md", audit_content)
        print("✓ Generated PR description: PR_DESCRIPTION.md")


if __name__ == "__main__":
    main()
