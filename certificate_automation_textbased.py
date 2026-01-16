#!/usr/bin/env python3
"""
Certificate Automation Script - Text-based version
Manages DNS names using pure text manipulation to preserve formatting
"""

import json
import sys
import argparse
import re
from typing import List, Dict, Tuple
from datetime import datetime


def get_wildcard_patterns(dns_name: str) -> List[str]:
    """Generate wildcard patterns for a DNS name"""
    parts = dns_name.split('.')
    patterns = []
    for i in range(1, len(parts) - 1):
        pattern = '*.' + '.'.join(parts[i:])
        patterns.append(pattern)
    return patterns


def is_covered_by_wildcard(dns_name: str, existing_hosts: List[str]) -> Tuple[bool, str]:
    """Check if a DNS name is covered by existing wildcard patterns"""
    namespace_prefix_pattern = r'^[^/]+/'
    
    clean_hosts = []
    for host in existing_hosts:
        clean_host = re.sub(namespace_prefix_pattern, '', host)
        clean_hosts.append(clean_host)
    
    wildcard_patterns = [h for h in clean_hosts if h.startswith('*.')]
    
    for pattern in wildcard_patterns:
        pattern_suffix = pattern[2:]  # Remove '*.'
        if dns_name.endswith('.' + pattern_suffix):
            return True, f"Covered by existing wildcard pattern '{pattern}'"
    
    my_wildcards = get_wildcard_patterns(dns_name)
    for my_wildcard in my_wildcards:
        if my_wildcard in clean_hosts:
            return True, f"Covered by existing wildcard pattern '{my_wildcard}'"
    
    return False, "No matching host or wildcard pattern found"


def add_dns_to_gateway_text(gateway_file: str, namespace: str, dns_names: List[str]) -> Tuple[bool, List[Dict]]:
    """Add DNS names to gateway using pure text manipulation"""
    results = []
    
    with open(gateway_file, 'r') as f:
        lines = f.readlines()
    
    # Find the server block for this namespace
    namespace_pattern = f"- {namespace}/"
    start_idx = None
    indent_spaces = None
    
    for i, line in enumerate(lines):
        if namespace_pattern in line:
            start_idx = i
            indent_spaces = len(line) - len(line.lstrip())
            break
    
    if start_idx is None:
        for dns_name in dns_names:
            results.append({
                'dns_name': dns_name,
                'added': False,
                'reason': f"Could not find namespace section for '{namespace}'"
            })
        return False, results
    
    # Collect existing hosts and find insertion point
    existing_hosts = []
    last_host_idx = start_idx
    i = start_idx
    
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        
        # Only collect lines that are part of this namespace's host list
        if stripped.startswith('- '):
            # Extract the host value (remove leading '- ')
            host = stripped[2:].strip()
            # Check if this host belongs to current namespace or is a wildcard for it
            if host.startswith(f'{namespace}/') or host.startswith(f'{namespace}/*.'):
                existing_hosts.append(host)
                last_host_idx = i
                i += 1
            else:
                # Different namespace, stop scanning
                break
        elif stripped and not stripped.startswith('-'):
            # Hit non-list item (like 'port:'), stop scanning
            break
        elif stripped == '':
            # Empty line, skip
            i += 1
        else:
            break
    
    insert_idx = last_host_idx + 1
    modified = False
    
    # Debug: Show what we found
    print(f"  Found {len(existing_hosts)} existing hosts in namespace section:")
    for host in existing_hosts:
        print(f"    - {host}")
    print()
    
    # Process each DNS name
    for dns_name in dns_names:
        full_host = f"{namespace}/{dns_name}"
        
        # Check if exists
        if full_host in existing_hosts:
            print(f"  ○ Skipping (already exists): {dns_name}")
            results.append({
                'dns_name': dns_name,
                'added': False,
                'reason': 'Already exists in gateway'
            })
            continue
        
        # Check wildcard
        is_covered, reason = is_covered_by_wildcard(dns_name, existing_hosts)
        
        if is_covered:
            print(f"  ○ Skipping (covered by wildcard): {dns_name}")
            results.append({
                'dns_name': dns_name,
                'added': False,
                'reason': reason
            })
        else:
            # Insert new line with exact same indentation
            new_line = f"{' ' * indent_spaces}- {namespace}/{dns_name}\n"
            lines.insert(insert_idx, new_line)
            insert_idx += 1
            modified = True
            print(f"  ✓ Adding host to gateway: {dns_name}")
            results.append({
                'dns_name': dns_name,
                'added': True,
                'reason': reason
            })
    
    if modified:
        with open(gateway_file, 'w') as f:
            f.writelines(lines)
    
    return modified, results


def add_dns_to_certificate_text(cert_file: str, credential_name: str, dns_names: List[str]) -> Tuple[bool, List[Dict]]:
    """Add DNS names to certificate using pure text manipulation"""
    results = []
    
    with open(cert_file, 'r') as f:
        content = f.read()
    
    # Split by document separator
    documents = content.split('\n---\n')
    modified = False
    
    for doc_idx, doc in enumerate(documents):
        if f'secretName: {credential_name}' not in doc:
            continue
        
        lines = doc.split('\n')
        
        # Find dnsNames section
        dns_section_idx = None
        indent_spaces = None
        
        for i, line in enumerate(lines):
            if line.strip() == 'dnsNames:':
                dns_section_idx = i
                # Get indentation from next line
                if i + 1 < len(lines):
                    next_line = lines[i + 1]
                    if next_line.strip().startswith('- '):
                        indent_spaces = len(next_line) - len(next_line.lstrip())
                break
        
        if dns_section_idx is None:
            continue
        
        # Collect existing DNS names
        existing_dns = []
        last_dns_idx = dns_section_idx
        i = dns_section_idx + 1
        
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            if stripped.startswith('- '):
                dns = stripped[2:].strip()
                existing_dns.append(dns)
                last_dns_idx = i
                i += 1
            elif stripped == '':
                i += 1
            elif stripped and not stripped.startswith('-'):
                break
            else:
                break
        
        insert_idx = last_dns_idx + 1
        
        # Add new DNS names
        for dns_name in dns_names:
            if dns_name in existing_dns:
                print(f"  ○ Skipping (already in certificate): {dns_name}")
                results.append({
                    'dns_name': dns_name,
                    'added': False,
                    'reason': 'Already exists in certificate'
                })
            else:
                new_line = f"{' ' * indent_spaces}- {dns_name}"
                lines.insert(insert_idx, new_line)
                insert_idx += 1
                modified = True
                print(f"  ✓ Adding DNS to certificate: {dns_name}")
                results.append({
                    'dns_name': dns_name,
                    'added': True,
                    'reason': 'DNS name must be explicitly listed in certificate for TLS validation'
                })
        
        documents[doc_idx] = '\n'.join(lines)
    
    if modified:
        with open(cert_file, 'w') as f:
            f.write('\n---\n'.join(documents))
    
    return modified, results


def get_credential_name_for_namespace_text(gateway_file: str, namespace: str) -> str:
    """Get credential name by reading gateway file as text"""
    with open(gateway_file, 'r') as f:
        content = f.read()
    
    # Find namespace section and its credentialName
    lines = content.split('\n')
    in_namespace_section = False
    
    for i, line in enumerate(lines):
        if f"- {namespace}/" in line or f'"{namespace}/' in line:
            in_namespace_section = True
        elif in_namespace_section and 'credentialName:' in line:
            cred_name = line.split('credentialName:')[1].strip()
            return cred_name
        elif in_namespace_section and line.strip().startswith('- hosts:'):
            in_namespace_section = False
    
    return None


def generate_audit_log(namespace: str, dns_names: List[str], gateway_results: List[Dict], 
                       cert_results: List[Dict], repo_name: str = None) -> str:
    """Generate audit log entry"""
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    log = f"\n## Automation Run - {timestamp}\n\n"
    if repo_name:
        log += f"**Repository:** `{repo_name}`\n\n"
    log += f"**Namespace:** `{namespace}`\n\n"
    log += "**DNS Names Requested:**\n"
    for i, dns in enumerate(dns_names, 1):
        log += f"{i}. `{dns}`\n"
    
    log += "\n### Gateway Changes\n\n"
    gateway_added = [r for r in gateway_results if r['added']]
    if gateway_added:
        log += "**Added to Gateway:**\n"
        for r in gateway_added:
            log += f"- ✅ `{r['dns_name']}`\n"
            log += f"  - Reason: {r['reason']}\n"
    
    gateway_skipped = [r for r in gateway_results if not r['added']]
    if gateway_skipped:
        log += "\n**Skipped (Gateway):**\n"
        for r in gateway_skipped:
            log += f"- ⏭️ `{r['dns_name']}`\n"
            log += f"  - Reason: {r['reason']}\n"
    
    log += "\n### Certificate Changes\n\n"
    cert_added = [r for r in cert_results if r['added']]
    if cert_added:
        log += "**Added to Certificate:**\n"
        for r in cert_added:
            log += f"- ✅ `{r['dns_name']}`\n"
            log += f"  - Reason: {r['reason']}\n"
    
    cert_skipped = [r for r in cert_results if not r['added']]
    if cert_skipped:
        log += "\n**Skipped (Certificate):**\n"
        for r in cert_skipped:
            log += f"- ⏭️ `{r['dns_name']}`\n"
            log += f"  - Reason: {r['reason']}\n"
    
    log += "\n---\n"
    return log


def generate_pr_description(namespace: str, dns_names: List[str], gateway_results: List[Dict],
                            cert_results: List[Dict], repo_name: str = None) -> str:
    """Generate PR description"""
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    desc = "## 🔐 Certificate Automation - DNS Names Update\n\n"
    if repo_name:
        desc += f"**Repository:** `{repo_name}`\n"
    desc += f"**Namespace:** `{namespace}`\n"
    desc += f"**Automation Run:** {timestamp}\n\n"
    
    desc += "### 📋 DNS Names Requested\n\n"
    for i, dns in enumerate(dns_names, 1):
        desc += f"{i}. `{dns}`\n"
    
    gateway_added = [r for r in gateway_results if r['added']]
    gateway_skipped = [r for r in gateway_results if not r['added']]
    
    desc += f"\n### 🌐 Gateway Changes\n\n"
    desc += f"**Summary:** {len(gateway_added)} added, {len(gateway_skipped)} skipped\n\n"
    
    if gateway_added:
        desc += "#### ✅ Added to Gateway\n\n"
        for r in gateway_added:
            desc += f"- **`{r['dns_name']}`**\n"
            desc += f"  - 💡 {r['reason']}\n"
    
    cert_added = [r for r in cert_results if r['added']]
    cert_skipped = [r for r in cert_results if not r['added']]
    
    desc += f"\n### 📜 Certificate Changes\n\n"
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


def main():
    parser = argparse.ArgumentParser(description='Certificate Automation - Text-based')
    parser.add_argument('--input', help='JSON input file path')
    parser.add_argument('--gateway', default='gateway.yaml', help='Gateway YAML file')
    parser.add_argument('--certificate', default='ingress-gateway-certificate.yaml', help='Certificate YAML file')
    parser.add_argument('--namespace', help='Kubernetes namespace')
    parser.add_argument('--dns', nargs='+', help='DNS names to add')
    parser.add_argument('--repo-name', help='Repository name for audit')
    parser.add_argument('--create-audit', action='store_true', help='Create/update audit log')
    parser.add_argument('--audit-file', default='AUDIT.md', help='Audit log file path')
    
    args = parser.parse_args()
    
    # Load from JSON or command line
    if args.input:
        with open(args.input, 'r') as f:
            input_data = json.load(f)
        gateway_file = input_data.get('gateway_file', 'gateway.yaml')
        cert_file = input_data.get('certificate_file', 'ingress-gateway-certificate.yaml')
        namespace = input_data['namespace']
        dns_names = input_data['dns_names']
        repo_name = input_data.get('repo_name', args.repo_name)
    else:
        gateway_file = args.gateway
        cert_file = args.certificate
        namespace = args.namespace
        dns_names = args.dns
        repo_name = args.repo_name
    
    print(f"\n{'='*80}")
    print(f"Certificate Automation - Text-Based Processing")
    print(f"{'='*80}")
    print(f"Namespace: {namespace}")
    if repo_name:
        print(f"Repository: {repo_name}")
    print(f"DNS Names to add:")
    for i, dns in enumerate(dns_names, 1):
        print(f"  {i}. {dns}")
    print(f"{'='*80}\n")
    
    # Get credential name
    print("Finding TLS credential...")
    credential_name = get_credential_name_for_namespace_text(gateway_file, namespace)
    if not credential_name:
        print(f"ERROR: Could not find credential for namespace '{namespace}'")
        sys.exit(1)
    print(f"  Found credential: {credential_name}\n")
    
    # Process gateway
    print("Processing gateway hosts...")
    gateway_modified, gateway_results = add_dns_to_gateway_text(gateway_file, namespace, dns_names)
    
    # Process certificate
    print("\nProcessing certificate DNS names...")
    cert_modified, cert_results = add_dns_to_certificate_text(cert_file, credential_name, dns_names)
    
    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    print(f"Gateway: {len([r for r in gateway_results if r['added']])} added")
    print(f"Certificate: {len([r for r in cert_results if r['added']])} added")
    print(f"{'='*80}\n")
    
    # Generate audit and PR description
    if args.create_audit:
        audit_content = generate_audit_log(namespace, dns_names, gateway_results, cert_results, repo_name)
        
        # Append to audit file
        try:
            with open(args.audit_file, 'r') as f:
                existing = f.read()
        except FileNotFoundError:
            existing = "# Certificate Automation Audit Log\n\nThis file tracks all automated changes to gateway and certificate configurations.\n\n---\n"
        
        with open(args.audit_file, 'w') as f:
            f.write(existing + audit_content)
        print(f"✓ Updated audit log: {args.audit_file}")
        
        # Write PR description
        pr_desc = generate_pr_description(namespace, dns_names, gateway_results, cert_results, repo_name)
        with open('PR_DESCRIPTION.md', 'w') as f:
            f.write(pr_desc)
        print(f"✓ Generated PR description: PR_DESCRIPTION.md")


if __name__ == '__main__':
    main()
