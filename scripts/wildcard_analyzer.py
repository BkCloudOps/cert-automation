#!/usr/bin/env python3
"""
Wildcard Suggestion Analyzer
Analyzes DNS patterns and suggests wildcard optimizations
"""

import json
import sys
import argparse
from typing import List, Dict, Set, Tuple
from collections import defaultdict
import re


def extract_domain_pattern(dns_name: str) -> str:
    """Extract the domain pattern including significant subdomains"""
    parts = dns_name.split('.')
    # Keep at least 3 parts (e.g., namespace.pod.cac.corp.aks.sunlife.com)
    # Don't reduce to just the TLD
    if len(parts) >= 4:
        return '.'.join(parts[1:])
    return dns_name


def find_common_pattern(hosts: List[str]) -> str:
    """Find common suffix pattern in hostnames"""
    if len(hosts) < 2:
        return None
    
    # Split all hosts into parts
    host_parts = [h.split('.') for h in hosts]
    
    # Find common suffix (working backwards)
    common_suffix = []
    min_length = min(len(parts) for parts in host_parts)
    
    for i in range(1, min_length + 1):
        suffixes = [parts[-i] for parts in host_parts]
        if len(set(suffixes)) == 1:  # All same
            common_suffix.insert(0, suffixes[0])
        else:
            break
    
    if len(common_suffix) >= 3:  # Require at least 3 domain parts
        return '.'.join(common_suffix)
    return None


def find_wildcard_pattern(hosts: List[str]) -> Tuple[str, str]:
    """Find a meaningful wildcard pattern for hosts"""
    if len(hosts) < 2:
        return None, None
    
    # Find common suffix
    common_suffix = find_common_pattern(hosts)
    if not common_suffix:
        return None, None
    
    # Get the prefixes (part before common suffix)
    prefixes = []
    for host in hosts:
        if host.endswith('.' + common_suffix):
            prefix = host[:-len('.' + common_suffix)]
            prefixes.append(prefix)
    
    # Check if prefixes have a pattern
    # Look for common endings like -chargeback, -api, etc.
    if len(prefixes) >= 2:
        # Check if all prefixes end with same pattern
        prefix_endings = [p.split('-')[-1] if '-' in p else p for p in prefixes]
        
        if len(set(prefix_endings)) == 1 and len(prefixes) >= 2:
            # Common ending pattern found
            if '-' in prefixes[0]:
                wildcard = f'*-{prefix_endings[0]}.{common_suffix}'
            else:
                wildcard = f'*.{common_suffix}'
            return wildcard, common_suffix
    
    # If no common pattern in prefix, just use generic wildcard
    # Require at least 3 parts (e.g., grafana.sunlife.ets)
    if len(common_suffix.split('.')) >= 3:
        return f'*.{common_suffix}', common_suffix
    
    return None, None


def analyze_existing_hosts(gateway_file: str, namespace: str) -> Tuple[List[str], Set[str]]:
    """Extract existing hosts and wildcards for a namespace"""
    with open(gateway_file, 'r') as f:
        lines = f.readlines()
    
    existing_hosts = []
    existing_wildcards = set()
    in_namespace = False
    
    for line in lines:
        stripped = line.strip()
        if f'{namespace}/' in stripped or f'"{namespace}/' in stripped:
            in_namespace = True
            if stripped.startswith('- '):
                host = stripped[2:].strip().strip('"').strip("'")
                if namespace in host:
                    clean_host = host.split('/', 1)[1] if '/' in host else host
                    if clean_host.startswith('*.'):
                        existing_wildcards.add(clean_host)
                    else:
                        existing_hosts.append(clean_host)
        elif in_namespace and 'port:' in stripped:
            break
    
    return existing_hosts, existing_wildcards


def analyze_certificate_hosts(cert_file: str, credential_name: str) -> List[str]:
    """Extract DNS names from certificate"""
    with open(cert_file, 'r') as f:
        content = f.read()
    
    documents = content.split('\n---\n')
    cert_hosts = []
    
    for doc in documents:
        if f'secretName: {credential_name}' in doc:
            lines = doc.split('\n')
            in_dns_section = False
            for line in lines:
                if 'dnsNames:' in line:
                    in_dns_section = True
                elif in_dns_section:
                    stripped = line.strip()
                    if stripped.startswith('- '):
                        dns = stripped[2:].strip()
                        cert_hosts.append(dns)
                    elif stripped and not stripped.startswith('-'):
                        break
    
    return cert_hosts


def get_credential_name(gateway_file: str, namespace: str) -> str:
    """Get credential name for namespace"""
    with open(gateway_file, 'r') as f:
        content = f.read()
    
    lines = content.split('\n')
    in_namespace_section = False
    
    for i, line in enumerate(lines):
        if f'{namespace}/' in line:
            in_namespace_section = True
        elif in_namespace_section and 'credentialName:' in line:
            return line.split('credentialName:')[1].strip()
        elif in_namespace_section and 'hosts:' in line and i > 0:
            in_namespace_section = False
    
    return None


def suggest_wildcards(existing_hosts: List[str], new_hosts: List[str], 
                      existing_wildcards: Set[str]) -> Dict:
    """Analyze and suggest wildcard patterns"""
    
    # Combine all hosts for analysis
    all_hosts = existing_hosts + new_hosts
    
    # Try different wildcard patterns by analyzing suffixes
    suggestions = []
    tested_wildcards = set()
    
    # For each host, try to find a wildcard pattern
    for host in all_hosts:
        parts = host.split('.')
        
        # Try wildcards at different levels
        # e.g., for bala.grafana.sunlife.ets, try:
        # - *.grafana.sunlife.ets
        # - *.sunlife.ets (too broad, skip if < 3 parts)
        for i in range(len(parts) - 2):  # Keep at least 3 parts after wildcard
            suffix_parts = parts[i+1:]
            if len(suffix_parts) < 3:  # Require at least 3 parts (e.g., grafana.sunlife.ets)
                continue
            
            suffix = '.'.join(suffix_parts)
            wildcard = f'*.{suffix}'
            
            if wildcard in tested_wildcards or wildcard in existing_wildcards:
                continue
            
            tested_wildcards.add(wildcard)
            
            # Find all hosts that would match this wildcard
            # Convert wildcard to regex: *.example.com -> ^[^.]+\.example\.com$
            wildcard_pattern = wildcard.replace('.', r'\.').replace('*', '[^.]+')
            wildcard_regex = re.compile(f'^{wildcard_pattern}$')
            
            covered_existing = []
            covered_new = []
            
            for h in existing_hosts:
                if wildcard_regex.match(h):
                    covered_existing.append(h)
            
            for h in new_hosts:
                if wildcard_regex.match(h):
                    covered_new.append(h)
            
            # Only suggest if it covers at least 2 hosts
            if len(covered_existing) + len(covered_new) >= 2:
                suggestions.append({
                    'wildcard': wildcard,
                    'pattern': suffix,
                    'would_cover_existing': covered_existing,
                    'would_cover_new': covered_new,
                    'total_covered': len(covered_existing) + len(covered_new),
                    'benefit': f'Replace {len(covered_existing) + len(covered_new)} individual entries with 1 wildcard'
                })
    
    return suggestions


def generate_report(namespace: str, suggestions: List[Dict], 
                   existing_hosts: List[str], new_hosts: List[str],
                   existing_wildcards: Set[str]) -> str:
    """Generate analysis report"""
    
    report = f"\n{'='*80}\n"
    report += f"Wildcard Optimization Analysis\n"
    report += f"{'='*80}\n\n"
    report += f"**Namespace:** `{namespace}`\n\n"
    
    report += f"### Current State\n\n"
    report += f"- Existing hosts: {len(existing_hosts)}\n"
    report += f"- Existing wildcards: {len(existing_wildcards)}\n"
    report += f"- New hosts requested: {len(new_hosts)}\n\n"
    
    if existing_wildcards:
        report += f"**Existing Wildcards:**\n"
        for wc in sorted(existing_wildcards):
            report += f"- `{wc}`\n"
        report += "\n"
    
    if not suggestions:
        report += f"### ✅ No Optimization Opportunities Found\n\n"
        report += f"Current configuration is already optimal or has insufficient entries for wildcards.\n"
    else:
        report += f"### 💡 Wildcard Suggestions ({len(suggestions)} found)\n\n"
        
        for idx, suggestion in enumerate(suggestions, 1):
            report += f"#### Suggestion {idx}: `{suggestion['wildcard']}`\n\n"
            report += f"**Benefit:** {suggestion['benefit']}\n\n"
            
            if suggestion['would_cover_existing']:
                report += f"**Would cover existing hosts ({len(suggestion['would_cover_existing'])}):**\n"
                for host in suggestion['would_cover_existing'][:5]:
                    report += f"- `{host}`\n"
                if len(suggestion['would_cover_existing']) > 5:
                    report += f"- ... and {len(suggestion['would_cover_existing']) - 5} more\n"
                report += "\n"
            
            if suggestion['would_cover_new']:
                report += f"**Would cover new hosts ({len(suggestion['would_cover_new'])}):**\n"
                for host in suggestion['would_cover_new']:
                    report += f"- `{host}`\n"
                report += "\n"
            
            report += f"**Action:** Add `{suggestion['wildcard']}` to gateway and remove individual entries\n\n"
            report += f"---\n\n"
    
    report += f"\n### 📊 Summary\n\n"
    report += f"- Total suggestions: {len(suggestions)}\n"
    if suggestions:
        total_savings = sum(s['total_covered'] for s in suggestions) - len(suggestions)
        report += f"- Potential reduction: {total_savings} entries\n"
    
    return report


def main():
    parser = argparse.ArgumentParser(description='Wildcard Suggestion Analyzer')
    parser.add_argument('--input', required=True, help='JSON input file')
    parser.add_argument('--gateway', default='gateway.yaml', help='Gateway file')
    parser.add_argument('--certificate', default='ingress-gateway-certificate.yaml', help='Certificate file')
    parser.add_argument('--output', default='WILDCARD_SUGGESTIONS.md', help='Output file')
    
    args = parser.parse_args()
    
    # Load input
    try:
        with open(args.input, 'r') as f:
            input_data = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Input file not found: {args.input}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {e}")
        sys.exit(1)
    
    # Handle both single and multi-namespace formats
    if 'requests' in input_data:
        requests = input_data['requests']
    else:
        requests = [{'namespace': input_data['namespace'], 'dns_names': input_data['dns_names']}]
    
    gateway_file = input_data.get('gateway_file', args.gateway)
    cert_file = input_data.get('certificate_file', args.certificate)
    
    all_reports = []
    
    for request in requests:
        namespace = request['namespace']
        new_hosts = request['dns_names']
        
        print(f"\nAnalyzing namespace: {namespace}")
        
        # Get credential name
        credential_name = get_credential_name(gateway_file, namespace)
        if not credential_name:
            print(f"  WARNING: Could not find credential for namespace '{namespace}'")
            continue
        
        # Analyze existing configuration
        existing_hosts, existing_wildcards = analyze_existing_hosts(gateway_file, namespace)
        cert_hosts = analyze_certificate_hosts(cert_file, credential_name)
        
        print(f"  Existing hosts: {len(existing_hosts)}")
        print(f"  Existing wildcards: {len(existing_wildcards)}")
        print(f"  Certificate hosts: {len(cert_hosts)}")
        print(f"  New hosts: {len(new_hosts)}")
        
        # Generate suggestions
        suggestions = suggest_wildcards(existing_hosts, new_hosts, existing_wildcards)
        
        print(f"  Suggestions: {len(suggestions)}")
        
        # Generate report
        report = generate_report(namespace, suggestions, existing_hosts, new_hosts, existing_wildcards)
        all_reports.append(report)
    
    # Write combined report
    final_report = "# Wildcard Optimization Suggestions\n\n"
    final_report += "This report analyzes DNS patterns and suggests wildcard optimizations.\n\n"
    final_report += ''.join(all_reports)
    
    with open(args.output, 'w') as f:
        f.write(final_report)
    
    print(f"\n✅ Analysis complete! Report saved to: {args.output}")


if __name__ == '__main__':
    main()
