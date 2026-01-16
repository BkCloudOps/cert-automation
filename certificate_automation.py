#!/usr/bin/env python3
"""
Certificate Automation Script
Automates adding DNS names to Istio Gateway and cert-manager Certificate resources
"""

import yaml
import json
import sys
import argparse
from typing import List, Dict, Any, Tuple
from copy import deepcopy
from datetime import datetime


def yaml_to_json(yaml_file: str) -> Dict[Any, Any]:
    """Convert YAML file to Python dict (JSON-like structure)"""
    with open(yaml_file, 'r') as f:
        return yaml.safe_load(f)


def yaml_documents_to_json(yaml_file: str) -> List[Dict[Any, Any]]:
    """Convert multi-document YAML file to list of Python dicts"""
    with open(yaml_file, 'r') as f:
        return list(yaml.safe_load_all(f))


def json_to_yaml(data: Any, yaml_file: str):
    """Convert Python dict to YAML file"""
    with open(yaml_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


def json_documents_to_yaml(documents: List[Dict[Any, Any]], yaml_file: str):
    """Convert list of Python dicts to multi-document YAML file"""
    with open(yaml_file, 'w') as f:
        yaml.dump_all(documents, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


def get_wildcard_patterns(dns_name: str) -> List[str]:
    """
    Generate wildcard patterns for a DNS name.
    For example: 'pie-alicloud-chargeback.platform-insights.prod.cac.corp.aks.manulife.com'
    Returns: ['*.platform-insights.prod.cac.corp.aks.manulife.com', '*.prod.cac.corp.aks.manulife.com']
    """
    parts = dns_name.split('.')
    patterns = []
    
    # Generate wildcard patterns for the last 2+ dot levels
    for i in range(1, len(parts) - 1):  # Skip the last part (TLD/base)
        pattern = '*.' + '.'.join(parts[i:])
        patterns.append(pattern)
    
    return patterns


def is_covered_by_wildcard(dns_name: str, existing_hosts: List[str]) -> Tuple[bool, str]:
    """
    Check if a DNS name is covered by existing wildcard patterns.
    Returns: (is_covered, reason)
    """
    # Check for exact match
    if dns_name in existing_hosts:
        return True, f"Exact match found in gateway hosts"
    
    # Check for wildcard patterns
    wildcard_patterns = get_wildcard_patterns(dns_name)
    for pattern in wildcard_patterns:
        if pattern in existing_hosts:
            return True, f"Covered by wildcard pattern: {pattern}"
    
    return False, "No matching host or wildcard pattern found"


def find_namespace_server_blocks(gateway_data: Dict[Any, Any], namespace: str) -> List[int]:
    """
    Find the server block indices for a given namespace in gateway.yaml
    Returns list of indices where the namespace hosts are defined
    """
    indices = []
    servers = gateway_data.get('spec', {}).get('servers', [])
    
    for idx, server in enumerate(servers):
        hosts = server.get('hosts', [])
        # Check if any host starts with the namespace prefix
        for host in hosts:
            if isinstance(host, str) and host.startswith(f"{namespace}/"):
                indices.append(idx)
                break
    
    return indices


def get_credential_name_for_namespace(gateway_data: Dict[Any, Any], namespace: str) -> str:
    """
    Get the TLS credential name for a namespace from the gateway
    """
    servers = gateway_data.get('spec', {}).get('servers', [])
    
    for server in servers:
        hosts = server.get('hosts', [])
        # Check if this server block is for the namespace and has HTTPS
        is_namespace = False
        for host in hosts:
            if isinstance(host, str) and host.startswith(f"{namespace}/"):
                is_namespace = True
                break
        
        if is_namespace and server.get('port', {}).get('protocol') == 'HTTPS':
            return server.get('tls', {}).get('credentialName', '')
    
    return ''


def add_dns_to_gateway(gateway_data: Dict[Any, Any], namespace: str, dns_names: List[str]) -> Tuple[Dict[Any, Any], List[Dict[str, str]]]:
    """
    Add DNS names to gateway.yaml for a specific namespace.
    Returns updated gateway data and list of dicts with DNS names and reasons.
    """
    gateway_results = []
    servers = gateway_data.get('spec', {}).get('servers', [])
    
    # Find the HTTPS server block for this namespace
    https_server_idx = None
    http_server_idx = None
    
    for idx, server in enumerate(servers):
        hosts = server.get('hosts', [])
        is_namespace = any(isinstance(h, str) and h.startswith(f"{namespace}/") for h in hosts)
        
        if is_namespace:
            if server.get('port', {}).get('protocol') == 'HTTPS':
                https_server_idx = idx
            elif server.get('port', {}).get('protocol') == 'HTTP':
                http_server_idx = idx
    
    if https_server_idx is None:
        print(f"Warning: No HTTPS server block found for namespace '{namespace}'")
        return gateway_data, gateway_results
    
    # Get existing hosts (handle YAML anchors by getting the actual list)
    https_hosts = servers[https_server_idx].get('hosts', [])
    if isinstance(https_hosts, list):
        existing_hosts = [h.split('/', 1)[1] if '/' in h else h for h in https_hosts]
    else:
        existing_hosts = []
    
    # Check each DNS name
    for dns_name in dns_names:
        is_covered, reason = is_covered_by_wildcard(dns_name, existing_hosts)
        
        if not is_covered:
            # Need to add this host
            namespaced_host = f"{namespace}/{dns_name}"
            https_hosts.append(namespaced_host)
            gateway_results.append({
                'dns_name': dns_name,
                'added': True,
                'reason': reason
            })
            print(f"  ✓ Adding host to gateway: {dns_name}")
            print(f"    Reason: {reason}")
        else:
            gateway_results.append({
                'dns_name': dns_name,
                'added': False,
                'reason': reason
            })
            print(f"  ○ Skipping gateway (already covered): {dns_name}")
            print(f"    Reason: {reason}")
    
    # Update both HTTPS and HTTP blocks with the same hosts
    servers[https_server_idx]['hosts'] = https_hosts
    if http_server_idx is not None:
        servers[http_server_idx]['hosts'] = https_hosts
    
    return gateway_data, gateway_results


def add_dns_to_certificate(cert_documents: List[Dict[Any, Any]], credential_name: str, dns_names: List[str]) -> Tuple[List[Dict[Any, Any]], List[Dict[str, str]]]:
    """
    Add DNS names to the certificate with matching credentialName.
    Returns updated certificate documents and list of dicts with DNS names and reasons.
    """
    cert_results = []
    
    # Find the certificate with matching secretName
    for cert in cert_documents:
        if cert.get('kind') != 'Certificate':
            continue
        
        secret_name = cert.get('spec', {}).get('secretName', '')
        if secret_name == credential_name:
            dns_list = cert.get('spec', {}).get('dnsNames', [])
            
            for dns_name in dns_names:
                if dns_name not in dns_list:
                    dns_list.append(dns_name)
                    cert_results.append({
                        'dns_name': dns_name,
                        'added': True,
                        'reason': 'DNS name must be explicitly listed in certificate for TLS validation'
                    })
                    print(f"  ✓ Adding DNS to certificate: {dns_name}")
                    print(f"    Reason: DNS name must be explicitly listed in certificate for TLS validation")
                else:
                    cert_results.append({
                        'dns_name': dns_name,
                        'added': False,
                        'reason': 'DNS name already exists in certificate'
                    })
                    print(f"  ○ Skipping certificate (already exists): {dns_name}")
                    print(f"    Reason: DNS name already exists in certificate")
            
            cert['spec']['dnsNames'] = dns_list
            break
    
    return cert_documents, cert_results


def process_certificate_request(
    gateway_file: str,
    certificate_file: str,
    namespace: str,
    dns_names: List[str],
    output_gateway: str = None,
    output_certificate: str = None,
    repo_name: str = None,
    create_audit: bool = False,
    audit_file: str = "AUDIT.md"
):
    """
    Main processing function to add DNS names to gateway and certificate files.
    """
    print(f"\n{'='*80}")
    print(f"Certificate Automation - Processing Request")
    print(f"{'='*80}")
    print(f"Namespace: {namespace}")
    if repo_name:
        print(f"Repository: {repo_name}")
    print(f"DNS Names to add:")
    for i, dns in enumerate(dns_names, 1):
        print(f"  {i}. {dns}")
    print(f"{'='*80}\n")
    
    # Set default output files - modify in place for CI/CD
    if output_gateway is None:
        output_gateway = gateway_file
    
    if output_certificate is None:
        output_certificate = certificate_file
    
    # Step 1: Load gateway.yaml
    print("Step 1: Loading gateway.yaml...")
    gateway_data = yaml_to_json(gateway_file)
    print(f"  Loaded gateway: {gateway_data['metadata']['name']}")
    
    # Step 2: Load ingress-gateway-certificate.yaml
    print("\nStep 2: Loading certificate.yaml...")
    cert_documents = yaml_documents_to_json(certificate_file)
    print(f"  Loaded {len(cert_documents)} certificate documents")
    
    # Step 3: Get credential name for namespace
    print(f"\nStep 3: Finding TLS credential for namespace '{namespace}'...")
    credential_name = get_credential_name_for_namespace(gateway_data, namespace)
    if not credential_name:
        print(f"  ERROR: Could not find credential name for namespace '{namespace}'")
        return
    print(f"  Found credential: {credential_name}")
    
    # Step 4: Add DNS names to gateway
    print(f"\nStep 4: Processing gateway hosts...")
    print(f"{'─'*80}")
    gateway_data, gateway_results = add_dns_to_gateway(gateway_data, namespace, dns_names)
    
    # Step 5: Add DNS names to certificate
    print(f"\n{'─'*80}")
    print(f"Step 5: Processing certificate DNS names...")
    print(f"{'─'*80}")
    cert_documents, cert_results = add_dns_to_certificate(cert_documents, credential_name, dns_names)
    
    # Step 6: Save updated files
    print(f"\n{'─'*80}")
    print(f"Step 6: Saving updated files...")
    json_to_yaml(gateway_data, output_gateway)
    print(f"  Saved gateway to: {output_gateway}")
    
    json_documents_to_yaml(cert_documents, output_certificate)
    print(f"  Saved certificates to: {output_certificate}")
    
    # Detailed Summary
    print(f"\n{'='*80}")
    print("SUMMARY REPORT")
    print(f"{'='*80}")
    
    # Gateway summary
    gateway_added = [r for r in gateway_results if r['added']]
    gateway_skipped = [r for r in gateway_results if not r['added']]
    
    print(f"\n📋 Gateway Changes:")
    print(f"  • Hosts added: {len(gateway_added)}")
    print(f"  • Hosts skipped: {len(gateway_skipped)}")
    
    if gateway_added:
        print(f"\n  Added to gateway:")
        for result in gateway_added:
            print(f"    ✓ {result['dns_name']}")
            print(f"      └─ {result['reason']}")
    
    if gateway_skipped:
        print(f"\n  Skipped (already covered):")
        for result in gateway_skipped:
            print(f"    ○ {result['dns_name']}")
            print(f"      └─ {result['reason']}")
    
    # Certificate summary
    cert_added = [r for r in cert_results if r['added']]
    cert_skipped = [r for r in cert_results if not r['added']]
    
    print(f"\n📜 Certificate Changes:")
    print(f"  • DNS names added: {len(cert_added)}")
    print(f"  • DNS names skipped: {len(cert_skipped)}")
    
    if cert_added:
        print(f"\n  Added to certificate:")
        for result in cert_added:
            print(f"    ✓ {result['dns_name']}")
            print(f"      └─ {result['reason']}")
    
    if cert_skipped:
        print(f"\n  Skipped (already in certificate):")
        for result in cert_skipped:
            print(f"    ○ {result['dns_name']}")
            print(f"      └─ {result['reason']}")
    
    print(f"\n{'='*80}")
    print("ℹ️  Key Information:")
    print(f"  • Gateway uses wildcards (*.domain.com) to route traffic")
    print(f"  • Certificates must list each DNS name explicitly for TLS validation")
    print(f"  • Even if a DNS is covered by a wildcard in the gateway,")
    print(f"    it still needs to be added to the certificate if new")
    print(f"{'='*80}\n")
    
    # Generate audit log and PR description
    generate_audit_log(
    namespace: str,
    dns_names: List[str],
    gateway_results: List[Dict[str, str]],
    cert_results: List[Dict[str, str]],
    repo_name: str = None
) -> str:
    """Generate audit log content"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    content = f"\n## Automation Run - {timestamp}\n\n"
    if repo_name:
        content += f"**Repository:** `{repo_name}`\n\n"
    content += f"**Namespace:** `{namespace}`\n\n"
    
    content += "**DNS Names Requested:**\n"
    for i, dns in enumerate(dns_names, 1):
        content += f"{i}. `{dns}`\n"
    content += "\n"
    
    content += "### Gateway Changes\n\n"
    gateway_added = [r for r in gateway_results if r['added']]
    gateway_skipped = [r for r in gateway_results if not r['added']]
    
    if gateway_added:
        content += "**Added to Gateway:**\n"
        for r in gateway_added:
            content += f"- ✅ `{r['dns_name']}`\n"
            content += f"  - Reason: {r['reason']}\n"
    else:
        content += "**Added to Gateway:** None\n"
    
    if gateway_skipped:
        content += "\n**Skipped (Already Covered):**\n"
        for r in gateway_skipped:
            content += f"- ⏭️  `{r['dns_name']}`\n"
            content += f"  - Reason: {r['reason']}\n"
    
    content += "\n### Certificate Changes\n\n"
    cert_added = [r for r in cert_results if r['added']]
    cert_skipped = [r for r in cert_results if not r['added']]
    
    if cert_added:
        content += "**Added to Certificate:**\n"
        for r in cert_added:
            content += f"- ✅ `{r['dns_name']}`\n"
            content += f"  - Reason: {r['reason']}\n"
    else:
        content += "**Added to Certificate:** None\n"
    
    if cert_skipped:
        content += "\n**Skipped (Already Exists):**\n"
        for r in cert_skipped:
            content += f"- ⏭️  `{r['dns_name']}`\n"
            content += f"  - Reason: {r['reason']}\n"
    
    content += "\n---\n"
    return content


def generate_pr_description(
    namespace: str,
    parser.add_argument(
        '--repo-name',
        help='Repository name for audit logging (e.g., myorg/my-k8s-configs)'
    )
    
    parser.add_argument(
        '--create-audit',
        action='store_true',
        help='Create/update audit log and PR description'
    )
    
    parser.add_argument(
        '--audit-file',
        repo_name = input_data.get('repo_name', args.repo_name)
        
        if not namespace:
            print("ERROR: 'namespace' is required in JSON input")
            sys.exit(1)
        if not dns_names:
            print("ERROR: 'dns_names' list is required in JSON input")
            sys.exit(1)
    else:
        # Use command line arguments
        if not args.namespace:
            print("ERROR: --namespace is required when not using --input")
            parser.print_help()
            sys.exit(1)
        if not args.dns:
            print("ERROR: --dns is required when not using --input")
            parser.print_help()
            sys.exit(1)
        
        gateway_file = args.gateway
        certificate_file = args.certificate
        namespace = args.namespace
        dns_names = args.dns
        output_gateway = args.output_gateway
        output_certificate = args.output_certificate
        repo_name = args.repo_name
    
    process_certificate_request(
        gateway_file=gateway_file,
        certificate_file=certificate_file,
        namespace=namespace,
        dns_names=dns_names,
        output_gateway=output_gateway,
        output_certificate=output_certificate,
        repo_name=repo_name,
        create_audit=args.create_audit,
        audit_file=args.audit_fil
            description += f"- **`{r['dns_name']}`**\n"
            description += f"  - 💡 {r['reason']}\n\n"
    
    if gateway_skipped:
        description += "#### ⏭️  Skipped (Already Covered by Wildcards)\n\n"
        for r in gateway_skipped:
            description += f"- **`{r['dns_name']}`**\n"
            description += f"  - 💡 {r['reason']}\n\n"
    
    description += "### 📜 Certificate Changes\n\n"
    description += f"**Summary:** {len(cert_added)} added, {len(cert_skipped)} skipped\n\n"
    
    if cert_added:
        description += "#### ✅ Added to Certificate\n\n"
        for r in cert_added:
            description += f"- **`{r['dns_name']}`**\n"
            description += f"  - 💡 {r['reason']}\n\n"
    
    if cert_skipped:
        description += "#### ⏭️  Skipped (Already in Certificate)\n\n"
        for r in cert_skipped:
            description += f"- **`{r['dns_name']}`**\n"
            description += f"  - 💡 {r['reason']}\n\n"
    
    description += "---\n\n"
    description += "### ℹ️  Key Information\n\n"
    description += "- Gateway uses wildcards (`*.domain.com`) to route traffic efficiently\n"
    description += "- Certificates must list each DNS name explicitly for TLS validation\n"
    description += "- Even if a DNS is covered by a wildcard in the gateway, it still needs to be in the certificate\n\n"
    description += "---\n\n"
    description += "🤖 *This PR was automatically generated by the Certificate Automation workflow*\n"
    
    return description


def append_to_audit_file(audit_file: str, content: str):
    """Append content to audit file, create if doesn't exist"""
    import os
    
    if not os.path.exists(audit_file):
        with open(audit_file, 'w') as f:
            f.write("# Certificate Automation Audit Log\n\n")
            f.write("This file tracks all automated changes to gateway and certificate configurations.\n\n")
            f.write("---\n")
    
    with open(audit_file, 'a') as f:
        f.write(content)


def if create_audit:
        audit_content = generate_audit_log(
            namespace=namespace,
            dns_names=dns_names,
            gateway_results=gateway_results,
            cert_results=cert_results,
            repo_name=repo_name
        )
        append_to_audit_file(audit_file, audit_content)
        
        pr_description = generate_pr_description(
            namespace=namespace,
            dns_names=dns_names,
            gateway_results=gateway_results,
            cert_results=cert_results,
            repo_name=repo_name
        )
        
        # Write PR description to file for GitHub Actions to use
        with open('PR_DESCRIPTION.md', 'w') as f:
            f.write(pr_description)
        print(f"✓ Generated PR description: PR_DESCRIPTION.md")
        print(f"✓ Updated audit log: {audit_file}")
    
    return {
        'gateway_results': gateway_results,
        'cert_results': cert_results,
        'gateway_added': len([r for r in gateway_results if r['added']]),
        'cert_added': len([r for r in cert_results if r['added']])
    }


def load_input_from_json(json_file: str) -> Dict[str, Any]:
    """Load input parameters from JSON file"""
    with open(json_file, 'r') as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(
        description='Automate adding DNS names to Istio Gateway and cert-manager Certificates',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example usage (with JSON input):
  python3 certificate_automation.py --input input_data.json

Example usage (with command line args):
  python3 certificate_automation.py \\
    --namespace platform-insights \\
    --dns alicloud-chargeback.manulife.ets \\
    --dns databricks-chargeback.manulife.ets \\
    --dns aks-chargeback.manulife.ets
        '''
    )
    
    parser.add_argument(
        '--input',
        '-i',
        help='Path to JSON input file with request parameters'
    )
    
    parser.add_argument(
        '--gateway',
        default='gateway.yaml',
        help='Path to gateway.yaml file (default: gateway.yaml)'
    )
    
    parser.add_argument(
        '--certificate',
        default='ingress-gateway-certificate.yaml',
        help='Path to certificate.yaml file (default: ingress-gateway-certificate.yaml)'
    )
    
    parser.add_argument(
        '--namespace',
        help='Namespace for the DNS names (e.g., platform-insights)'
    )
    
    parser.add_argument(
        '--dns',
        action='append',
        help='DNS name to add (can be specified multiple times)'
    )
    
    parser.add_argument(
        '--output-gateway',
        help='Output path for updated gateway.yaml (default: gateway_updated_TIMESTAMP.yaml)'
    )
    
    parser.add_argument(
        '--output-certificate',
        help='Output path for updated certificate.yaml (default: ingress-gateway-certificate_updated_TIMESTAMP.yaml)'
    )
    
    args = parser.parse_args()
    
    # Load from JSON input file or command line arguments
    if args.input:
        print(f"Loading input from JSON file: {args.input}\n")
        input_data = load_input_from_json(args.input)
        
        gateway_file = input_data.get('gateway_file', 'gateway.yaml')
        certificate_file = input_data.get('certificate_file', 'ingress-gateway-certificate.yaml')
        namespace = input_data.get('namespace')
        dns_names = input_data.get('dns_names', [])
        output_gateway = input_data.get('output_gateway')
        output_certificate = input_data.get('output_certificate')
        
        if not namespace:
            print("ERROR: 'namespace' is required in JSON input")
            sys.exit(1)
        if not dns_names:
            print("ERROR: 'dns_names' list is required in JSON input")
            sys.exit(1)
    else:
        # Use command line arguments
        if not args.namespace:
            print("ERROR: --namespace is required when not using --input")
            parser.print_help()
            sys.exit(1)
        if not args.dns:
            print("ERROR: --dns is required when not using --input")
            parser.print_help()
            sys.exit(1)
        
        gateway_file = args.gateway
        certificate_file = args.certificate
        namespace = args.namespace
        dns_names = args.dns
        output_gateway = args.output_gateway
        output_certificate = args.output_certificate
    
    process_certificate_request(
        gateway_file=gateway_file,
        certificate_file=certificate_file,
        namespace=namespace,
        dns_names=dns_names,
        output_gateway=output_gateway,
        output_certificate=output_certificate
    )


if __name__ == '__main__':
    main()
