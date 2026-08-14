import pyshark
import json
import ipaddress


def is_public_ip(ip_str):

    try:
        ip = ipaddress.ip_address(ip_str)

        return not ip.is_private and not ip.is_loopback and not ip.is_multicast
    
    except ValueError:

        return False


def is_external_domain(domain_str, internal_domain=None):
   
    if not domain_str:
        return False
        
    domain_str = domain_str.lower()
    
    if '.' not in domain_str:        
        return False
        
    if domain_str.endswith('.arpa'):
        return False
        
    if domain_str.endswith(('.local', '.lan', '.corp', '.home', '.internal')):
        return False
        
    if domain_str.startswith('_') or '._' in domain_str:
        return False
        
    if internal_domain and domain_str.endswith(internal_domain):
        return False
        
    return True


def parse_pcap_to_json(pcap_path, output_path, internal_domain=None):

    print(f"[*] Analysing file: {pcap_path} ...")  

    data = {  # Using set() to not store duplicate entries

        "domains": set(),
        "public_ips": set()
    }
    
    cap = pyshark.FileCapture(
        pcap_path, 
        display_filter="dns or http or tls.handshake.type == 1"
    )

    for pkt in cap:

        # Public IPs
        if hasattr(pkt, 'ip'):

            if is_public_ip(pkt.ip.dst):

                data["public_ips"].add(pkt.ip.dst)

        # DNS requests -> domains
        if hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name'):

            domain = pkt.dns.qry_name

            if is_external_domain(domain, internal_domain):

                data["domains"].add(domain)

        # HTTP Host -> domains
        if hasattr(pkt, 'http') and hasattr(pkt.http, 'host'):

            domain = pkt.http.host

            if is_external_domain(domain, internal_domain):

                data["domains"].add(domain)

        # TLS SNI -> domains
        if hasattr(pkt, 'tls') and hasattr(pkt.tls, 'handshake_extensions_server_name'):

            domain = pkt.tls.handshake_extensions_server_name

            if is_external_domain(domain, internal_domain):

                data["domains"].add(domain)

    cap.close()

    export_data = {

        "domains": list(data["domains"]),
        "public_ips": list(data["public_ips"])
    }

    with open(output_path, 'w', encoding='utf-8') as f:

        json.dump(export_data, f, indent=4)
        
    print(f"[+] Parsing completed. Data saved to: {output_path}")
