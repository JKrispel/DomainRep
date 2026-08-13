import pyshark
import json
import ipaddress


def is_public_ip(ip_str):

    try:
        ip = ipaddress.ip_address(ip_str)

        return not ip.is_private and not ip.is_loopback and not ip.is_multicast
    
    except ValueError:

        return False


def parse_pcap_to_json(pcap_path, output_path):
    print(f"[*] Analiza pliku: {pcap_path} ...")
    
    # set() to not store duplicate entries
    data = {
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

            data["domains"].add(pkt.dns.qry_name)

        # HTTP Host -> domains
        if hasattr(pkt, 'http') and hasattr(pkt.http, 'host'):

            data["domains"].add(pkt.http.host)

        # TLS SNI -> domains
        if hasattr(pkt, 'tls') and hasattr(pkt.tls, 'handshake_extensions_server_name'):

            data["domains"].add(pkt.tls.handshake_extensions_server_name)

    cap.close()

    export_data = {

        "domains": list(data["domains"]),
        "public_ips": list(data["public_ips"])
    }

    with open(output_path, 'w', encoding='utf-8') as f:

        json.dump(export_data, f, indent=4)
        
    print(f"[+] Zakończono parsowanie. Dane zapisano w: {output_path}")
