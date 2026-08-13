import json
import time
import requests
import os
import datetime


def load_progress(output_file):

    if os.path.exists(output_file):

        with open(output_file, 'r', encoding='utf-8') as f:

            print(f"[+] Previous progress loaded!")

            return json.load(f)
        
    return {"domains": {}, "ips": {}}


def save_progress(data, output_file):

    with open(output_file, 'w', encoding='utf-8') as f:

        json.dump(data, f, indent=4)

    print("  [+] Progress saved.")


def check_vt(identifier, api_key, indicator_type="domains"):

    headers = {

        "accept": "application/json",
        "x-apikey": api_key
    }
    
    url = f"https://www.virustotal.com/api/v3/{indicator_type}/{identifier}"

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:

            data = response.json()

            return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        
        elif response.status_code == 429:

            print("  [!] API Rate Limit exceeded! Waiting 60 seconds...")
            time.sleep(60)

            return check_vt(identifier, api_key, indicator_type)
        
        else:
            print(f"  [-] API Error for {identifier}: {response.status_code}")

            return None
        
    except requests.exceptions.Timeout:

        print(f"  [-] Timeout: Serwer VirusTotal nie odpowiedział w ciągu 10s.")

        return None

    except requests.exceptions.ConnectionError:

        print(f"  [-] Błąd połączenia: Brak internetu lub problem z DNS.")

        return None

    except requests.exceptions.RequestException as e:

        print(f"  [-] Inny błąd HTTP/requests: {e}")

        return None


def run_vt_check(api_key, input_file, output_file):

    print(f"[*] Loading data from: {input_file}")

    with open(input_file, 'r', encoding='utf-8') as f:

        pcap_data = json.load(f)

    domains = pcap_data.get("domains", [])
    ips = pcap_data.get("public_ips", [])
    print(f"[*] To check: {len(domains)} domains and {len(ips)} IPs.")   
    results = load_progress(output_file)
    domains_to_check = [d for d in domains if d not in results["domains"]]
    ips_to_check = [ip for ip in ips if ip not in results["ips"]]
    print(f"[*] Remaining API checks: {len(domains_to_check)} domains and {len(ips_to_check)} IPs.")
    items_left = len(domains_to_check) + len(ips_to_check)

    for domain in domains_to_check:

        print(f"[>] Checking domain: {domain}... ({items_left} left, estimated time: {datetime.timedelta(seconds=items_left * 16)})")
        stats = check_vt(domain, api_key, "domains")

        if stats:

            results["domains"][domain] = stats
            save_progress(results, output_file)
            items_left -= 1
        else:
            return False            

        time.sleep(16) 

    for ip in ips_to_check:

        print(f"[>] Checking IP: {ip}... ({items_left} left, estimated time: {datetime.timedelta(seconds=items_left * 16)})")
        stats = check_vt(ip, api_key, "ip_addresses")

        if stats:

            results["ips"][ip] = stats
            save_progress(results, output_file)
            items_left -= 1
        else:
            return False   
        
        time.sleep(16)

    print(f"\n[*] VirusTotal scanning complete! Results saved to: {output_file}")

    return True
