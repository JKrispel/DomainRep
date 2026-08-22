import json
import time
import requests
import os
import datetime

CACHE_FILE = os.path.join("output", "vt_cache.json")
CACHE_TTL_SECONDS = 86400


def load_cache():

    if os.path.exists(CACHE_FILE):

        with open(CACHE_FILE, 'r', encoding='utf-8') as f:

            print(f"[+] Cached VirustTotal data loaded!")

            raw_data = json.load(f)
            now = time.time()
            clean_cache = {"domains": {}, "ips": {}}
            
            for category in ["domains", "ips"]:

                for item, content in raw_data.get(category, {}).items():

                    if isinstance(content, dict) and "cached_at" in content:

                        if now - content["cached_at"] < CACHE_TTL_SECONDS:

                            clean_cache[category][item] = content
                            
            return clean_cache
        
    return {"domains": {}, "ips": {}}


def save_cache(data):

    with open(CACHE_FILE, 'w', encoding='utf-8') as f:

        json.dump(data, f, indent=4)

    print("  [+] Saved to cache.")


def check_vt(identifier, api_key, indicator_type="domains"):

    headers = {

        "accept": "application/json",
        "x-apikey": api_key
    }
    
    url = f"https://www.virustotal.com/api/v3/{indicator_type}/{identifier}"

    while True:

        try:
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:

                data = response.json()

                return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            elif response.status_code == 404:

                print(f"  [-] Not found in VT (404): {identifier}")

                return {"malicious": 0, "suspicious": 0, "error": "404 Not Found"}
            
            elif response.status_code == 400:

                print(f"  [-] Invalid format / Bad Parsing (400): {identifier}")
                
                return {"malicious": 0, "suspicious": 0, "error": "400 Bad Request"}
                
            elif response.status_code in [401, 403]:

                print(f"  [-] Fatal API Error: HTTP {response.status_code} (Check your API Key)")

                return None

            elif response.status_code == 429:

                print("  [!] API Rate Limit exceeded! Waiting 60 seconds...")
                time.sleep(60)
                continue

            elif response.status_code >= 500:

                print(f"  [-] VT Server Error (HTTP {response.status_code}). Waiting 30 seconds...")
                time.sleep(30)
                continue

            else:
                print(f"  [-] Unexpected HTTP {response.status_code} for {identifier}")
                
                return None

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:

            print(f"  [-] Network error: {type(e).__name__}. Retrying in 30 seconds...")
            time.sleep(30)
            continue
            
        except requests.exceptions.RequestException as e:

            print(f"  [-] Unexpected request error: {e}. Retrying in 30 seconds...")
            time.sleep(30)
            continue


def run_vt_check(api_key, input_file, output_file):

    print(f"[*] Loading data from: {input_file}")

    with open(input_file, 'r', encoding='utf-8') as f:

        pcap_data = json.load(f)

    domains = pcap_data.get("domains", [])
    ips = pcap_data.get("public_ips", [])
    print(f"[*] To check: {len(domains)} domains and {len(ips)} IPs.")   
    cache = load_cache()
    run_results = {"domains": {}, "ips": {}}

    domains_to_check = []

    for d in domains:

        if d in cache["domains"]:

            run_results["domains"][d] = cache["domains"][d]["stats"]
        else:
            domains_to_check.append(d)

    ips_to_check = []

    for ip in ips:

        if ip in cache["ips"]:

            run_results["ips"][ip] = cache["ips"][ip]["stats"]
        else:
            ips_to_check.append(ip)

    print(f"[*] Remaining API checks: {len(domains_to_check)} domains and {len(ips_to_check)} IPs.")
    items_left = len(domains_to_check) + len(ips_to_check)

    for domain in domains_to_check:

        print(f"[>] Checking domain: {domain}... ({items_left} left, estimated time: {datetime.timedelta(seconds=items_left * 16)})")
        stats = check_vt(domain, api_key, "domains")

        if stats:

            cache["domains"][domain] = {

                "stats": stats,
                "cached_at": time.time()
            }          
            save_cache(cache)
            run_results["domains"][domain] = stats
            items_left -= 1
        else:
            return False            

        time.sleep(16) 

    for ip in ips_to_check:

        print(f"[>] Checking IP: {ip}... ({items_left} left, estimated time: {datetime.timedelta(seconds=items_left * 16)})")
        stats = check_vt(ip, api_key, "ip_addresses")

        if stats:

            cache["ips"][ip] = {

                "stats": stats,
                "cached_at": time.time()
            }
            save_cache(cache)           
            run_results["ips"][ip] = stats
            items_left -= 1           
        else:        
            return False   
        
        time.sleep(16)

    with open(output_file, 'w', encoding='utf-8') as f:

        json.dump(run_results, f, indent=4)

    print(f"\n[*] VirusTotal scanning completed! Results saved to: {output_file}")

    return True
