import json
import requests
from pathlib import Path


def filter_vt_data(vt_file, sus_file):

    print(f"[*] Filtering clean indicators from {vt_file}...")
    
    try:
        with open(vt_file, 'r', encoding='utf-8') as f:

            vt_data = json.load(f)

    except Exception as e:

        print(f"[-] Error loading {vt_file}: {e}")
        return None

    sus_data = {
        "malicious_domains": {},
        "malicious_ips": {},
        "suspicious_domains": {},
        "suspicious_ips": {}
    }

    errors_data = {
        "domains": {},
        "ips": {}
    }

    def categorize(indicators, indicator_type):

        for item, stats in indicators.items():
            
            if stats.get("error"):  # didn't get VirusTotal check, manual investigation needed

                if indicator_type == "domain":

                    errors_data["domains"][item] = stats
                else:
                    errors_data["ips"][item] = stats
                continue
        
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:

                if indicator_type == "domain":

                    sus_data["malicious_domains"][item] = stats
                else:
                    sus_data["malicious_ips"][item] = stats

            elif suspicious > 0:

                if indicator_type == "domain":

                    sus_data["suspicious_domains"][item] = stats
                else:
                    sus_data["suspicious_ips"][item] = stats

    categorize(vt_data.get("domains", {}), "domain")
    categorize(vt_data.get("ips", {}), "ip")

    with open(sus_file, 'w', encoding='utf-8') as f:

        json.dump(sus_data, f, indent=4)

    # Derive errors file path
    vt_path = Path(vt_file)
    error_filename = vt_path.name.replace("vt_rep_", "errors_")
    error_file = vt_path.parent / error_filename
    # Save errors if any occurred
    total_errors = len(errors_data["domains"]) + len(errors_data["ips"])

    if total_errors > 0:

        with open(error_file, 'w', encoding='utf-8') as f:

            json.dump(errors_data, f, indent=4)
            
        print(f"[!] Saved {total_errors} errors/404s to {error_file}")

    total_suspicious = sum(len(v) for v in sus_data.values())
    print(f"[+] Found {total_suspicious} suspicious/malicious indicators.")
    print(f"[*] Filtered data saved to {sus_file}")
    
    return sus_data


def generate_report(sus_data, report_file):

    print("[*] Contacting local LLM (LM Studio) to generate report...")  
    total_threats = sum(len(v) for v in sus_data.values())

    if total_threats == 0:

        print("[!] No malicious or suspicious indicators found. Generating empty report.")

        with open(report_file, 'w', encoding='utf-8') as f:

            f.write("# Incident Report\n\nNo malicious or suspicious indicators were detected in the provided PCAP file.")

        print(f"[+] Report saved to {report_file}")
        return

    # Load optional example report to enforce strict output layout (1-Shot Prompting)
    example_path = Path("src/example_report.md")
    example_text = ""
    
    if example_path.exists():

        print("[*] Found 'example_report.md'. Including layout example in the prompt...")

        with open(example_path, 'r', encoding='utf-8') as f:

            example_text = f.read()

    url = "http://localhost:1234/v1/chat/completions"
    

    system_prompt = """You are a highly skilled Tier 3 SOC Analyst and Malware Analyst. 
        Your task is to analyze the provided JSON containing network indicators (Domains and IPs) categorized by their VirusTotal reputation.
        Write a professional Incident Report in Markdown format.
        You MUST strictly follow the structural style, section naming, table formatting, and tone shown in the provided example report.
        Make sure all IP addresses and domain names are mentioned"""

    user_prompt = ""

    if example_text:

        user_prompt += f"### EXPECTED OUTPUT LAYOUT AND STYLE EXAMPLE:\n{example_text}\n\n---\n\n"
        
    user_prompt += f"### INPUT DATA TO ANALYZE:\n{json.dumps(sus_data, indent=2)}\n\n"
    user_prompt += "Generate the incident report for the INPUT DATA following the exact layout style from the example above."

    payload = {

        "model": "local-model",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.2,
        "max_tokens": 2048
    }
    
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        
        response_data = response.json()
        report_content = response_data['choices'][0]['message']['content']
        
        with open(report_file, 'w', encoding='utf-8') as f:

            f.write(report_content)
            
        print(f"[+] LLM Report generated successfully and saved to: {report_file}")
        
    except requests.exceptions.ConnectionError:

        print("[-] ERROR: Could not connect to LM Studio.")
        print("[-] Please ensure LM Studio is open, a model is loaded, and the Local Server is running on port 1234.")

    except Exception as e:

        print(f"[-] An error occurred during LLM generation: {e}")


def run_llm_pipeline(vt_file, sus_file, report_file):

    sus_data = filter_vt_data(vt_file, sus_file)

    if sus_data is not None:

        generate_report(sus_data, report_file)
        