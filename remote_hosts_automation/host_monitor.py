####
# Acts as an event producer for backend_listener.py (or SOAR)
##
# Requirements:
#   - Suricata service running (with .pcap logs).
#   - Cloud storage implementing S3-compatible API (e.g. Clouflare R2 Object Storage).
#   - Python 3+ and automation_requirements.txt modules installed.
#   - Correct config variables below.
#   - This script running as a service.
##
# For more detailed instructions read AUTOMATION.md
####
import glob
import json
import os
import subprocess
import time

import requests

# --- CONFIG ---
EVE_JSON_PATH = "/var/log/suricata/eve.json"  # Suricata log file
PCAP_DIR = "/var/log/suricata/"  # enable .pcap logs in Suricata
CLOUDFLARE_ACCOUNT_ID = "YOUR_ACCOUNT_ID_R2"
BUCKET_NAME = "your-bucket-name-r2"
WEBHOOK_URL = "https://shuffler.io/api/v1/hooks/YOUR_SHUFFLE_WEBHOOK_ID"
HONEYPOT_NAME = "ubuntu-honeypot-01"
ENDPOINT_URL = f"https://{CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com"


def upload_pcap_to_r2(pcap_path, file_name):
    print(f"[*] Uploading {file_name} to Cloudflare R2...", flush=True)
    cmd = [
        "aws",
        "--endpoint-url",
        ENDPOINT_URL,
        "s3",
        "cp",
        pcap_path,
        f"s3://{BUCKET_NAME}/{file_name}",
    ]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[+] File {file_name} successfully uploaded to R2.", flush=True)
        return True
    else:
        print(f"[-] Error uploading to R2: {result.stderr}", flush=True)
        return False


# Sends a JSON notification to Shuffle SOAR.
def notify_shuffle_soar(file_name, alerts_list, pcap_uploaded=False):

    payload = {
        "event_type": "new_suricata_alert_batch",
        "source_host": HONEYPOT_NAME,
        "pcap_file": file_name if pcap_uploaded else None,
        "pcap_uploaded": pcap_uploaded,
        "bucket": BUCKET_NAME if pcap_uploaded else None,
        "alert_details": alerts_list,
    }

    try:
        response = requests.post(WEBHOOK_URL, json=payload, timeout=5)
        if response.status_code in [200, 201, 202]:
            print(
                f"[+] Notification sent to Shuffle SOAR (HTTP {response.status_code}).",
                flush=True,
            )
        else:
            print(
                f"[-] Shuffle responded with an error: {response.status_code} - {response.text}",
                flush=True,
            )
    except Exception as e:  # noqa: BLE001
        print(f"[-] Error connecting to Shuffle: {e}", flush=True)


# Generator yielding new lines in real-time, handling log rotation.
def follow_file(filepath):

    current_file = open(filepath, "r")  # noqa: SIM115
    current_file.seek(0, 2)
    current_ino = os.fstat(current_file.fileno()).st_ino

    while True:
        pos = current_file.tell()
        line = current_file.readline()

        if line.endswith("\n"):
            yield line
        elif line != "":
            current_file.seek(pos)
            time.sleep(0.5)
            yield None
        else:
            time.sleep(0.5)
            yield None
            try:
                if os.stat(filepath).st_ino != current_ino:
                    print(
                        "[*] Log rotation detected. Reopening eve.json...", flush=True
                    )
                    current_file.close()
                    current_file = open(filepath, "r")  # noqa: SIM115
                    current_ino = os.fstat(current_file.fileno()).st_ino
            except FileNotFoundError:
                pass


# Process the corresponding logs.
def prepare_pcap_context(target_filename):

    pcap_files = sorted(
        glob.glob(os.path.join(PCAP_DIR, "*.pcap*")), key=os.path.getmtime
    )

    if not pcap_files:
        return None

    latest_pcap = pcap_files[-1]
    files_to_merge = [latest_pcap]

    if os.path.getsize(latest_pcap) < 5 * 1024 * 1024 and len(pcap_files) > 1:
        previous_pcap = pcap_files[-2]
        files_to_merge.insert(0, previous_pcap)
        print(
            f"[*] Latest PCAP is small. Merging with {os.path.basename(previous_pcap)} for context.",
            flush=True,
        )

    safe_output_path = os.path.join("/tmp", target_filename)
    cmd = ["mergecap", "-w", safe_output_path] + files_to_merge
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if os.path.exists(safe_output_path) and os.path.getsize(safe_output_path) > 0:
        return safe_output_path
    else:
        print(f"[-] mergecap failed to produce output: {result.stderr}", flush=True)
        return latest_pcap


# Process a list of aggregated alerts from an incident.
def handle_aggregated_alerts(alerts):

    if not alerts:
        return

    first_alert = alerts[0]

    try:
        date_part = first_alert["timestamp"].split("T")[0]
        time_part = (
            first_alert["timestamp"].split("T")[1].split(".")[0].replace(":", "-")
        )
        file_name = f"log_{date_part}_{time_part}.pcap"
    except Exception:  # noqa: BLE001
        file_name = f"log_{int(time.time())}.pcap"

    pcap_path = prepare_pcap_context(file_name)

    if not pcap_path:
        print("[-] No PCAP file found. Sending notifications without PCAP.", flush=True)
        notify_shuffle_soar(None, alerts, pcap_uploaded=False)
        return

    if upload_pcap_to_r2(pcap_path, file_name):
        notify_shuffle_soar(file_name, alerts, pcap_uploaded=True)

        if pcap_path.startswith("/tmp/"):
            os.remove(pcap_path)
    else:
        notify_shuffle_soar(None, alerts, pcap_uploaded=False)


def main():

    print("[*] Starting Suricata -> Shuffle SOAR monitor...", flush=True)

    while not os.path.exists(EVE_JSON_PATH):
        print("[*] Waiting for eve.json file to be created...", flush=True)
        time.sleep(5)

    pending_alerts = []
    last_alert_time = 0.0

    for line in follow_file(EVE_JSON_PATH):
        current_time = time.time()

        if line:
            try:
                event = json.loads(line)

                if event.get("event_type") == "alert":
                    alert_data = {
                        "timestamp": event.get("timestamp"),
                        "src_ip": event.get("src_ip"),
                        "dest_ip": event.get("dest_ip"),
                        "dest_port": event.get("dest_port"),
                        "signature": event.get("alert", {}).get("signature"),
                        "severity": event.get("alert", {}).get("severity"),
                        "category": event.get("alert", {}).get("category"),
                    }

                    print(f"[!] Alert detected: {alert_data['signature']}", flush=True)
                    pending_alerts.append(alert_data)
                    last_alert_time = current_time

            except json.JSONDecodeError:
                print("[-] JSON decoding error for line. Skipping...", flush=True)
                continue
            except Exception as e:  # noqa: BLE001
                print(f"[-] Error during processing: {e}", flush=True)

        if pending_alerts and (current_time - last_alert_time >= 10.0):
            print(
                f"[*] 10 seconds of silence detected. Aggregating {len(pending_alerts)} alerts...",
                flush=True,
            )
            handle_aggregated_alerts(pending_alerts)
            pending_alerts = []


if __name__ == "__main__":
    main()
