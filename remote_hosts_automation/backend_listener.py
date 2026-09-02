# Acts as an Event Consumer, running alert data analysis in the backend.
import os
import queue
import subprocess
import sys
import threading

import backend_config
import boto3
import ngrok
import requests
from flask import Flask, jsonify, request

listener = ngrok.forward(5000, authtoken=backend_config.NGROK_AUTHTOKEN)
print(f"[*] Listening at {listener.url()}")
app = Flask(__name__)

ANALYSIS_QUEUE = queue.Queue()


def delete_pcap_from_r2(filename):

    print(f"[*] Deleting {filename} from R2 bucket to free up space...")
    try:
        s3 = boto3.client(
            "s3",
            endpoint_url=backend_config.R2_ENDPOINT_URL,
            aws_access_key_id=backend_config.R2_ACCESS_KEY,
            aws_secret_access_key=backend_config.R2_SECRET_KEY,
        )
        s3.delete_object(Bucket=backend_config.R2_BUCKET_NAME, Key=filename)
        print("[+] PCAP file deleted from R2 successfully.")
    except Exception as e:  # noqa: BLE001
        print(f"[-] R2 S3 deletion error: {e}")


def download_pcap_from_r2(filename):

    os.makedirs(backend_config.LOCAL_PCAP_DIR, exist_ok=True)
    local_path = os.path.join(backend_config.LOCAL_PCAP_DIR, filename)

    if os.path.exists(local_path):
        print(f"[*] PCAP {filename} already exists locally. Skipping R2 download.")
        return local_path

    print(
        f"[*] Downloading from R2 bucket '{backend_config.R2_BUCKET_NAME}': {filename} -> {local_path}"
    )

    try:
        s3 = boto3.client(
            "s3",
            endpoint_url=backend_config.R2_ENDPOINT_URL,
            aws_access_key_id=backend_config.R2_ACCESS_KEY,
            aws_secret_access_key=backend_config.R2_SECRET_KEY,
        )
        s3.download_file(backend_config.R2_BUCKET_NAME, filename, local_path)
        print("[+] PCAP file downloaded successfully.")

        delete_pcap_from_r2(filename)

        return local_path

    except Exception as e:  # noqa: BLE001
        print(f"[-] R2 S3 download error: {e}")
        return None


# Background thread that consumes the queue one by one.
def worker_loop():

    while True:
        task_data = ANALYSIS_QUEUE.get()
        if task_data is None:
            break

        pcap_filename = task_data.get("pcap_filename")

        local_pcap = download_pcap_from_r2(pcap_filename)
        if not local_pcap:
            ANALYSIS_QUEUE.task_done()
            continue

        report_name = f"report_{pcap_filename}.md"
        base_dir = os.path.dirname(os.path.abspath(__file__))
        domain_rep_path = os.path.abspath(os.path.join(base_dir, "..", "domain_rep.py"))

        cmd = [
            sys.executable,
            domain_rep_path,
            "--pcap",
            local_pcap,
            "--report",
            report_name,
        ]

        if getattr(backend_config, "VT_API_KEY", None):
            cmd.extend(["--api-key", backend_config.VT_API_KEY])

        if getattr(backend_config, "INTERNAL_DOMAIN", None):
            cmd.extend(["--internal-domain", backend_config.INTERNAL_DOMAIN])

        print(f"[*] Starting GPU analysis from queue: {' '.join(cmd)}")

        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"[+] Analysis for {pcap_filename} completed.")

            slack_url = getattr(backend_config, "SLACK_WEBHOOK_URL", None)

            if slack_url:
                report_path = os.path.join(base_dir, "output", report_name)

                if os.path.exists(report_path):
                    with open(report_path, "r", encoding="utf-8") as f:
                        report_content = f.read()

                    if len(report_content) > 3000:
                        report_content = (
                            report_content[:3000]
                            + "\n\n[Report truncated due to length...]"
                        )

                    slack_payload = {
                        "text": f"*New DomainRep Analysis Report for `{pcap_filename}`*\n```{report_content}```"
                    }

                    response = requests.post(slack_url, json=slack_payload, timeout=5)
                    print(
                        f"[*] Slack response status: {response.status_code}, body: {response.text}"
                    )
                else:
                    print(f"[-] Report file not found at path: {report_name}")
            # ---------------------------------------------------------------------

        except subprocess.CalledProcessError as e:
            print(f"[-] Error during analysis for {pcap_filename}: {e.stderr}")

        ANALYSIS_QUEUE.task_done()


threading.Thread(target=worker_loop, daemon=True).start()


@app.route("/trigger", methods=["POST"])
def trigger_analysis():

    data = request.json
    print("\n[!] Notification received from Shuffle SOAR!")

    alert_details = data.get("alert_details", [])
    print(f"    [!] Processing batch of {len(alert_details)} alerts")

    for alert in alert_details:
        print(f"    Signature: {alert.get('signature', 'N/A')}")
        print(f"    IP: {alert.get('src_ip', 'N/A')} -> {alert.get('dest_ip', 'N/A')}")
        print("    ---")
    # -----------------------------------------------------------------------------

    pcap_filename = data.get("pcap_file")
    pcap_uploaded = data.get("pcap_uploaded", False)

    if not pcap_uploaded or not pcap_filename:
        print(
            "[*] Alert logged, but no new PCAP was uploaded. Skipping download and analysis."
        )
        return jsonify(
            {
                "status": "success",
                "message": "Metadata logged, skipped PCAP download as none was uploaded",
            }
        ), 200

    print(f"[*] Adding {pcap_filename} to the analysis queue.")
    ANALYSIS_QUEUE.put({"pcap_filename": pcap_filename})

    return jsonify(
        {
            "status": "queued",
            "message": "PCAP analysis task has been added to the queue.",
        }
    ), 202


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
