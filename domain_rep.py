import argparse
import getpass
import json
import os
from pathlib import Path

from src.llm_reporter import run_llm_pipeline
from src.pcap_parser import parse_pcap_to_json
from src.vt_checker import run_vt_check


def main():

    parser = argparse.ArgumentParser(
        description="DomainRep - Data Extraction & Reputation Check"
    )
    parser.add_argument(
        "--pcap", required=True, help="Provide name or path for the .pcap file"
    )
    parser.add_argument(
        "--report",
        default="report.md",
        help="Provide name or path for the report (default: report.md)",
    )
    parser.add_argument(
        "--internal-domain", default=None, help="Provide internal domain to ignore"
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Provide VirusTotal API key (or set VT_API_KEY env var)",
    )
    args = parser.parse_args()
    print("=" * 55)
    print("   DomainRep - Data Extraction & Reputation Check   ")
    print("=" * 55)
    pcap_path = Path(args.pcap)

    if not pcap_path.exists():
        print(f"\n[-] Error: File '{pcap_path}' not found.")
        return

    report_input = args.report
    internal_domain = args.internal_domain
    # Flag, environment variable, or fallback to prompt if running manually.
    api_key = args.api_key or os.environ.get("VT_API_KEY")

    if not api_key:
        api_key = getpass.getpass(
            "Provide your VirusTotal API key (characters are hidden): "
        ).strip()

    if not api_key:
        print("\n[-] Error: API key is needed.")
        return

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    base_name = pcap_path.stem
    parsed_file = output_dir / f"parsed_{base_name}.json"
    vt_file = output_dir / f"vt_rep_{base_name}.json"
    sus_file = output_dir / f"sus_{base_name}.json"
    report_path = Path(report_input)

    if not report_path.parent.name:  # User entered just 'report.md'.
        report_file = output_dir / report_input
    else:
        report_file = report_path

    print("\n" + "-" * 40)
    print("[STEP 1/3] Parsing domains and IP addresses from .pcap")
    print("-" * 40)
    parse_pcap_to_json(str(pcap_path), str(parsed_file), internal_domain)

    print("\n" + "-" * 40)
    print(
        "[STEP 2/3] Verifying using VirusTotal API with free plan request rate (4/min)"
    )
    print("-" * 40)
    success = run_vt_check(api_key, str(parsed_file), str(vt_file))

    if not success:
        print(
            "[!] VirusTotal scanning interrupted! Your progress has been saved to cache file. Resume at any time!"
        )

        return  # exit to avoid skipping data and error loops

    print("\n" + "-" * 40)
    print("[STEP 3/3] Filtering indicators and generating LLM Report")
    print("-" * 40)
    run_llm_pipeline(str(vt_file), str(sus_file), str(report_file))

    print("\n" + "=" * 55)
    print("[+] Analysis finished!\n")
    print(f"  - Raw domains and addresses:    {parsed_file}")
    print(f"  - VirusTotal reputation data:   {vt_file}")
    print(f"  - Filtered (malicious) data:    {sus_file}")
    print(f"  - Final report provided by LLM: {report_file}")
    # Warn about potentially missed indicators
    error_file = output_dir / f"errors_{base_name}.json"

    if error_file.exists():
        try:
            with open(error_file, "r", encoding="utf-8") as f:
                errors_data = json.load(f)

            total_errors = len(errors_data.get("domains", {})) + len(
                errors_data.get("ips", {})
            )

            if total_errors > 0:
                print(f"  - Skipped/Error indicators:     {error_file}")
                print(
                    f"\n[!] WARNING: {total_errors} indicator(s) could not be checked automatically"
                )
                print("             (e.g., 404 Not Found, invalid format).")
                print(
                    "             Manual investigation of the errors file is highly recommended!"
                )

        except Exception:  # noqa: BLE001, S110
            pass  # No errors!

    print("=" * 55)


if __name__ == "__main__":
    main()
