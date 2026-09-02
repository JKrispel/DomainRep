# DomainRep - turn your .pcap files into reports containing malicious IPs and domains.

## Requirements:

- Python + modules (requirements.txt)
- Wireshark / tshark (for pyshark wrapper module to work)
- VirusTotal API key (VT free account)
- LM Studio with local server enabled on port 1234 (default) and LLM loaded (e.g. openai/gpt-oss-20b works fine)
- some decent GPU to load the local LLM (or you can swap the _url_ variable in the source code for some cloud provider's API, if it fits your risk profile)

## How to use it?

Download the repository and simply run the **domain_rep.py** script in your terminal. Then provide all the information it asks for: 
- .pcap file
- output report file name
- VirusTotal API key
- internal domain to ignore (optional)

<img width="2386" height="406" alt="image" src="https://github.com/user-attachments/assets/e2437b8f-5b0b-43a1-9b27-eadb76188fc7" />

You can provide just the **name** of the file or an **absolute path**. 

By default all generated files are saved in the _**output**_ folder.

**The API key is not being saved.**

## How does it work?

#### To begin you can take a look at the output: [**examples/automatic_report.md**](https://github.com/JKrispel/DomainRep/blob/main/examples/automatic_report.md), further explanation below...

Python script directly parses the **.pcap** file using the **pyshark** module. 
It tries to find all **public IP addresses** and **domain names** and saves them to a **.json** file. 

### This particular data is being extracted:

<img width="802" height="584" alt="image" src="https://github.com/user-attachments/assets/0bfe5915-7b00-4978-8059-e9b85a6336d6" />

Further the indicators are being sent to **VirusTotal API** to check their reputation. 
Failed requests (if present) will be dumped into an error file for further manual investigation. 
Later another script removes entries with a crystal clear reputation. 
Finally suspicious indicators are being sent to the local LLM in order to generate a structured and readable report out of it. 

The model is also provided with a **system prompt** and a **manually selected report**. 
With these specific instructions and an example it's able to generate consistent output. 

**Remember:** VirusTotal free API supports only **4 lookups / min** so it may take a while!

However the API responses are being continuously **cached** and kept for 24 hours. This allows us to skip many future VT requests and significantly speed up the process.

### Below is the flowchart for the tool:
<img width="700" height="800" alt="diagram drawio (1)" src="https://github.com/user-attachments/assets/7d19abc9-efaf-4a4f-b1e7-1cbf7e67766a" />


### Automation for multiple hosts

You can use scripts provided in **_remote_hosts_automation_** folder for this task. Instructions in the [**AUTOMATION.md**](https://github.com/JKrispel/DomainRep/blob/main/remote_hosts_automation/AUTOMATION.md) file will help you to set up your own **NIDS** with automated, enriched alerts from multiple remote hosts.
