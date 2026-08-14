# DomainRep - easily scan your .pcap files for malicious IPs and domains

## How to use it?

Download the repository and simply run the **domain_rep.py** script in your terminal. Then provide all the information it asks for: 
- .pcap file
- output report file name
- VirusTotal API key
- internal domain to ignore (optional)

<img width="2386" height="406" alt="image" src="https://github.com/user-attachments/assets/e2437b8f-5b0b-43a1-9b27-eadb76188fc7" />

You can provide just the **name** of the file or an **absolute path**. 

By default all generated files are saved in _**output**_ folder.

**The API key is not being saved.**
## How does it work?
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

However the progress is being saved between sessions.

### Below is the flowchart of the process:
<img width="861" height="1023" alt="diagram drawio (1)" src="https://github.com/user-attachments/assets/7d19abc9-efaf-4a4f-b1e7-1cbf7e67766a" />


