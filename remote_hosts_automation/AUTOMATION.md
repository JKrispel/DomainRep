# NIDS for multiple hosts with automated and enriched reporting.

## Required monitored hosts components:

* Traffic source - currently **only Linux** (e.g. local host, friend's Linux host, Honeypot - KVM VPS + Cowrie)
* NIDS with .pcap logging (e.g. Suricata)
* host_monitor.py (event producer)
* wireshark-common package (mergecap)
* aws-cli package
  
## Required backend host components:

* backend_listener.py (event consumer)
* automation_requirements.txt Python modules
* DomainRep (enrichment and reporting tool)
* All requirements for DomainRep ([README.md](https://github.com/JKrispel/DomainRep/blob/main/README.md))

## Other components:

* AWS S3 API compatible storage (e.g. Cloudflare R2)
* SOAR webhook workflow (e.g. Shuffle)
* Slack / Discord webhook workflow


## Setup instructions and explanation.

For the sake of this demonstration I will use KVM VPS with Linux Ubuntu and turn it into a honeypot using Cowrie. 
This is a demanding environment for this tool, as the server and it's SSH port will be open for all the incoming traffic, 
including automated scanners and botnets. Honeypot will be communicating with a lot of different IPs and domains constantly,
creating a lot of which we will be trying to analyze and understand using tools in this repository, as well as other free services.

## Step 1: Configuring SSH ports.

We need to leave the port 22 for Cowrie to trick the attackers and set 
```
mkdir -p /etc/systemd/system/ssh.socket.d/
```
```
cat << EOF > /etc/systemd/system/ssh.socket.d/override.conf
[Socket]
ListenStream=
ListenStream=0.0.0.0:2222
ListenStream=\[::]:2222
EOF
```

Allow the new port in the firewall:

```bash
ufw allow 2222/tcp
```

Restart services:

```bash
systemctl daemon-reload
systemctl restart ssh.socket
```

From now on, connect like this:

```bash
ssh -p 2222 ubuntu@YOUR_VPS_IP
```

## Step 2: Download and run Suricata on VPS

```bash
# Rules update
suricata-update

# Identify your network interface
ip -br a

# Enable .pcap logging in configuration
sudo nano /etc/suricata/suricata.yaml
```

*(Use Ctrl + W to search in nano)*

```yaml
af-packet:
      interface: ens3 # (enter yours)

...

# Storage limit for logs
- pcap-log:
      enabled: yes
      filename: log.pcap.%t
      limit: 100mb
      max-files: 10
      compression: none
      mode: normal
```

```bash
sudo systemctl start suricata
sudo systemctl status suricata

# Check for activity
tail -f /var/log/suricata/eve.json
```

## Step 3: Download and run Cowrie on VPS

**Dedicated cowrie user:**

```bash
sudo su - cowrie
source cowrie-env/bin/activate
cowrie start
cowrie status
```

**Process securing (SWAP creation):**

```bash
# 1. Create a 4GB file
fallocate -l 4G /swapfile

# 2. Set correct permissions
chmod 600 /swapfile

# 3. Format file as SWAP
mkswap /swapfile

# 4. Enable SWAP in the system
swapon /swapfile

# 5. Add entry to fstab so SWAP persists after reboot
echo '/swapfile none swap sw 0 0' >> /etc/fstab
```

**Configure Cowrie as a systemd service (Auto-restart):**

```bash
# Create the daemon file, paths may vary!
nano /etc/systemd/system/cowrie.service
```

```ini
[Unit]
Description=Cowrie SSH/TELNET Honeypot
After=network.target

[Service]
Type=forking
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/cowrie/cowrie
Environment="PATH=/home/cowrie/cowrie/cowrie-env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/home/cowrie/cowrie/cowrie-env/bin/twistd --umask=0022 --pidfile var/run/cowrie.pid -l var/log/cowrie/cowrie.log cowrie
ExecStop=/home/cowrie/cowrie/cowrie-env/bin/cowrie stop
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl start cowrie

# Should be active (running)
sudo systemctl status cowrie

# Start on boot
systemctl enable cowrie
```

## Step 4: Configure iptables port forwarding

Redirect attackers' traffic hitting standard SSH (22) and Telnet (23) to the Cowrie honeypot (22222 and 22223).

```bash
# Redirect port 22 (SSH) to port 22222 (Cowrie SSH)
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 22222

# Redirect port 23 (Telnet) to port 22223 (Cowrie Telnet)
iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 22223

# Allow ports for attackers (honeypot trap)
ufw allow 22/tcp
ufw allow 23/tcp

# Ensure your management SSH port is still open!
ufw allow 2222/tcp

# Enable firewall (if it wasn't enabled yet)
ufw --force enable
```

## Step 5: Save iptables rules persistently

```bash
apt install -y iptables-persistent
netfilter-persistent save
```

## Step 6: VPS -> SOAR (Detection and alert)

```bash
# Create another system service
sudo nano /etc/systemd/system/suricata-soar.service
```

```ini
[Unit]
Description=Suricata to SOAR Alert Monitor
After=network.target suricata.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/suricata/host_monitor.py
Restart=always
RestartSec=5

Environment="AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY_ID"
Environment="AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY"
Environment="AWS_DEFAULT_REGION=auto"

StandardOutput=append:/var/log/suricata-soar.log
StandardError=append:/var/log/suricata-soar-error.log

[Install]
WantedBy=multi-user.target
```

Create the `suricata` folder in `/opt/` and place `host_monitor.py` there with the configured variables. 
If you don't have the required libraries (e.g. requests), install them:

```bash
apt update
apt install python3-requests
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable suricata-soar.service

# Important: start ONLY after filling in the webhook URL in the python script!
sudo systemctl start suricata-soar.service
```

## Step 7: SOAR -> Your backend (Trigger and download)

*(Awaiting further context)*

## Step 8: Your backend -> Communicator (Webhook)

*(Awaiting further context)*

## (Optional) Step 9: SOAR Scalability

Features like SMS notifications, blocking IPs on the firewall via API, or adding Shodan enrichment can be easily implemented in Tines/Shuffle by arranging workflow blocks.
