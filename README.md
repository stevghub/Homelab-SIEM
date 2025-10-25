# Homelab-SIEM

Build a small SIEM lab at home. You will run Wazuh with an ELK stack in Docker, ship logs from Windows and Linux, and test alerts.

## What you get

* One command Docker setup for Wazuh server and dashboard
* Windows and Linux agent setup
* Sample data scripts to generate auth and process events
* A few rules and decoders to learn tuning
* Checklists and a daily workflow

## Quick start

Requirements

* 16 GB RAM
* 4 CPU cores
* 60 GB free disk
* Docker and Docker Compose
* One Windows 10 or 11 VM
* One Ubuntu 22.04 VM

Start the stack on your SIEM host

```bash
git clone https://github.com/youruser/homelab-siem.git
cd homelab-siem/siem
cp .env.example .env
docker compose up -d
```

Open the dashboard

* URL [https://localhost](https://localhost)
* Default user admin
* Default pass admin

Change the admin password right away.

## Repo layout

```
homelab-siem
├─ README.md
├─ siem
│  ├─ docker-compose.yml
│  ├─ .env.example
│  ├─ config
│  │  ├─ wazuh
│  │  │  ├─ ossec.conf
│  │  │  └─ rules
│  │  │     ├─ local_rules.xml
│  │  │     └─ decoders.xml
│  │  └─ filebeat
│  │     └─ filebeat.yml
├─ agents
│  ├─ windows
│  │  ├─ install-wazuh-agent.ps1
│  │  └─ sysmon
│  │     ├─ install-sysmon.ps1
│  │     └─ sysmon-config.xml
│  └─ linux
│     └─ install-wazuh-agent.sh
├─ data-gen
│  ├─ windows-noise.ps1
│  └─ linux-noise.sh
├─ detections
│  ├─ sigma
│  │  └─ proc_creation_susp_cmd.yml
│  └─ wazuh
│     └─ 100001_susp_cmd_rule.xml
├─ playbooks
│  └─ brute_force_linux.md
└─ docs
   ├─ onboarding_checklist.md
   └─ daily_workflow.md
```

## Step 1 SIEM server in Docker

siem/docker-compose.yml

```yaml
services:
  wazuh.manager:
    image: wazuh/wazuh-manager:4.8.0
    hostname: wazuh.manager
    restart: unless-stopped
    ports:
      - "1514:1514/udp"
      - "1515:1515"
      - "55000:55000"
    volumes:
      - ./config/wazuh/ossec.conf:/wazuh-config-mount/ossec.conf
      - ./config/wazuh/rules/local_rules.xml:/wazuh-config-mount/custom_rules/local_rules.xml
      - ./config/wazuh/rules/decoders.xml:/wazuh-config-mount/decoders/decoders.xml

  wazuh.indexer:
    image: wazuh/wazuh-indexer:4.8.0
    hostname: wazuh.indexer
    restart: unless-stopped
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g"
    ulimits:
      memlock: -1
    ports:
      - "9200:9200"

  wazuh.dashboard:
    image: wazuh/wazuh-dashboard:4.8.0
    hostname: wazuh.dashboard
    restart: unless-stopped
    ports:
      - "443:5601"
    environment:
      - INDEXER_URL=https://wazuh.indexer:9200
      - WAZUH_API_URL=https://wazuh.manager:55000
    depends_on:
      - wazuh.indexer
      - wazuh.manager
```

siem/.env.example

```dotenv
WAZUH_PASSWORD=YOURPWHERE
```

siem/config/wazuh/ossec.conf

```xml
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
  </global>

  <ruleset>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
    <rule_dir>etc/custom_rules</rule_dir>
  </ruleset>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>udp</protocol>
  </remote>

  <alerts>
    <log_alert_level>3</log_alert_level>
  </alerts>
</ossec_config>
```

siem/config/wazuh/rules/local_rules.xml

```xml
<group name="local,windows,linux">
  <rule id="100001" level="8">
    <if_group>sysmon_event1</if_group>
    <match>powershell.exe</match>
    <description>Suspicious PowerShell spawn</description>
    <group>process_creation</group>
  </rule>
</group>
```

siem/config/wazuh/rules/decoders.xml

```xml
<decoders>
  <!-- Custom decoders go here -->
</decoders>
```

## Step 2 Agents

Windows agent install
agents/windows/install-wazuh-agent.ps1

```powershell
param(
  [string]$ManagerIP = "192.168.1.10"
)

$msi = "$env:TEMP\wazuh-agent.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.0-1.msi" -OutFile $msi
Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msi`" /qn ADDRESS=$ManagerIP PROTOCOL=udp"
Start-Sleep -Seconds 5
Start-Service WazuhSvc
Set-Service WazuhSvc -StartupType Automatic
```

Sysmon install for rich process logs
agents/windows/sysmon/install-sysmon.ps1

```powershell
$zip = "$env:TEMP\Sysmon.zip"
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip
Expand-Archive $zip -DestinationPath $env:TEMP\Sysmon -Force
$cfg = "$PSScriptRoot\sysmon-config.xml"
& "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i $cfg
```

agents/windows/sysmon/sysmon-config.xml

```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="end with">powershell.exe</Image>
      <Image condition="end with">cmd.exe</Image>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

Linux agent install
agents/linux/install-wazuh-agent.sh

```bash
#!/usr/bin/env bash
set -e
MGR_IP="${1:-192.168.1.10}"
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo apt install -y wazuh-agent
sudo sed -i "s/^address.*/address = $MGR_IP/" /var/ossec/etc/ossec.conf
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

## Step 3 Sample data

Generate safe noise to test rules.

Windows
data-gen/windows-noise.ps1

```powershell
# Failed logons
1..5 | ForEach-Object { cmd /c "runas /user:fakeuser cmd.exe" }

# Suspicious PowerShell pattern
powershell -NoP -W Hidden -C "Start-Sleep 1"

# Create and delete temp files
1..50 | % { New-Item -Path "$env:TEMP\file$_.txt" -ItemType File | Out-Null }
Remove-Item "$env:TEMP\file*.txt"
```

Linux
data-gen/linux-noise.sh

```bash
#!/usr/bin/env bash
# Failed sudo attempts
for i in {1..5}; do echo wrong | sudo -S ls >/dev/null 2>&1; done

# Simple process noise
for i in {1..20}; do sleep 0.1; echo "hello" >/tmp/lab_$i.txt; done
rm -f /tmp/lab_*.txt
```

## Step 4 Detections

Sigma rule example
detections/sigma/proc_creation_susp_cmd.yml

```yaml
title: Suspicious PowerShell launch
id: 5b6e9e7a-6d2d-4a2a-ae7a-ps1-susp
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
  condition: selection
level: high
```

Wazuh local rule aligned to Sigma
detections/wazuh/100001_susp_cmd_rule.xml

```xml
<group name="local,windows">
  <rule id="100002" level="8">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.Image">\powershell.exe</field>
    <description>Powershell process creation</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
</group>
```

## Step 5 Dashboards

In Wazuh dashboard

* Add a saved search for agent status
* Add a visualization for auth failures by host
* Add a visualization for process creation count by image
* Save a dashboard named Home Lab Overview

## Step 6 Playbooks

playbooks/brute_force_linux.md

```markdown
Goal detect repeated sudo failures

Triage
- Open Security Events in Wazuh
- Filter rule groups authentication or sshd
- Pivot by src_ip and agent.name

Scope
- Count unique users targeted
- Count failures per minute

Response
- Block src_ip with UFW on the agent
- Rotate user passwords if targeted accounts are real

Recovery
- Clear failed login counters
- Reopen firewall when clean

Lessons
- Add a rule to raise level when failures exceed 10 in 1 minute
```

## Step 7 Hardening

* Change all default passwords
* Restrict dashboard to your LAN
* Set daily snapshots of the indexer VM
* Enable TLS for agents
* Add backups of /var/ossec and index data

## Step 8 Daily workflow

docs/daily_workflow.md

```markdown
Morning
- Check agent connectivity
- Review top 10 alerts by level
- Acknowledge noisy rules

Midday
- Tune rules that fired more than 50 times
- Add notes to cases

Evening
- Run data-gen scripts
- Confirm alerts fire
- Commit rule changes with message
```

## Step 9 Onboarding checklist

docs/onboarding_checklist.md

```markdown
- Spin up SIEM stack
- Install Windows agent
- Install Sysmon
- Install Linux agent
- Run noise scripts
- Confirm alerts in dashboard
- Add first custom rule
- Save overview dashboard
```

## Screens and URLs

* Wazuh dashboard [https://localhost](https://localhost)
* Indexer API [https://localhost:9200](https://localhost:9200)
* Wazuh API [https://localhost:55000](https://localhost:55000)

## Next steps

* Add Zeek on a SPAN port for network logs
* Add Filebeat on Windows for Event Logs to indexer
* Add alerts to Slack or email
* Try Atomic Red Team tests for more signal

## License

MIT

## Credits

This lab uses the Wazuh project and the OpenSearch stack.
