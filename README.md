<img width="300" src="https://github.com/user-attachments/assets/9cfcace3-c11e-4a15-9a86-7ccb230e99fa"/>

# Threat Hunt Report: Unauthorized TOR Usage

## Platforms and Languages Leveraged
- Azure Virtual Machines
- Microsoft Defender for Endpoint
- Microsoft Sentinel
- Kusto Query Language (KQL)
- Wireshark
- Powershell
- DeepBlueCLI
- Atomic Red Team

##  Scenario

Our monitoring tools have detected the execution of AutoIt3.exe, a non-standard script interpreter, on an Azure-hosted Windows virtual machine (b83f2cce4b9c3ff8107ecb50d005858ef52885f9). This activity was not expected and falls outside our baseline for approved software. The origin and purpose of this execution are currently unknown, and there is no immediate indication of user-initiated installation. Per the NIST 800-61 Incident Response framework, we are currently in the Identification phase. The SOC team is tasked with investigating this event to determine whether it constitutes a security incident. Key objectives include identifying how the file was introduced, whether it executed any additional commands or downloads, and assessing the potential scope and impact. Based on findings, further action under Containment, Eradication, and Recovery may be required.

### NIST 800-61 Incident Response


![0_TK8eNr0w7WNQVjRI](https://github.com/user-attachments/assets/3195916c-a72c-452d-bf4d-6f893910d5d0)


---

## Steps Taken

### 1. Preparation 

During the prepartion phase I created alerts that may suspect percular activities in microsoft defender for endpoint. With KQL I created these alerts to help:

Rule 1) Alert when AutoIt.exe is launched from a User, Temp or Downloads folder and the command line runs the malicious calc.au3 script file:
---

```kql
DeviceProcessEvents
| where DeviceId == "b83f2cce4b9c3ff8107ecb50d005858ef52885f9"
| where FileName =~ "AutoIt3.exe"
| where ProcessCommandLine has_any (".au3", "calc.au3")
| where FolderPath has_any ("Users", "Temp", "Downloads", "AutoIt3")
```

Rule 2) Alert when calc.exe is launched from an abdnormal parent-child process. 
---

```kql
DeviceProcessEvents
| where DeviceId == "b83f2cce4b9c3ff8107ecb50d005858ef52885f9"
| where not(FolderPath startswith "C:\\Windows\\System32")
| where FileName =~ "calc.exe"
```
Rule 3) Alert when PowerShell is used to download something from the internet via the “Invoke-WebRequest” command:
---

```kql
DeviceProcessEvents
| where DeviceId == "b83f2cce4b9c3ff8107ecb50d005858ef52885f9"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "wget", "curl")
| where ProcessCommandLine has "autoit" "getfile.pl"
```

Rule 4) Alert when Powershell is being used to install Autolt.exe (Unsual installation in a normal enterprise environment).
---

```kql
DeviceFileEvents
| where DeviceId == "b83f2cce4b9c3ff8107ecb50d005858ef52885f9"
| where FileName has "powershell"
| where InitiatingProcessCommandLine contains "autoit-v3-setup.exe"
```

Rule 5) Alert when non-standard scripting engines are found
---

```kql
DeviceProcessEvents
| where DeviceId == "b83f2cce4b9c3ff8107ecb50d005858ef52885f9"
| where FileName has_any ("AutoIt3.exe", "cscript.exe", "wscript.exe", "mshta.exe")
```

---

### 2. Identification

The initial alert was detected from MDE, specifically Rule 4) "Alert when Powershell is being used to install Autolt.exe".
This alert was created to catch a potential suspicious download through powershell. Since powershell isn't used typcally for downloading. 

Suspicious Activity: AutoIt3.exe executed unexpectedly on Azure Windows VM

Indicators Observed:

- File path: C:\Program Files (x86)\AutoIt3\
- Execution method: PowerShell
- Associated script: calc.au3 (from Atomic Red Team folder)

![image](https://github.com/user-attachments/assets/3d1de8c2-525d-4617-8908-c0155d750bf5)

Tools Used:

- Microsoft Sentinel (KQL queries)
- Defender for Endpoint (DeviceProcessEvents, file timeline)


---

### 3. Containment

Short-Term Containment:

- Isolate affected VM from network, while investigating to prevent furthur damage from being done. 
- Kill or block AutoIt process

Long-Term Containment:

- Disable execution of unknown interpreters
- Update detection rules to alert on PowerShell download to tailor AutoIt patterns

---

### 4. Eradication

Remove Artifacts:

- Delete AutoIt installer and installed files from the endpoint
- Remove any downloaded payloads or malicious scripts

Patch/Remediate Gaps:

- Block PowerShell web requests in non-admin contexts
- Implement stricter software whitelisting

---

### 5. Recovery

System Validation:

- Confirm VM is clean via AV/EDR scans
- Review system logs and user activity to ensure no persistence remains

Reintegration:

- Reconnect VM to network after clearance
- Monitor for any repeat activity

---

### 6. Lessons Learned

Root Cause: Interpreter downloaded and executed via PowerShell

Detection Improvements:

- Create alerts for Invoke-WebRequest + .exe installation patterns
- Add KQL watchlists for suspicious interpreters like AutoIt, Python, etc.

Response Enhancements:

- Improve alert context by enriching with parent-child process lineage
- Automate isolation of VMs on execution of high-risk interpreters

---

## 🧾 Summary of Events – AutoIt Script Execution Incident
Initial Detection: Security monitoring tools triggered an alert when PowerShell was used to download and silently install AutoIt3.exe — a non-standard scripting engine — on an Azure-hosted Windows VM (b83f2cce4b9c3ff8107ecb50d005858ef52885f9).

Execution Observed: Shortly after installation, AutoIt3.exe executed a script (calc.au3) located in the Atomic Red Team test directory. This script launched calc.exe, a commonly used benign executable often leveraged in red team simulations.

Suspicion Raised: The use of PowerShell for software installation and the presence of AutoIt3 — uncommon in enterprise environments — prompted further investigation.

Response Actions:

- The VM was isolated from the network to prevent potential lateral movement or external communication.
- All AutoIt-related files, including the installer and script, were removed from the system.
- Endpoint scans confirmed no further suspicious activity or persistence mechanisms.

Current Status: The system has been cleared and reconnected to the network. Investigation findings are being documented under the NIST 800-61 framework to improve detection and response processes.

---

