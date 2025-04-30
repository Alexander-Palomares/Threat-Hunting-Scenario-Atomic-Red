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

### 2. Searched the `DeviceProcessEvents` Table

After identifying the suspicious user alexanderp, I used the previously gathered context to query the DeviceProcessEvents table. I filtered for processes initiated by this user and command lines containing references to “tor”. This revealed the execution of tor-browser-windows-x86_64-portable-14.0.9.exe, a portable version of the Tor Browser for 64-bit Windows. This version runs without installation and supports silent execution.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where AccountName == "alexanderp"
| where FileName == "tor-browser-windows-x86_64-portable-14.0.9.exe" 
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

<img width="884" alt="Screenshot 2025-04-17 at 3 41 52 PM" src="https://github.com/user-attachments/assets/85bc3b96-b717-4b95-9c7c-39a71bc09c23" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I continued investigating the DeviceProcessEvents table for additional evidence that alexanderp had executed the Tor Browser. At 2025-04-14T23:05:26.9374591Z, I observed the launch of firefox.exe (used by the Tor Browser) followed by multiple instances of tor.exe, confirming active use.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where AccountName == "alexanderp"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1403" alt="Screenshot 2025-04-17 at 3 46 35 PM" src="https://github.com/user-attachments/assets/af276d39-1f43-42c8-a356-8969c0c0e3f0" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I queried the DeviceNetworkEvents table to identify any network activity indicating Tor Browser usage over known Tor-related ports. At 2025-04-14T23:06:06.81814Z, the user on the threat-hunt-lab device established a successful connection to 127.0.0.1 on port 9150. Additional connections were observed on port 9001, initiated by tor.exe, along with outbound traffic over port 443, confirming active Tor network communication.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "alexanderp"
| where RemotePort in ("9001", "9030", "9041", "9051", "9051", "9150", "80", "443")
| where InitiatingProcessFileName in ( "firefox.exe", "tor.exe")
| project Timestamp, ActionType, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc 
```
<img width="1403" alt="Screenshot 2025-04-17 at 3 53 28 PM" src="https://github.com/user-attachments/assets/9c08233f-2993-405f-89db-b75fb2fb754a" />

---

## Chronological Event Timeline 
# 🛡️ Threat Hunt Report – Tor Browser Activity (User: alexanderp)

## 📅 Date: April 14, 2025  
**System Monitored:** `threat-hunt-lab`  
**User Involved:** `alexanderp`  

---

## 📌 Timeline of Events

### 1. File Download – Tor Installer  
**Timestamp:** `2025-04-14T23:00:23.1664006Z`  
**Event:** User downloaded a Tor Browser installer to the desktop.  
**Action:** File download detected.  
**Details:**  
- Multiple Tor-related files were copied to the desktop.  
- A file named `tor-shopping-list.txt` was also created, potentially containing notes or a plan.

---

### 2. Process Execution – Tor Installer Launched  
**Timestamp:** *(Shortly after initial download)*  
**Event:** Execution of `tor-browser-windows-x86_64-portable-14.0.9.exe` detected.  
**Action:** Silent process execution.  
**Details:**  
- Portable version of Tor Browser executed.  
- No standard installation required.

---

### 3. Process Execution – Tor Browser Usage Confirmed  
**Timestamp:** `2025-04-14T23:05:26.9374591Z`  
**Event:** Tor Browser processes launched.  
**Action:** Process creation for Tor executables.  
**Details:**  
- `firefox.exe` and `tor.exe` observed.  
- Indicates successful launch and use of Tor Browser.

---

### 4. Network Connection – Initial Tor Network Access  
**Timestamp:** `2025-04-14T23:06:06.81814Z`  
**Event:** Local connection established to `127.0.0.1:9150`.  
**Action:** Tor proxy active.  
**Process:** `tor.exe`

---

### 5. Additional Network Connections – Tor Network Activity  
**Timestamps:** *Shortly after 23:06:06Z*  
**Event:** Outbound connections to Tor network observed.  
**Action:** Multiple connections established.  
**Details:**  
- Connection to external IPs on port `9001`.  
- HTTPS traffic over port `443`.  
- Confirms active anonymized web access via Tor.

---

## 🧾 Summary

On **April 14, 2025**, user **`alexanderp`** downloaded and executed a portable version of the Tor Browser. The activity included launching Tor processes (`firefox.exe`, `tor.exe`), establishing internal proxy connections, and successfully connecting to the Tor network over known ports. The creation of a file titled `tor-shopping-list.txt` suggests intentional use or planning. Network telemetry confirms full browser execution and external communication through the Tor network.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
