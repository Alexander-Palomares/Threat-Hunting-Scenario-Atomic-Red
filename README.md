<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Alexander-Palomares/Threat-Hunting-Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I began by querying the DeviceFileEvents table, filtering for any entries containing the string “tor”. This led to the discovery that user alexanderp had downloaded a Tor installer. Multiple Tor-related files were copied to the desktop, and a text file named tor-shopping-list.txt was created. These events began at 2025-04-14T23:00:23.1664006Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "alexanderp"
| where FileName contains "tor"
| where Timestamp >= todatetime('2025-04-14T23:00:23.1664006Z')
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, account = InitiatingProcessAccountName
```

<img width="1213" alt="Screenshot 2025-04-17 at 3 27 17 PM" src="https://github.com/user-attachments/assets/f0a7809a-18b9-4066-9da5-95dad97c77c3" />

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
