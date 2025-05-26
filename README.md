<img width="600" src="https://github.com/user-attachments/assets/3a89b512-b3b9-4ebe-92c3-8eecc9ade289" alt="Threat actor threatening with extortion email">




# Threat Hunt Report: Extortion Email using Breached School Data
- [Scenario Creation]

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Python Script
- SMTP Server

##  Scenario

Management has identified suspicious outbound email activity from a user in response to a recent resurgence of extortion emails linked to the Powerschool breach. As a result, the team suspects that some school data has been compromised and is being leveraged for ransom. Additionally, there have been some reports indicating that threat actor/actors are attempting to extort the affected victim by demanding some form of payment. The goal is to identify any evidence of data collection and extortion emails targeting internal staff. If any of these activities are detected, notify management immediately.

### High-Level Extortion Email IoC Discovery Plan

- **Check `DeviceFileEvents`** for creation files with extensions like `.csv`, `.pdf`, `.txt`, `.zip`, or `.dp` to detect staged sensitive data. 
- **Check `DeviceProcessEvents`** for any signs of execution of compressed files
- **Check `DeviceNetworkEvents`** for any signs of outbound connections to mail or mail-related ports

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file extensions commonly used in data exfiltration (e.g., `.csv`, `.pdf`, `.txt`, `.zip`, `.db` and discovered a file named `students.csv` created at `2025-05-12T23:57:37.3164809Z`, along with an extortion note created shortly after at `2025-05-13T00:18:00.6008846Z`. While there's no evidence the extortion message was sent, the `students.csv` file was later compressed using PowerShell at `2025-05-13T00:23:42.1783386Z`, suggesting potential preparation for data exfiltration.

**Query used to locate events:**

```kql
let TargetDeviceName = "hr-laptop-101";
let SuspiciousFileExtensions = dynamic([".csv", ".pdf",".txt", ".zip",".db"]);
DeviceFileEvents
|where DeviceName == TargetDeviceName
|where FileName has_any (SuspiciousFileExtensions)
|where ActionType == "FileCreated"
| order by Timestamp desc
                 
```
![image](https://github.com/user-attachments/assets/62062512-5d03-455f-a5f9-0875913abc93)

![image](https://github.com/user-attachments/assets/a9a0b901-63a0-4354-9071-71f2bc80e7a7)

---

### 2. Searched the `DeviceProcessEvents` Table

To investigate post-zip activity, I queried the `DeviceProcessEvents` table for events that occurred after the `students.csv` at `2025-05-13T00:23:42.1783386Z` and discovered the execution of `send_extortion.py` at `2025-05-13T01:21:19.302708Z` via PowerShell: `(c:\windows\system32\windowspowershell\v1.0\powershell.exe)`. While there's no confirmation that the file reached its intended target, multiple script executions from `2025-05-13T01:21:19.302708Z` to `2025-05-13T01:28:07.9827846Z` suggest repeated attempts, possibly due to delivery failure.

**Query used to locate event:**

```kql

let TargetDeviceName = "hr-laptop-101";
DeviceProcessEvents
|where DeviceName == TargetDeviceName
|where Timestamp > datetime(2025-05-13T00:23:42.1783386Z)
|where ProcessCommandLine has_any ("python", "extortion", "subject")
|order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/a3f85719-ada2-4097-9bb0-d70144057c61)

---

### 3. Searched the `DeviceNetworkEvents` Table

Searched `DeviceNetworkEvents` to identify any successful connections to an email server. Since several ports can be used, I searched  process command lines containing “extortion” to trace email activity. Three attempts to connect to port 1025 were found, with one successful attempt at `2025-05-13T01:24:57.3521978Z`, aligning with script executions in the `DeviceProcessEvents` table — confirming user “ShadowInbox” on hr-laptop-101 successfully ran `send_extortion.py` to deliver email to intended target.

**Query used to locate events:**

```kql
let TargetDeviceName = "hr-laptop-101";
DeviceNetworkEvents
|where DeviceName == TargetDeviceName
|where Timestamp > datetime(2025-05-13T00:23:42.1783386Z)
|where InitiatingProcessCommandLine has_any ("extortion")
|order by Timestamp desc 

```
![image](https://github.com/user-attachments/assets/87021f6b-1cc5-4bf1-8a1c-d7d35b78390c)

![image](https://github.com/user-attachments/assets/688c6668-9658-48fe-b02b-09f61707b628)

---

## Chronological Event Timeline 

### 1. File Creation - students.csv

- **Timestamp:** `2025-05-12T23:57:37.3164809Z`
- **Event:** A file named `students.csv` was created by user "ShadowInbox" on device hr-laptop-101.
- **Action:** File creation detected.
- **File Path:** `C:\Users\ShadowInbox\Desktop\students.csv`

### 2. File Creation - extortion note

- **Timestamp:** ` 2025-05-13T00:18:00.6008846Z`
- **Event:** A file resembling an extortion note was created on the same device.
- **Action:** File creation detected.


### 3. File Compression - PowerShell Archive Command

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---

