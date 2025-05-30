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

- **Timestamp:** `2025-05-13T00:23:42.1783386Z`
- **Event:** The `students.csv` file was zipped using a PowerShell command, resulting in `data.zip`.
- **Action:** File compression via PowerShell
- **Command:** `powershell.exe Compress-Archive -Path C:\Users\ShadowInbox\Desktop\students.csv -DestinationPath C:\Users\ShadowInbox\Desktop\data.zip`


### 4. Script Execution - send_extortion.py(1st Attempt)

- **Timestamp:** `2025-05-13T01:21:19.302708Z`
- **Event:** A Python script named `send_extortion.py` was executed in PowerShell.
- **Action:** Script execution detected.
- **Command:** "python.exe" `send_extortion.py`
- **Initiating Process Path:** C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

### 5. Network Connection Attempt - Port 1025

- **Timestamps:** 2025-05-13T01:21:42Z (approx.)
- **Event:** An attempt was made to connect to port 1025, presumably to send the extortion email.
- **Action:** Connection attempt detected; failed.

### 6. Script Execution - send_extortion.py (Second Attempt)

- **Timestamp:** 2025-05-13T01:23:58Z (approx.)
- **Event:** The script send_extortion.py was executed again, possibly due to prior failure.
- **Action:** Reattempt of script execution noted.

### 7. Successful Network Connection - Email Transmission

- **Timestamp:**  2025-05-13T01:24:57.3521978Z
- **Event:** A successful connection to port 1025 was made using the Python script, aligning with previous script execution.
- **Action:** Email likely transmitted.
- **Command:** "python.exe" send_extortion.py
- **Device:** hr-laptop-101
- **User:** ShadowInbox


---

## Summary
The user "ShadowInbox" on the "hr-laptop-101" device successfully but illegally obtained student data: `students.csv` and proceeded to compress the file using PowerShell in preparation for data exfiltration. Though there were no signs of outreach initially, it was later discovered that a Python script, `send_extortion.py`, was used to send an extortion email asking for a bitcoin ransom. After 2 failed attempts, a successful connection to port 1025 was logged, which aligns with the final script execution, indicating that the email with the extortion content was likely delivered to the target.

Although no evidence confirms the recipient received the extortion note, the activity pattern and successful connection indicate the attacker's intent to exfiltrate sensitive data.

---

## Response Taken

The `hr-laptop-101` was immediately isolated from the network, and the incident was escalated to the security response team for further in-depth analysis. Upper management was notified about the threat, and all collected data (`students.csv`, `data.zip`, `send_extortion.py`) were collected for review.




---

