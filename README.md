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

Searched for any file extensions commonly used in data exfiltration (e.g., `.csv`, `.pdf`, `.txt`, `.zip`, `.db` and discovered a file named `students.csv` created at `2025-05-12T23:57:37.3164809Z`, along with an extortion note created shortly after at `2025-05-13T00:18:00.6008846Z`. While there's no evidence the extortion message was sent, the `students.csv` file was later compressed using PowerShell at `2025-05-13T00:18:00.6008846Z`, suggesting potential preparation for data exfiltration.



**Query used to locate events:**

```kql


---

### 2. Searched the `DeviceProcessEvents` Table



**Query used to locate event:**

```kql



```



---

### 3. Searched the `DeviceProcessEvents` 



**Query used to locate events:**

```kql

```




---

### 4. Searched the `DeviceNetworkEvents` 


**Query used to locate events:**

```kql

```


---

## Chronological Event Timeline 

### 1. 

- **Timestamp:** 
- **Event:** 
- **Action:** 
- **File Path:** 

### 2. 

- **Timestamp:** 
- **Event:**
- **Action:** 
- **Command:** 
- **File Path:** 

### 3. Process Execution -

- **Timestamp:** 
- **Event:** 
- **Action:** 
- **File Path:** 

### 4. Network Connection -

- **Timestamp:** 
- **Event:** 
- **Action:** 
- **Process:** 
- **File Path:** 

### 5. Additional Network Connections - 

- **Timestamps:**
 
- **Event:** 
- **Action:** 

### 6. File Creation - 

- **Timestamp:**
- **Event:** 
- **Action:** 
- **File Path:** 

---

## Summary



---

## Response Taken



---
