# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/KamalAltway/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "kamal" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-09-07T17:01:03.3962586Z`. These events began at `2025-09-07T17:01:03.3962586Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "kamal-windows-1"  
| where InitiatingProcessAccountName == "kaltway"  
| where FileName contains "tor"  
| where Timestamp >= datetime('2025-09-07T17:01:03.3962586Z')  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName 

```
<img width="1229" height="450" alt="image" src="https://github.com/user-attachments/assets/7265fe18-27cc-4b3a-a1da-929ab6465b87" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.6.exe". Based on the logs returned, at `2025-09-07T17:20:47.2655316Z`, an employee on the "kamal-windows-1" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "kamal-windows-1"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.6.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1243" height="462" alt="image" src="https://github.com/user-attachments/assets/d24b34a1-0f69-408a-864a-185dc9168f38" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "kaltway" actually opened the TOR browser. There was evidence that they did open it at `2025-09-07T17:21:21.5215176Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "kamal-windows-1"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1218" height="446" alt="image" src="https://github.com/user-attachments/assets/7f3eda04-e386-4eeb-839e-3db11495b1d5" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-09-07T17:22:37.6905131Z`, an employee on the "kamal-windows-1" device successfully established a connection to the remote IP address `81.137.179.68` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\kaltway\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "kamal-windows-1"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1214" height="438" alt="image" src="https://github.com/user-attachments/assets/41a301a2-ec80-45e6-ac4c-e6e55858baac" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-09-07T17:01:03.3962586Z`
- **Event:** The user "kaltway" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\kaltway\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-09-07T17:20:47.2655316Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.6.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.6.exe  /S`
- **File Path:** `C:\Users\kaltway\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-09-07T17:21:21.5215176Z`
- **Event:** User "kaltway" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\kaltway\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-09-07T17:22:37.6905131Z`
- **Event:** A network connection to IP `81.137.179.68` on port `9001` by user "kaltway" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\kaltway\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-09-07T17:22:37.6606518Z` - Connected to `193.23.244.244` on port `443`.
  - `2025-09-07T17:21:55.4674378Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "kaltway" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-09-07T17:33:47.6935793Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\kaltway\Desktop\tor-shopping-list.txt`

---

## Summary

The user "kaltway" on the "kamal-windows-1" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint 'kamal-windows-1' by the user 'kaltway'. The device was isolated, and the user's direct manager was notified.

---
