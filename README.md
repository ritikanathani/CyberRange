# Unauthorized TOR Usage Detection

**Author:** Ritika Nathani

---

## Overview

This project demonstrates the detection of unauthorized TOR browser installation and usage within an enterprise environment. A controlled simulation was conducted to generate realistic Indicators of Compromise (IoCs), followed by analysis using Microsoft Defender XDR advanced hunting.

---

## Objective

* Simulate unauthorized TOR activity
* Generate endpoint and network telemetry
* Detect suspicious behavior using KQL
* Build a multi-layered detection approach

---

## Attack Simulation

To replicate adversarial behavior, the following steps were performed:

* Downloaded the TOR browser installer
* Executed a silent installation using command-line arguments
* Launched the TOR browser and accessed `.onion` domains
* Created and deleted a file (`tor-shopping-list.txt`) to simulate user activity and evasion

---

## Data Sources

### DeviceFileEvents

* Monitors file creation, modification, and deletion
* Used to detect TOR installer, binaries, and suspicious file activity

### DeviceProcessEvents

* Captures process execution data
* Used to identify installation and execution of TOR

### DeviceNetworkEvents

* Tracks network connections
* Used to detect TOR-related traffic over known ports

---

## Detection Approach

Detection logic was built by correlating signals across:

* File activity (installer and executable presence)
* Process behavior (silent installation and execution patterns)
* Network traffic (connections over TOR-specific ports)
* User activity (file creation and deletion patterns)

---

## Sample Queries

### TOR Installer Detection

```kql
DeviceFileEvents
| where FileName startswith "tor"
```

### Silent Installation Detection

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "/S"
| where ProcessCommandLine contains "tor-browser"
```

### TOR Execution Detection

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("tor.exe", "firefox.exe")
```

### TOR Network Activity

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
```

### Suspicious File Activity

```kql
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```

---

## Key Takeaways

* Correlating multiple telemetry sources improves detection accuracy
* Silent installations are strong indicators of suspicious activity
* Known TOR ports provide reliable network-based detection signals
* File activity patterns can indicate user intent and evasion techniques

---

## Skills Demonstrated

* Threat simulation and adversary emulation
* KQL-based threat hunting
* Microsoft Defender XDR analysis
* Detection engineering

---

## Future Enhancements

* Implement automated alerting rules
* Map detections to MITRE ATT&CK framework
* Expand monitoring to additional telemetry sources
