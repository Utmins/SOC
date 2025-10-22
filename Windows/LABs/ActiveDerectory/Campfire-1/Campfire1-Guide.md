# Campfire1 — Guide  
### Practical Guide to Investigating a Kerberoasting Incident

---

## 📖 Scenario Overview

A user reported suspicious files on a workstation to the SOC. Preliminary analysis suggests a possible Kerberoasting attack within an Active Directory environment.

Provided artifacts for the investigation:

- Domain Controller security logs: `Security-DC.evtx`  
- PowerShell operational logs from the workstation: `Powershell-Operational.evtx`  
- Prefetch files from the affected workstation

Objective — confirm or refute Kerberoasting activity, collect a set of IOCs (IPs, accounts, executable names, timestamps), and map observed behavior to the MITRE ATT&CK technique **T1558.003**.

---

## 🧰 Tools and Resources

| Category | Purpose | Recommendations |
|---|---:|---|
| EVTX → CSV/JSON | Convert Windows event logs | `EvtxEcmd`, `wevtx`, PowerShell `Get-WinEvent` |
| Prefetch analysis | Parse prefetch artifacts | `PECmd` |
| Timeline / visualization | Correlate events across sources | `TimelineExplorer`, ELK/Splunk |
| PowerShell logging | Decode / search scriptblocks | Event Viewer (4104), `LogParser` |
| General CLI | Text processing and automation | `jq`, `grep`, `awk`, `sed` (Linux/WSL) |

> ⚠️ Perform all activities **only** in an isolated lab environment (VM / sandbox). Work on copies of artifacts — never analyze suspicious binaries on a production host.

---

## 🧩 Quick Overview: What is Kerberoasting?

Kerberoasting is a technique that abuses Kerberos service tickets (TGS) to obtain encrypted ticket material for service accounts and then attempts to crack those tickets offline (MITRE ATT&CK: **T1558.003**).

Common Windows event indicators:
- **Event ID 4768** — TGT request.  
- **Event ID 4769** — TGS (service ticket) request for an SPN.  
- **Event ID 4624 / 4625** — successful / failed logon.  
- **Event ID 4648** — explicit credential usage.  
- **Event ID 4688** — process creation.  
- **Event ID 4104** — PowerShell ScriptBlock logging (content of executed scripts).

---

## 🧭 Analysis Workflow

Recommended sequence:
1. Export EVTX records to CSV/JSON for analysis.  
2. Rebuild a timeline: correlate events in `Security-DC.evtx`, `Powershell-Operational.evtx`, and Prefetch.  
3. Identify suspicious TGS requests (4769) and any correlated process/script execution (4688 / 4104).  
4. Determine who, when, from which host, and which files were involved.  
5. Produce IOCs and recommended remediation actions.

---

## 🔎 Detailed Tasks

### Task 1 — Determine incident time window (start of activity)
**Goal:** identify the time window during which suspicious activity occurred.

**Approach:**
1. Export relevant Security events (e.g., 4768, 4769, 4648, 4624, 4625) to CSV using `EvtxEcmd` or PowerShell:
```powershell
Get-WinEvent -Path .\Security-DC.evtx -FilterHashtable @{Id=4768,4769,4648,4624,4625} | Export-Csv -Path headers.csv -NoTypeInformation
```
2. Filter for Event ID **4769** and look for bursts of requests in a short time span.  
3. Correlate with 4648/4624/4625 events to see credential usage prior to or during the TGS requests.

**Notes:** Kerberoasting is often a short burst of many 4769 requests for different SPNs originating from one host or account. Record the min/max timestamps to define your incident corridor.

---

### Task 2 — Identify target service(s) (ServiceName / SPN)
**Goal:** find which SPNs were targeted by the actor.

**Approach:**
1. In your exported 4769 records, look for the `ServiceName` / `Service Principal Name` field.  
2. Gather unique SPNs — pay attention to service types like `MSSQLSvc/host:port`, `HTTP/host`, `LDAP/host`, etc.

**Example PowerShell:**

```powershell
Import-Csv headers.csv | Where-Object {$_.Id -eq 4769} | Select-Object TimeCreated,TargetUserName,ServiceName | Sort-Object TimeCreated
```

**Note:** SPN requests grant a ticket that contains the encrypted material targeted in Kerberoast attacks.

---

### Task 3 — Identify source workstation IP
**Goal:** determine the client IP used to make the suspicious requests.

**Approach:**
- In Event Viewer, check the `Network Information: Client Address` field. In exported CSV look for `ClientAddress` / `RemoteHost` fields.
- Example extraction pattern (adjust to CSV schema):

```powershell
Import-Csv headers.csv | Where-Object {$_.Id -in 4768,4769} | Select TimeCreated,@{n='ClientIP';e={$_.ClientAddress}},TargetUserName
```

**Note:** Document IP + host name (if present) to pivot to endpoint logs and EDR telemetry.

---

### Task 4 — Determine script/file used for enumeration
**Goal:** find which PowerShell script or binary performed Active Directory enumeration and SPN requests.

**Approach:**
1. Search `Powershell-Operational.evtx` for Event ID **4104** entries within the incident time window. These contain ScriptBlock logging output.
2. Filter entries by the account that triggered the 4769 requests.
3. Search the ScriptBlock content for common enumeration keywords and tool names: `Get-ADUser`, `Get-ADComputer`, `Get-ADServiceAccount`, `Setspn`, `Invoke-Kerberoast`, `Request-TGS`, etc.

**Example export:**

```powershell
Get-WinEvent -Path .\Powershell-Operational.evtx -FilterHashtable @{Id=4104} | Export-Csv -Path ps_4104.csv -NoTypeInformation
```

**Interpretation:** presence of functions/modules explicitly requesting SPNs or using Kerberoast-related code is strong evidence of an attack framework in use.

---

### Task 5 — Timestamps: when was the script or tool executed?
**Goal:** determine precise execution times for correlation with DC logs.

**Approach:**
- Use `TimeCreated` on 4104 records and `Event ID 4688` (process creation) entries to extract execution timestamps.
- Cross-reference Prefetch timestamps where available.

**Example:**

```powershell
Get-WinEvent -Path .\Security-DC.evtx -FilterHashtable @{Id=4688} | Where-Object { $_.Message -match 'powershell|cmd|python' } | Select TimeCreated, Message
```

**Note:** if the script was run via `powershell.exe -File script.ps1`, the process command line will include the script path and parameters.

---

### Task 6 — Identify utility and full path via Prefetch
**Goal:** identify the executable used on the host and its path.

**Approach:**
1. Parse Prefetch files with `PECmd` or similar to produce CSV/JSON output:
```bash
pecmd.exe -f prefetch_folder -o prefetch.csv
```
2. Load results into your timeline and filter by the incident time window.
3. Look for executables outside standard system locations or with suspicious names (`svchosts.exe`, `pwsh-old.exe`, etc.).

**Interpretation:** Prefetch provides executable name, path and run count — useful to tie a binary to observed activity.

---

### Task 7 — Determine launch time of the discovered utility
**Goal:** obtain the precise launch timestamp to correlate with 4769 requests.

**Approach:** combine Prefetch timestamps and Event ID 4688 process creation logs to produce a precise timeline for the executable launch.

**Note:** Matching timestamps between utility execution, ScriptBlock logging, and mass 4769 requests strengthens attribution to the tool.

---

## ✅ Reporting Requirements

Your final report should include:

1. Executive summary: incident description, impacted assets, and immediate risk.  
2. Timeline: concise event chronology with timestamps and event IDs.  
3. IOCs:
   - Source IP(s) and hostnames (ClientAddress).  
   - Targeted service accounts and SPNs.  
   - User accounts involved (TargetUserName).  
   - Filenames/paths and any available hashes (from Prefetch or extracted files).  
4. MITRE ATT&CK mapping: include **T1558.003 — Kerberoasting** and rationale.  
5. Remediation recommendations:
   - Reset passwords for affected service accounts, prioritizing accounts without complex password policies.  
   - Harden service account privileges and apply least privilege.  
   - Enable or review Kerberos auditing and PowerShell logging settings.  
   - Conduct endpoint EDR hunts for the source host and related activity.  

---

## 🔒 Safety Notes for Analysis

- Work only with copies of artifacts.  
- Never execute suspicious binaries outside an isolated analysis VM.  
- Preserve logs and exported CSV/JSON for IR and possible legal processes.

---

## 🛠 Quick Commands / Templates

- Export relevant Security events:
```powershell
Get-WinEvent -Path .\Security-DC.evtx -FilterHashtable @{Id=4768,4769,4688,4104,4648} | Export-Csv -Path security_events.csv -NoTypeInformation
```
- Extract SPN-targeted events from CSV:
```powershell
Import-Csv security_events.csv | Where-Object {$_.Id -eq 4769} | Select TimeCreated, TargetUserName, ServiceName | Sort TimeCreated
```
- Convert Prefetch to CSV (PECmd) and filter by time/name.

---

## References and Tools

- MITRE ATT&CK: Kerberoasting — T1558.003
- Utilities: `EvtxEcmd`, `PECmd`, `TimelineExplorer`, PowerShell `Get-WinEvent`

---

> This guide is designed as a reproducible SOC/DFIR playbook for triaging suspected Kerberoasting incidents. If you want, I can also:
> - save this as `Campfire1-Guide.md` in `/mnt/data`, or
> - export a DOCX version ready for distribution.
