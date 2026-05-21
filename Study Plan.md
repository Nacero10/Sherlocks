
## Track 0 — Intro to Blue Team

| Sherlock Name | Difficulty | Focus Area                           | Core Skills                               | Typical Artifacts                         | ATT&CK Themes                                        | Recommended Outcome                    |
| ------------- | ---------- | ------------------------------------ | ----------------------------------------- | ----------------------------------------- | ---------------------------------------------------- | -------------------------------------- |
| Brutus        | Very Easy  | SSH brute-force investigation        | Linux auth analysis, log review           | auth.log, SSH logs                        | T1110 Brute Force                                    | Detect password spraying & SSH attacks |
| BFT           | Very Easy  | Windows forensic timeline basics     | Timeline analysis, event correlation      | Windows Event Logs, filesystem timestamps | T1070 Indicator Removal, T1083 File Discovery        | Build DFIR investigation flow          |
| Unit42        | Very Easy  | Sysmon / endpoint investigation      | Sysmon hunting, process tracing           | Sysmon logs, process trees                | T1059 Command Execution, T1105 Ingress Tool Transfer | Understand endpoint telemetry          |
| i-like-to     | Easy       | Web / OSINT investigation            | Web enumeration, OSINT                    | HTTP logs, public intel                   | Reconnaissance techniques                            | Investigate public exposure            |
| Meerkat       | Easy       | Malware / phishing analysis          | IOC extraction, phishing triage           | Emails, URLs, malware indicators          | T1566 Phishing                                       | Identify phishing campaigns            |
| Litter        | Easy       | Windows event logs & DFIR            | Event ID correlation                      | Security.evtx, PowerShell logs            | T1059.001 PowerShell                                 | Understand Windows logging             |
| LogJammer     | Easy       | Log analysis & attack tracing        | SIEM thinking, attack path analysis       | Mixed logs                                | Multiple ATT&CK stages                               | Trace attacker actions chronologically |
| Nubilum2      | Easy       | Cloud / Linux investigation          | Linux & cloud artifact analysis           | Linux logs, cloud traces                  | Cloud persistence & access                           | Understand hybrid investigations       |
| Tracer        | Easy       | Threat hunting & artifact tracing    | IOC hunting, endpoint tracing             | Registry, logs, persistence artifacts     | T1547 Boot/Logon Autostart                           | Build hunting methodology              |
| Jingle Bell   | Easy       | Seasonal forensic case               | General DFIR workflow                     | Mixed evidence                            | Multiple ATT&CK stages                               | Practice end-to-end triage             |
| Pikaptcha     | Easy       | Web exploitation traces              | Web attack analysis                       | Web server logs                           | T1190 Exploit Public-Facing Application              | Investigate web compromise             |
| Ultimatum     | Easy       | Incident response investigation      | Incident scoping, containment logic       | Mixed enterprise logs                     | Full attack chain                                    | Improve IR decision-making             |
| Recollection  | Easy       | Memory / artifact recovery           | Memory analysis, recovery                 | RAM artifacts, temp files                 | Credential & malware traces                          | Recover attacker evidence              |
| Lockpick      | Easy       | Authentication / credential analysis | Credential hunting, authentication review | Login logs, Kerberos/NTLM artifacts       | T1003 OS Credential Dumping                          | Detect credential abuse                |
| RogueOne      | Easy       | Insider / rogue device activity      | Insider threat analysis                   | Device logs, user activity                | T1078 Valid Accounts                                 | Investigate unauthorized access        |
| Heartbreaker  | Medium     | Advanced DFIR challenge              | Multi-stage DFIR, advanced correlation    | Enterprise-scale artifacts                | Multi-tactic intrusion                               | Simulate real SOC investigation        |

## Track 1 — CDSA Preparation

|                       |            |                                 |                                        |                                  |                    |
| --------------------- | ---------- | ------------------------------- | -------------------------------------- | -------------------------------- | ------------------ |
| Sherlock Name         | Difficulty | Focus Area                      | Why It Matters for CDSA                | Key Defensive Skills             | Suggested Priority |
| Unit42                | Very Easy  | Sysmon / endpoint investigation | Builds endpoint telemetry fundamentals | Process analysis, Sysmon hunting | High               |
| Campfire-1            | Very Easy  | Intro forensic analysis         | Establishes investigation workflow     | Evidence handling, log review    | High               |
| Recollection          | Easy       | Memory / artifact recovery      | Important for DFIR practical exams     | Artifact recovery                | High               |
| RogueOne              | Easy       | Insider / rogue activity        | Covers account misuse patterns         | User behavior analysis           | Medium             |
| LogJammer             | Easy       | Attack tracing                  | Excellent for timeline reconstruction  | Correlation & SIEM logic         | High               |
| Trojan                | Easy       | Malware investigation           | Malware triage basics                  | IOC extraction                   | High               |
| Tracer                | Easy       | Threat hunting                  | Hunting methodology                    | IOC pivoting                     | High               |
| ReliableThreat        | Medium     | Threat intelligence & IR        | More realistic enterprise analysis     | Threat correlation               | Medium             |
| Jinkies               | Medium     | Advanced investigation          | Multi-step DFIR reasoning              | Deep artifact analysis           | Medium             |
| Detroit Becomes Human | Hard       | Complex DFIR scenario           | Advanced CDSA-style challenge          | Enterprise investigation         | High               |
| Streamer              | Hard       | Advanced intrusion analysis     | Realistic attacker behavior            | Full attack-chain tracing        | High               |





## Track 2 — Operation Tinsel Trace II: Santa vs. Krampus

| **Track 0**                            |                |                                   |                             |                                |                           |            |
| -------------------------------------- | -------------- | --------------------------------- | --------------------------- | ------------------------------ | ------------------------- | ---------- |
| **Sherlock Name**                      | **Difficulty** | **Focus Area**                    | **Likely Technologies**     | **Defensive Concepts**         | **Investigation Style**   | **Status** |
| OpTinselTrace24-1: Sneaky Cookies      | Hard           | Session / cookie abuse            | Web apps, browser artifacts | Session hijacking              | Web forensic analysis     |            |
| OpTinselTrace24-2: Cookie Consumption  | Easy           | Web tracking & abuse              | HTTP traffic                | Request analysis               | Beginner web DFIR         |            |
| OpTinselTrace24-3: Blizzard Breakdown  | Medium         | System compromise investigation   | Endpoint telemetry          | Attack chain reconstruction    | DFIR case study           |            |
| OpTinselTrace24-4: Neural Noel         | Easy           | AI / phishing / automation themes | Scripts, AI workflows       | Detection engineering          | Threat analysis           |            |
| OpTinselTrace24-5: Tale of Maple Syrup | Hard           | Advanced intrusion tracing        | Enterprise artifacts        | Lateral movement & persistence | Advanced DFIR             |            |
| OpTinselTrace24-6: Sleigh Slayer       | Hard           | Major incident response           | Mixed infrastructure        | Enterprise compromise response | Full attack investigation |            |



