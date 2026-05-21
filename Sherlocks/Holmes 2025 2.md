
Discovery and Reconnaissance

We notice a communication between a user and a chatbot website hosted as' *msp-helpdesk-ai:1337*'
the first post request is originated from the machine *10.0.69.45* made by the machine WATSON-ALPHA-2

The attacker tried to perform prompt injection to leak remote management tool info  *2025-08-19 12:02:06*


**RMM ID**: 565 963 039  \n   - **Password**: CogWork_Central_97&65 

Viewing  Acces logs of Team viewer we can coclude that he attacker remotely access Cogwork Central Workstation  


![[Pasted image 20260510205124.png]]

the attacker machine whose address ip *192.168.69.213* accessed the machine using The RMM account James Moriarty. *2025-08-20 09:58:25*

Viewing meticulously the log file TeamViewer158logfile the attacker stage some tools in the directory *C:\Windows\temp\safe\*




[CSV Viewer Online](https://csv-viewer-online.github.io/)

Using the tool [rowingdude/analyzeMFT](https://github.com/rowingdude/analyzeMFT) that parses MFt tables and USN journal


- When you run a program or executable, Windows creates a `.pf` file in the `C:\Windows\Prefetch` directory to cache data, such as program paths and run counts. This helps the application open faster the next time you use it.


When did the attacker access and read a txt file, which was probably the output of one of the tools they brought, due to the naming convention of the file?



Filtering On files created under the directorry safe using the identifer Entrynumber

![[Pasted image 20260517191638.png]]

the attacker read the file dump.txt


# Main Persistence Techniques Covered

| MITRE ID      | Technique                               | Relevant Events        |
| ------------- | --------------------------------------- | ---------------------- |
| T1053         | Scheduled Task/Job                      | 4688, 4624, 4672, 4648 |
| T1543         | Create/Modify System Process (Services) | 4688, 4672, 4624       |
| T1060 / T1547 | Registry Run Keys & Startup Folder      | 4688, 4624             |
| T1546         | Event Triggered Execution (WMI)         | 4688, 4672             |
| T1055         | Process Injection / Token Abuse         | 4696, 4672             |
| T1098         | Account Manipulation                    | 4624, 4672             |
| T1078         | Valid Accounts                          | 4624, 4648, 4672       |
| T1550         | Use Alternate Authentication Material   | 4624, 4648             |
| T1558         | Kerberos Attacks                        | 4768, 4672             |
| T1548         | Abuse Elevation Control Mechanism       | 4672, 4696             |


using registry explorer to pard teh software hive

![[Pasted image 20260517224434.png]]



![[Pasted image 20260517224745.png]]