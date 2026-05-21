



We notice a suspicious Get request from a suspicious useragent Lilnunc , the attacker ip was 121.36.37.224

| 2025-05-01 08:23:12 | Lilnunc | 121.36.37.224 | HIGH 13 | 200 | GET | robots.txt | GET /robots.txt HTTP/1.1 |
| ------------------- | ------- | ------------- | ------- | --- | --- | ---------- | ------------------------ |

Also the waf detected a webshell deployment througn the file  *temp_4A4D.php* 

| 2025-05-15 11:25:12 | waf.exec | 121.36.37.224 | WEBSHELL_DEPLOYMENT | PHP web shell temp_4A4D.php created |
| ------------------- | -------- | ------------- | ------------------- | ----------------------------------- |


The threat actor also managed to exfiltrate the database *database_dump_4A4D.sql*