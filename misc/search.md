Search Exploits
Browser

Always search in "google" or others: <service_name> [version] exploit

You should also try the shodan exploit search from https://exploits.shodan.io/.
Searchsploit

Useful to search exploits for services in exploitdb from the console.

#Searchsploit tricks
searchsploit "linux Kernel" #Example
searchsploit apache mod_ssl #Other example
searchsploit -m 7618 #Paste the exploit in current directory
searchsploit -p 7618[.c] #Show complete path
searchsploit -x 7618[.c] #Open vi to inspect the exploit
searchsploit --nmap file.xml #Search vulns inside an nmap xml result

MSF-Search

msf> search platform:windows port:135 target:XP type:exploit

PacketStorm

If nothing is found, try to search the used technology inside https://packetstormsecurity.com/​
Vulners

You can also search in vulners database: https://vulners.com/​
Sploitus
This search exploits in other databases: https://sploitus.com/
