194,6667,6660-7000 - Pentesting IRC
Basic Information

IRC was originally a plain text protocol (although later extended), which on request was assigned port 194/TCP by IANA. However, the de facto standard has always been to run IRC on 6667/TCP and nearby port numbers (for example TCP ports 6660–6669, 7000) to avoid having to run the IRCd software with root privileges.

For connecting to a server it is required merely a nickname. Once connection is established, the first thing the server does is a reverse-dns to your ip:

It seems that overall there are two kinds of users: operators and ordinary users. For logging in as an operator it is required a username and a password (and in many occasions a particular hostname, ip  and even a particular hostmask). Within operators there are different privilege levels wherein the administrator has the highest privilege.

Default ports: 194, 6667, 6660-7000

PORT     STATE SERVICE
6667/tcp open  irc

Enumeration
Banner

IRC can support TLS.

nc -vn <IP> <PORT>
openssl s_client -connect <IP>:<PORT> -quiet

Manual

Here you can see how to connect and access the IRC using some random nickname and then enumerate some interesting info. You can learn more commands of IRC here.

#Connection with random nickname
USER ran213eqdw123 0 * ran213eqdw123
NICK ran213eqdw123
#If a PING :<random> is responded you need to send
#PONG :<received random>
​
VERSION
HELP
INFO
LINKS
HELPOP USERCMDS
HELPOP OPERCMDS
OPERATOR CAPA
ADMIN      #Admin info
USERS      #Current number of users
TIME       #Server's time
STATS a    #Only operators should be able to run this
NAMES      #List channel names and usernames inside of each channel -> Nombre del canal y nombre de las personas que estan dentro
LIST       #List channel names along with channel banner
WHOIS <USERNAME>      #WHOIS a username
USERHOST <USERNAME>   #If available, get hostname of a user
USERIP <USERNAME>     #If available, get ip of a user
JOIN <CHANNEL_NAME>   #Connect to a channel
​
#Operator creds Brute-Force
OPER <USERNAME> <PASSWORD>

Find and scan IRC services

nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 194,6660-7000 irked.htb

​Brute Force​
Shodan

    looking up your hostname
