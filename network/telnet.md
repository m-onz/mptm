23 - Pentesting Telnet
Basic Information

Telnet is a network protocol that gives users a UNsecure way to access a computer over a network.

Default port: 23

23/tcp open  telnet

Enumeration
Banner Grabbing

nc -vn <IP> 23

All the interesting enumeration can be performed by nmap:

nmap -n -sV -Pn --script "*telnet* and safe" -p 23 <IP>

The script telnet-ntlm-info.nse will obtain NTLM info (Windows versions).

In the TELNET Protocol are various "options" that will be sanctioned and may be used with the "DO, DON'T, WILL, WON'T" structure to allow a user and server to agree to use a more elaborate (or perhaps just different) set of conventions for their TELNET connection. Such options could include changing the character set, the echo mode, etc. (From the telnet RFC)
I know it is possible to enumerate this options but I don't know how, so let me know if know how.
​Brute force​
Config file

/etc/inetd.conf
/etc/xinetd.d/telnet
/etc/xinetd.d/stelnet
