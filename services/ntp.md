123/udp - Pentesting NTP
Basic Information

 The Network Time Protocol (NTP) is a networking protocol for clock synchronization between computer systems over packet-switched, variable-latency data networks.

Default port: 123/udp

PORT    STATE SERVICE REASON
123/udp open  ntp     udp-response

Enumeration

ntpq -c readlist <IP_ADDRESS>
ntpq -c readvar <IP_ADDRESS>
ntpq -c peers <IP_ADDRESS>
ntpq -c associations <IP_ADDRESS>
ntpdc -c monlist <IP_ADDRESS>
ntpdc -c listpeers <IP_ADDRESS>
ntpdc -c sysinfo <IP_ADDRESS>

nmap -sU -sV --script "ntp* and (discovery or vuln) and not (dos or brute)" -p 123 <IP>

Examine configuration files

    ntp.conf

NTP Amplification Attack

​How NTP DDoS Attack Works​

NTP protocol by design uses UDP to operate, which does not require any handshake like TCP, thus no record of the request. So, NTP DDoS amplification attack begins when an attacker crafts packets with a spoofed source IP to make the packets appear to be coming from the intended target and sends them to NTP server. Attacker initially crafts the packet of few bytes, but NTP responds with a large amount of data thus adding to amplification of this attack.

MONLIST command: It is a NTP protocol command which has very little use, but it is this command which is the main culprit for this attack. However, the use of MONLIST command is to give details of the last 600 clients that have connected to the NTP time service. Below is the command syntax:

ntpdc -n -c monlist <IP>

Shodan

    ntp
