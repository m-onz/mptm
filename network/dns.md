53 - Pentesting DNS
Basic Information

The Domain Name Systems (DNS) is the phonebook of the Internet. Humans access information online through domain names, like nytimes.com or espn.com. Web browsers interact through Internet Protocol (IP) addresses. DN S translates domain names to IP addresses so browsers can load Internet resources.
From here.

Default port: 53

PORT     STATE SERVICE  REASON
53/tcp   open  domain  Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
5353/udp open  zeroconf udp-response
53/udp   open  domain  Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)

Enumeration
Banner Grabbing

DNS does not have a "banner" to grab. The closest equivalent is a magic query for version.bind. CHAOS TXT which will work on most BIND nameservers.
You can perform this query using dig:

dig version.bind CHAOS TXT @DNS

If that does not work you can use fingerprinting techniques to determine the remote server's version -- the fpdns tool is one option for that, but there are others.

You can grab the banner also with a nmap script:

--script dns-nsid

Zone Transfer

dig axfr @<DNS_IP> #Try zone transfer without domain
dig axfr @<DNS_IP> <DOMAIN> #Try zone transfer guessing the domain
fierce -dns <DOMAIN> #Will try toperform a zone transfer against every authoritative name server and if this doesn'twork, will launch a dictionary attack

More info

dig ANY @<DNS_IP> <DOMAIN>     #Any information
dig A @<DNS_IP> <DOMAIN>       #Regular DNS request
dig AAAA @<DNS_IP> <DOMAIN>    #IPv6 DNS request
dig TXT @<DNS_IP> <DOMAIN>     #Information
dig MX @<DNS_IP> <DOMAIN>      #Emails related
dig NS @<DNS_IP> <DOMAIN>      #DNS that resolves that name
dig -x 192.168.0.2 @<DNS_IP>   #Reverse lookup
dig -x 2a00:1450:400c:c06::93 @<DNS_IP> #reverse IPv6 lookup
​
#Use [-p PORT]  or  -6 (to use ivp6 address of dns)

Using nslookup

nslookup
> SERVER <IP_DNS> #Select dns server
> 127.0.0.1 #Reverse lookup of 127.0.0.1, maybe...
> <IP_MACHINE> #Reverse lookup of a machine, maybe...

Useful metasploit modules

auxiliary/gather/enum_dns #Perform enumeration actions

Useful nmap scripts

#Perform enumeration actions
nmap -n --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" <IP>

DNS - Reverse BF

dnsrecon -r 127.0.0.0/24 -n <IP_DNS>  #DNS reverse of all of the addresses
dnsrecon -r 127.0.1.0/24 -n <IP_DNS>  #DNS reverse of all of the addresses
dnsrecon -r <IP_DNS>/24 -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d active.htb -a -n <IP_DNS> #Zone transfer

Another tool to do so: https://github.com/amine7536/reverse-scan​

You can query reverse IP ranges to https://bgp.he.net/net/205.166.76.0/24#_dns (this tool is also helpful with BGP).
DNS - Subdomains BF

dnsrecon -D subdomains-1000.txt -d <DOMAIN> -n <IP_DNS>
dnscan -d <domain> -r -w subdomains-1000.txt #Bruteforce subdomains in recursive way, https://github.com/rbsec/dnscan

Active Directory servers

dig -t _gc._tcp.lab.domain.com
dig -t _ldap._tcp.lab.domain.com
dig -t _kerberos._tcp.lab.domain.com
dig -t _kpasswd._tcp.lab.domain.com
nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='domain.com'"

DNSSec

 #Query paypal subdomains to ns3.isc-sns.info
 nmap -sSU -p53 --script dns-nsec-enum --script-args dns-nsec-enum.domains=paypal.com ns3.isc-sns.info

IPv6

Brute force using "AAAA" requests to gather IPv6 of the subdomains.

dnsdict6 -s -t <domain>

Bruteforce reverse DNS in using IPv6 addresses

dnsrevenum6 pri.authdns.ripe.net 2001:67c:2e8::/48 #Will use the dns pri.authdns.ripe.net

DNS Recursion DDoS

If DNS recursion is enabled, an attacker could spoof the origin on the UDP packet in order to make the DNS send the response to the victim server. An attacker could abuse ANY or DNSSEC record types as they use to have the bigger responses.
The way to check if a DNS supports recursion is to query a domain name and check if the flag "ra" (recursion available) is in the response:

dig google.com A @<IP>

Non available:

Available:
Mail to nonexistent account

From book: Network Security Assessment (3rd edition)

Simply sending an email message to a nonexistent address at a target domain often reveals useful internal network information through a nondelivery notification (NDN).

Generating server: noa.nintendo.com
​
blah@nintendo.com
#550 5.1.1 RESOLVER.ADR.RecipNotFound; not found ##
​
Original message headers:
​
Received: from ONERDEDGE02.one.nintendo.com (10.13.20.35) by
 onerdexch08.one.nintendo.com (10.13.30.39) with Microsoft SMTP Server (TLS)
 id 14.3.174.1; Sat, 26 Apr 2014 16:52:22 -0700
Received: from barracuda.noa.nintendo.com (205.166.76.35) by
 ONERDEDGE02.one.nintendo.com (10.13.20.35) with Microsoft SMTP Server (TLS)
 id 14.3.174.1; Sat, 26 Apr 2014 16:51:22 -0700
X-ASG-Debug-ID: 1398556333-0614671716199b0d0001-zOQ9WJ
Received: from gateway05.websitewelcome.com (gateway05.websitewelcome.com  [69.93.154.37]) by 
barracuda.noa.nintendo.com with ESMTP id xVNPkwaqGgdyH5Ag for <blah@nintendo.com>; Sat, 
26 Apr 2014 16:52:13 -0700 (PDT)
X-Barracuda-Envelope-From: chris@example.org
X-Barracuda-Apparent-Source-IP: 69.93.154.37

The following data in this transcript is useful:

    Internal hostnames, IP addresses, and subdomain layout

    The mail server is running Microsoft Exchange Server 2010 SP3

    A Barracuda Networks device is used to perform content filtering

Config files

host.conf
resolv.conf
named.conf
