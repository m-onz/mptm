88tcp/udp - Pentesting Kerberos
Basic Information

Firstly, Kerberos is an authentication protocol, not authorization. In other words, it allows to identify each user, who provides a secret password, however, it does not validates to which resources or services can this user access.
Kerberos is used in Active Directory. In this platform, Kerberos provides information about the privileges of each user, but it is responsability of each service to determine if the user has access to its resources.

Default Port: 88/tcp/udp

PORT   STATE SERVICE
88/tcp open  kerberos-sec

To learn how to abuse Kerberos you should read the post about Active Directory.
More
Shodan

    port:88 kerberos

MS14-068

Simply stated, the vulnerability enables an attacker to modify an existing, valid, domain user logon token (Kerberos Ticket Granting Ticket, TGT, ticket) by adding the false statement that the user is a member of Domain Admins (or other sensitive group) and the Domain Controller (DC) will validate that (false) claim enabling attacker improper access to any domain (in the AD forest) resource on the network.
Kerberos Vulnerability in MS14-068 (KB3011780) Explained
Thanks to Gavin Millard (@gmillard on Twitter), we have a graphic that covers the issue quite nicely (wish I had of thought of it!) Exploit Code is now on the net! As of December 4th, 2014, there is Proof of Concept (POC) code posted that exploits MS14-068 by Sylvain Monné by using Python to interact with ...
adsecurity.org

Other exploits: https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek
