548 - Pentesting Apple Filing Protocol (AFP)
Basic Information

The Apple Filing Protocol (AFP), formerly AppleTalk Filing Protocol, is a proprietary network protocol, and part of the Apple File Service (AFS), that offers file services for macOS and the classic Mac OS. In macOS, AFP is one of several file services supported. AFP currently supports Unicode file names, POSIX and access control list permissions, resource forks, named extended attributes, and advanced file locking. In Mac OS 9 and earlier, AFP was the primary protocol for file services.

Default port: 548

PORT    STATE SERVICE
548/tcp open  afp

Enumeration

msf> use auxiliary/scanner/afp/afp_server_info
nmap -sV --script "afp-* and not dos and not brute" -p <PORT> <IP>

Name
	

Description

afp-ls
	

Lists available AFP volumes and files

afp-path-vuln
	

Lists all AFP volumes and filesa​

afp-serverinfo
	

Displays AFP server information

afp-showmount
	

Lists available AFP shares and respective ACLs

Brute force

nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
