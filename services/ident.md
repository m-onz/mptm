113 - Pentesting Ident
Basic Information

Is an Internet protocol that helps identify the user of a particular TCP connection.

Default port: 113

PORT    STATE SERVICE
113/tcp open  ident

Enumeration
Manual - Get user/Identify the service

If a machine is running the service ident and samba (445) and you are connected to samba using the port 43218. You can get which user is running the samba service by doing:

If you just press enter when you conenct to the service:

Other errors:
Nmap

By default (-sC) nmap will identify every user of every running port:

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.3p2 Debian 9 (protocol 2.0)
|_auth-owners: root
| ssh-hostkey: 
|   1024 88:23:98:0d:9d:8a:20:59:35:b8:14:12:14:d5:d0:44 (DSA)
|_  2048 6b:5d:04:71:76:78:56:96:56:92:a8:02:30:73:ee:fa (RSA)
113/tcp open  ident
|_auth-owners: identd
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: LOCAL)
|_auth-owners: root
445/tcp open  netbios-ssn Samba smbd 3.0.24 (workgroup: LOCAL)
|_auth-owners: root

Ident-user-enum

Ident-user-enum is a simple PERL script to query the ident service (113/TCP) in order to determine the owner of the process listening on each TCP port of a target system. The list of usernames gathered can be used for password guessing attacks on other network services. It can be installed with apt install ident-user-enum.

root@kali:/opt/local/recon/192.168.1.100# ident-user-enum 192.168.1.100 22 113 139 445
ident-user-enum v1.0 ( http://pentestmonkey.net/tools/ident-user-enum )
​
192.168.1.100:22  root
192.168.1.100:113 identd
192.168.1.100:139 root
192.168.1.100:445 root

Shodan

    oident

Files

identd.conf
