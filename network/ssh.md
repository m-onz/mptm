22 - Pentesting SSH/SFTP
Basic Information

SSH or Secure Shell or Secure Socket Shell, is a network protocol that gives users a secure way to access a computer over an unsecured network.

Default port: 22

22/tcp open  ssh     syn-ack

SSH servers:

    ​openSSH – OpenBSD SSH, shipped in BSD, Linux distributions and Windows since Windows 10

    ​Dropbear – SSH implementation for environments with low memory and processor resources, shipped in OpenWrt

    ​PuTTY – SSH implementation for Windows, the client is commonly used but the use of the server is rarer

    ​CopSSH – implementation of OpenSSH for Windows

SSH libraries (implementing server-side):

    ​libssh – multiplatform C library implementing the SSHv2 protocol with bindings in Python, Perl and R; it’s used by KDE for sftp and by GitHub for the git SSH infrastructure

    ​wolfSSH – SSHv2 server library written in ANSI C and targeted for embedded, RTOS, and resource-constrained environments

    ​Apache MINA SSHD – Apache SSHD java library is based on Apache MINA

    ​paramiko – Python SSHv2 protocol library

Enumeration
Banner Grabbing

nc -vn <IP> 22

Automated ssh-audit

ssh-audit is a tool for ssh server & client configuration auditing.

​https://github.com/jtesta/ssh-audit is an updated fork from https://github.com/arthepsy/ssh-audit/​

Features:

    SSH1 and SSH2 protocol server support;

    analyze SSH client configuration;

    grab banner, recognize device or software and operating system, detect compression;

    gather key-exchange, host-key, encryption and message authentication code algorithms;

    output algorithm information (available since, removed/disabled, unsafe/weak/legacy, etc);

    output algorithm recommendations (append or remove based on recognized software version);

    output security information (related issues, assigned CVE list, etc);

    analyze SSH version compatibility based on algorithm information;

    historical information from OpenSSH, Dropbear SSH and libssh;

    runs on Linux and Windows;

    no dependencies

usage: ssh-audit.py [-1246pbcnjvlt] <host>
​
   -1,  --ssh1             force ssh version 1 only
   -2,  --ssh2             force ssh version 2 only
   -4,  --ipv4             enable IPv4 (order of precedence)
   -6,  --ipv6             enable IPv6 (order of precedence)
   -p,  --port=<port>      port to connect
   -b,  --batch            batch output
   -c,  --client-audit     starts a server on port 2222 to audit client
                               software config (use -p to change port;
                               use -t to change timeout)
   -n,  --no-colors        disable colors
   -j,  --json             JSON output
   -v,  --verbose          verbose output
   -l,  --level=<level>    minimum output level (info|warn|fail)
   -t,  --timeout=<secs>   timeout (in seconds) for connection and reading
                               (default: 5)
$ python3 ssh-audit <IP>

​See it in action (Asciinema)​
Public SSH key of server

ssh-keyscan -t rsa <IP> -p <PORT>

Weak Cipher Algorithms

This is discovered by default by nmap. But you can also use sslcan or sslyze.
Shodan

    ssh

Brute force usernames, passwords and private keys
Username Enumeration

In some versions of OpenSSH you can make a timing attack to enumerate users. You can use a metasploit module in order to exploit this:

msf> use scanner/ssh/ssh_enumusers

​Brute force​

Some common ssh credentials here and here and below.
Private/Public Keys BF

If you know some ssh private key that could be used... lets try it. You can use the nmap script:

https://nmap.org/nsedoc/scripts/ssh-publickey-acceptance.html

Or the MSF auxiliary module:

msf> use scanner/ssh/ssh_identify_pubkeys

Known badkeys can be found here:
rapid7/ssh-badkeys
A collection of static SSH keys (public and private) that have made their way into software and hardware products. - rapid7/ssh-badkeys
github.com

You should look here in order to search for valid keys for the victim machine.
Kerberos

crackmapexec using the ssh protocol can use the option --kerberos to authenticate via kerberos.
For more info run crackmapexec ssh --help.
Default Credentials

Vendor
	

Usernames
	

Passwords

APC
	

apc, device
	

apc

Brocade
	

admin
	

admin123, password, brocade, fibranne

Cisco
	

admin, cisco, enable, hsa, pix, pnadmin, ripeop, root, shelladmin
	

admin, Admin123, default, password, secur4u, cisco, Cisco, _Cisco, cisco123, C1sco!23, Cisco123, Cisco1234, TANDBERG, change_it, 12345, ipics, pnadmin, diamond, hsadb, c, cc, attack, blender, changeme

Citrix
	

root, nsroot, nsmaint, vdiadmin, kvm, cli, admin
	

C1trix321, nsroot, nsmaint, kaviza, kaviza123, freebsd, public, rootadmin, wanscaler

D-Link
	

admin, user
	

private, admin, user

Dell
	

root, user1, admin, vkernel, cli
	

calvin, 123456, password, vkernel, Stor@ge!, admin

EMC
	

admin, root, sysadmin
	

EMCPMAdm7n, Password#1, Password123#, sysadmin, changeme, emc

HP/3Com
	

admin, root, vcx, app, spvar, manage, hpsupport, opc_op
	

admin, password, hpinvent, iMC123, pvadmin, passw0rd, besgroup, vcx, nice, access, config, 3V@rpar, 3V#rpar, procurve, badg3r5, OpC_op, !manage, !admin

Huawei
	

admin, root
	

123456, admin, root, Admin123, Admin@storage, Huawei12#$, HwDec@01, hwosta2.0, HuaWei123, fsp200@HW, huawei123

IBM
	

USERID, admin, manager, mqm, db2inst1, db2fenc1, dausr1, db2admin, iadmin, system, device, ufmcli, customer
	

PASSW0RD, passw0rd, admin, password, Passw8rd, iadmin, apc, 123456, cust0mer

Juniper
	

netscreen
	

netscreen

NetApp
	

admin
	

netapp123

Oracle
	

root, oracle, oravis, applvis, ilom-admin, ilom-operator, nm2user
	

changeme, ilom-admin, ilom-operator, welcome1, oracle

VMware
	

vi-admin, root, hqadmin, vmware, admin
	

vmware, vmw@re, hqadmin, default
Config Misconfigurations
Root login

By default most SSH server implementation will allow root login, it is advised to disable it because if the credentials of this accounts leaks, attackers will get administrative privileges directly and this will also allow attackers to conduct bruteforce attacks on this account.

How to disable root login for openSSH:

    Edit SSH server configuration sudoedit /etc/ssh/sshd_config

    Change #PermitRootLogin yes into PermitRootLogin no

    Take into account configuration changes: sudo systemctl daemon-reload

    Restart the SSH server sudo systemctl restart sshd

SFTP command execution

Another common SSH misconfiguration is often seen in SFTP configuration. Most of the time when creating a SFTP server the administrator want users to have a SFTP access to share files but not to get a remote shell on the machine. So they think that creating a user, attributing him a placeholder shell (like /usr/bin/nologin or /usr/bin/false) and chrooting him in a jail is enough to avoid a shell access or abuse on the whole file system. But they are wrong, a user can ask to execute a command right after authentication before it’s default command or shell is executed. So to bypass the placeholder shell that will deny shell access, one only has to ask to execute a command (eg. /bin/bash) before, just by doing:

$ ssh -v noraj@192.168.1.94 id
...
Password:
debug1: Authentication succeeded (keyboard-interactive).
Authenticated to 192.168.1.94 ([192.168.1.94]:22).
debug1: channel 0: new [client-session]
debug1: Requesting no-more-sessions@openssh.com
debug1: Entering interactive session.
debug1: pledge: network
debug1: client_input_global_request: rtype hostkeys-00@openssh.com want_reply 0
debug1: Sending command: id
debug1: client_input_channel_req: channel 0 rtype exit-status reply 0
debug1: client_input_channel_req: channel 0 rtype eow@openssh.com reply 0
uid=1000(noraj) gid=100(users) groups=100(users)
debug1: channel 0: free: client-session, nchannels 1
Transferred: sent 2412, received 2480 bytes, in 0.1 seconds
Bytes per second: sent 43133.4, received 44349.5
debug1: Exit status 0
​
$ ssh noraj@192.168.1.94 /bin/bash

Here is an example of secure SFTP configuration (/etc/ssh/sshd_config – openSSH) for the user noraj:

Match User noraj
        ChrootDirectory %h
        ForceCommand internal-sftp
        AllowTcpForwarding no
        PermitTunnel no
        X11Forwarding no
        PermitTTY no

This configuration will allow only SFTP: disabling shell access by forcing the start command and disabling TTY access but also disabling all kind of port forwarding or tunneling.
SFTP Tunneling

If you have access to a SFTP server you can also tunnel your traffic through this for example using the common port forwarding:

sudo ssh -L <local_port>:<remote_host>:<remote_port> -N -f <username>@<ip_compromised>

SFTP Symlink

The sftp have the command "symlink". Therefor, if you have writable rights in some folder, you can create symlinks of other folders/files. As you are probably trapped inside a chroot this won't be specially useful for you, but, if you can access the created symlink from a no-chroot service (for example, if you can access the symlink from the web), you could open the symlinked files through the web.

For example, to create a symlink from a new file "froot" to "/":

sftp> symlink / froot

If you can access the file "froot" via web, you will be able to list the root ("/") folder of the system.
Authentication methods

On high security environment it’s a common practice to enable only key-based or two factor authentication rather than the simple factor password based authentication. But often the stronger authentication methods are enabled without disabling the weaker ones. A frequent case is enabling publickey on openSSH configuration and setting it as the default method but not disabling password. So by using the verbose mode of the SSH client an attacker can see that a weaker method is enabled:

$ ssh -v 192.168.1.94
OpenSSH_8.1p1, OpenSSL 1.1.1d  10 Sep 2019
...
debug1: Authentications that can continue: publickey,password,keyboard-interactive

For example if an authentication failure limit is set and you never get the chance to reach the password method, you can use the PreferredAuthentications option to force to use this method.

$ ssh -v 192.168.1.94 -o PreferredAuthentications=password
...
debug1: Next authentication method: password

Review the SSH server configuration is necessary to check that only expected
methods are authorized. Using the verbose mode on the client can help to see
the effectiveness of the configuration.
Config files

ssh_config
sshd_config
authorized_keys
ssh_known_hosts
known_hosts
id_rsa

Fuzzing

    ​https://packetstormsecurity.com/files/download/71252/sshfuzz.txt​

    ​https://www.rapid7.com/db/modules/auxiliary/fuzzers/ssh/ssh_version_2​

References

    You can find interesting guides on how to harden SSH in https://www.ssh-audit.com/hardening_guides.html​

    ​https://community.turgensec.com/ssh-hacking-guide
