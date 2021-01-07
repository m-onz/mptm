513 - Pentesting Rlogin
Basic Information

This service was mostly used in the old days for remote administration but now because of security issues this service has been replaced by the slogin and the ssh.

Default port: 513

PORT    STATE SERVICE
513/tcp open  login

Login

apt-get install rsh-client

This command will try to login to the remote host by using the login name root (for this service you don't need to know any password):

rlogin <IP> -l <username>

​Brute force​

hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V

Find files

find / -name .rhosts
