514 - Pentesting Rsh
Basic Information

Rsh use .rhosts files and /etc/hosts.equiv for authentication. These methods relied on IP addresses and DNS (Domain Name System) for authentication. However, spoofing IP addresses is fairly easy, especially if the attacker is on the local network.

Furthermore, the .rhosts files were stored in users' home directories, which were typically stored on NFS (Network File System) volumes. (from here: https://www.ssh.com/ssh/rsh).

Default port: 514
Login

rsh <IP> <Command>
rsh <IP> -l domain\user <Command>
rsh domain/user@<IP> <Command>
rsh domain\\user@<IP> <Command>

Brute force

hydra -L <Username_list> rsh://<Victim_IP> -v -V
http://pentestmonkey.net/tools/misc/rsh-grind
