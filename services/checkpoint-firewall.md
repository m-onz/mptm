264 - Pentesting Check Point FireWall-1

Module sends a query to the port 264/TCP on CheckPoint Firewall-1 firewalls to obtain the firewall name and management station (such as SmartCenter) name via a pre-authentication request

use auxiliary/gather/checkpoint_hostname
set RHOST 10.10.xx.xx

Sample Output

[*] Attempting to contact Checkpoint FW1 SecuRemote Topology service...
[+] Appears to be a CheckPoint Firewall...
[+] Firewall Host: FIREFIGHTER-SEC
[+] SmartCenter Host: FIREFIGHTER-MGMT.example.com
[*] Auxiliary module execution completed

From: https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html#check-point-firewall-1-topology-port-264​

Another way to obtain the firewall's hostname and ICA name could be

printf '\x51\x00\x00\x00\x00\x00\x00\x21\x00\x00\x00\x0bsecuremote\x00' | nc -q 1 x.x.x.x 264 | grep -a CN | cut -c 2-

Sample Output

CN=Panama,O=MGMTT.srv.rxfrmi

From: https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk69360
