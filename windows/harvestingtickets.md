Harvesting tickets from Windows

In Windows, tickets are handled and stored by the lsass (Local Security Authority Subsystem Service) process, which is responsible for security. Hence, to retrieve tickets from a Windows system, it is necessary to communicate with lsass and ask for them. As a non-administrative user only owned tickets can be fetched, however, as machine administrator, all of them can be harvested. For this purpose, the tools Mimikatz or Rubeus can be used as shown below:

mimikatz # sekurlsa::tickets /export
.\Rubeus dump
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))

This information was taken from: https://www.tarlogic.com/en/blog/how-to-attack-kerberos/

Harvesting tickets from Linux

On Linux, tickets are stored in credential caches or ccaches. There are 3 main types, which indicate where tickets can be found:

    Files, by default under /tmp directory, in the form of krb5cc_%{uid}.

    Kernel Keyrings, an special space in the Linux kernel provided for storing keys.

    Process memory, used when only one process needs to use the tickets.

To verify what type of storage is used in a specific machine, the variable default_ccache_name must be checked in the /etc/krb5.conf file, which by default has read permission to any user. In case of this parameter being missing, its default value is FILE:/tmp/krb5cc_%{uid}.

In order to extract tickets from the other 2 sources (keyrings and processes), a great paper, Kerberos Credential Thievery (GNU/Linux), released in 2017, explains ways of recovering the tickets from them.
Keyring - From the paper

    The Linux kernel has a feature called keyrings. This is an area of memory residing within the kernel that is used to manage and retain keys.

    The keyctl system call was introduced in kernel version 2.6.10 5 . This provides user space applications an API which can be used to interact with kernel keyrings.

    The name of the keyring in use can be parsed from the Kerberos configuration file /etc/krb5.conf which has read permission enable for anybody (octal 644) by default. An attacker can then leverage this information to search for ticket 11 containing keyrings and extract the tickets. A proof of concept script that implements this functionality can be seen in Section A.2 (hercules.sh). In a keyring the ccache is stored as components. As seen in Figure 2, a file ccache is made up of 3 distinct components: header, default principal, and a sequence of credentials. A keyring holds the default principal and credentials. This script will dump these components to separate files. Then using an attacker synthesised header these pieces are combined in the correct order to rebuild a file ccache. This rebuilt file can then be exfiltrated to an attacker machine and then used to impersonate a Kerberos user. A simple program for generating a valid ccache header can be seen in Section A.3.

Based on the heracles.sh script (from the paper) a C tool you can use (created by the author of the complete post) is tickey,  and it extracts tickets from keyrings:

/tmp/tickey -i

This information was taken from: https://www.tarlogic.com/en/blog/how-to-attack-kerberos/
