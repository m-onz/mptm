161,162,10161,10162/udp - Pentesting SNMP
SNMP - Explained

SNMP - Simple Network Management Protocol is a protocol used to monitor different devices in the network (like routers, switches, printers, IoTs...).

PORT    STATE SERVICE REASON                 VERSION
161/udp open  snmp    udp-response ttl 244   ciscoSystems SNMPv3 server (public)

MIB

MIB stands for Management Information Base and is a collection of information organized hierarchically. These are accessed using a protocol such as SNMP. There are two types of MIBs: scalar and tabular.
Scalar objects define a single object instance whereas tabular objects define multiple related object instances grouped in MIB tables.
OIDs

OIDs stands for Object Identifiers. OIDs uniquely identify managed objects in a MIB hierarchy. This can be depicted as a tree, the levels of which are assigned by different organizations. Top level MIB object IDs (OIDs) belong to different standard organizations.
Vendors define private branches including managed objects for their own products.

You can navigate through an OID tree from the web here: http://www.oid-info.com/cgi-bin/display?tree=#focus or see what a OID means (like 1.3.6.1.2.1.1) accessing http://oid-info.com/get/1.3.6.1.2.1.1.
There are some well-known OIDs like the ones inside 1.3.6.1.2.1 that references MIB-2 defined Simple Network Management Protocol (SNMP) variables. And from the OIDs pending from this one you can obtain some interesting host data (system data, network data, processes data...)
OID Example

1 . 3 . 6 . 1 . 4 . 1 . 1452 . 1 . 2 . 5 . 1 . 3. 21 . 1 . 4 . 7

Here is a breakdown of this address.

    1 – this is called the ISO and it establishes that this is an OID. This is why all OIDs start with “1”

    3 – this is called ORG and it is used to specify the organization that built the device.

    6 – this is the dod or the Department of Defense which is the organization that established the Internet first.

    1 – this is the value of the internet to denote that all communications will happen through the Internet.

    4 – this value determines that this device is made by a private organization and not a government one.

    1 – this value denotes that the device is made by an enterprise or a business entity.

These first six values tend to be the same for all devices and they give you the basic information about them. This sequence of numbers will be the same for all OIDs, except when the device is made by the government.

Moving on to the next set of numbers. 

    1452 – gives the name of the organization that manufactured this device.

    1 – explains the type of device. In this case, it is an alarm clock.

    2 – determines that this device is a remote terminal unit.

The rest of the values give specific information about the device.

    5 – denotes a discrete alarm point.

    1 – specific point in the device

    3 – port

    21 – address of the port

    1 – display for the port

    4 – point number

    7 – state of the point

(Example take from here)
SNMP Versions

There are 2 important versions of SNMP:

    SNMPv1: Main one, it is still the most frequent, the authentication is based on a string (community string) that travels in plain-text (all the information travels in plain text). Version 2 and 2c send the traffic in plain text also and uses a community string as authentication.

    SNMPv3: Uses a better authentication form and the information travels encrypted using (dictionary attack could be performed but would be much harder to find the correct creds that inn SNMPv1 and v2).

Community Strings

As mentioned before, in order to access the information saved on the MIB you need to know the community string on versions 1 and 2/2c and the credentials on version 3.
The are 2 types of community strings: 

    public mainly read only functions 

    private Read/Write in general

Note that the writability of an OID depends on the community string used, so even if you find that "public" is being used, you could be able to write some values. Also, there may exist objects which are always "Read Only".
If you try to write an object a noSuchName or readOnly error is received.

In versions 1 and 2/2c if you to use a bad community string the server wont respond. So, if it responds, a valid community strings was used.
Ports

      The SNMP agent receives requests on UDP port 161.

      The manager receives notifications (Traps and InformRequests) on port 162.

     When used with Transport Layer Security or Datagram Transport Layer Security, requests are received on port 10161 and notifications are sent to port 10162.

Brute-Force Community String (v1 and v2c)

To guess the community string you could perform a dictionary attack. Check here different ways to perform a brute-force attack against SNMP.
Enumerating SNMP

If you know a valid community string, you can access the data using SNMPWalk or SNMP-Check:

snmpwalk -v [VERSION_SNMP] -c [COMM_STRING] [DIR_IP]
snmpwalk -v [VERSION_SNMP] -c [COMM_STRING] [DIR_IP] 1.3.6.1.2.1.4.34.1.3 #Get IPv6, needed dec2hex
snmp-check [DIR_IP] -p [PORT] -c [COMM_STRING]
nmap --script "snmp* and not snmp-brute" <target>

To see whats does means each OID gathered from the device, it is recommended to install:

apt-get install snmp-mibs-downloader
download-mibs

And in /etc/snmp/snmp.conf comment the line "mibs :"

It is recommended to install and configure this before launching any SNMP enumeration.

SNMP has a lot of information about the host and things that you may find interesting are: Network interfaces (IPv4 and IPv6 address) and processes running (may contain passwords)....
Massive SNMP

​Braa is a mass SNMP scanner. The intended usage of such a tool is, of course, making SNMP queries – but unlike snmpwalk from net-snmp, it is able to query dozens or hundreds of hosts simultaneously, and in a single process. Thus, it consumes very few system resources and does the scanning VERY fast.

Braa implements its OWN snmp stack, so it does NOT need any SNMP libraries like net-snmp.

Syntax: braa [Community-string]@[IP of SNMP server]:[iso id]

braa ignite123@192.168.1.125:.1.3.6.*

This can extract a lot MB of information that you cannot process manually.

So, lets look for the most interesting information (from https://blog.rapid7.com/2016/05/05/snmp-data-harvesting-during-penetration-testing/):
Devices

One of the first things I do is extract the sysDesc .1.3.6.1.2.1.1.1.0 MIB data from each file to determine what devices I have harvested information from. This can easily be done using the following grep command:

grep ".1.3.6.1.2.1.1.1.0" *.snmp

Identify private string

As an example, if I can identify the private community string used by an organization on their Cisco IOS routers, then I could possibly use that community string to extract the running configurations from those routers. The best method for finding such data has often been related to SNMP Trap data. So again, using the following grep we can parse through a lot of MIB data quickly searching for the key word of “trap”:

grep -i "trap" *.snmp

Usernames/passwords

Another area of interest is logs, I have discovered that there are some devices that hold logs within the MIB tables. These logs can also contain failed logon attempts. Think about the last time you logged into a device via Telnet or SSH and inadvertently entered your password as the username. I typically search for key words such as fail, failed or login and examine that data to see if there is anything of value.

grep -i "login\|fail" *.snmp

Emails

grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" *.snmp

Modifying SNMP values

You can use NetScanTools to modify values. You will need to know the private string in order to do so.
Spoofing

If there is an ACL that only allows some IPs to query the SMNP service, you can spoof one of this addresses inside the UDP packet an sniff the traffic. 
Examine SNMP Configuration files

    snmp.conf

    snmpd.conf

    snmp-config.xml
