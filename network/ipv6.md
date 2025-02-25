Pentesting IPv6
IPv6 Basic theory
Networks

In an IPv6 address, the first 48 bits are the network prefix. The next 16 bits are the subnet ID and are used for defining subnets. The last 64 bits are the interface identifier (which is also known as the Interface ID or the Device ID, is for devices). If necessary, the bits that are normally reserved for the Device ID can be used for additional subnet masking.

There is not ARP in IPv6. Instead, there is ICMPv6 NS (Neighbor Solicitation) and NA (Neighbor Advertisement). The NS is used to resolve and address, so it sends multicast packets. The NA is unicast as is used to answer the NS. A NA packet could also be sent without needing a NS packet.

0:0:0:0:0:0:0:1 = 1  – This is 127.0.0.1 equivalent in IPv4.

Link-local Addresses: These are private address that is not meant to be routed on the internet. They can be used locally by private or temporary LANs for sharing and distribution of file among devices on the LAN. Other devices in your local LAN using this kind of addresses can be found sending a pig to the multicast address ff02::01
FE80::/10  – Link-local unicast address range.

ping6 –I eth0 -c 5 ff02::1 > /dev/null 2>&1
ip neigh | grep ^fe80
​
#Or you could also use
alive6 eth0

If you know the MAC address of a host in the same net as you (you could just ping its ipv4 address and view the arp table to found its MAC address), you can calculate his Link-local address to communicate with him.
Suppose the MAC address is 12:34:56:78:9a:bc

    To IPv6 notation: 1234:5678:9abc

    Append fe80:: at the begging and Insert fffe in the middle: fe80::1234:56ff:fe78:9abc

    Invert seventh bit from the left, from 0001 0010 to 0001 0000: fe80::1034:5678:9abc

    fe80::1034:5678:9abc

Unique local  address:  This type of ipv6 address also  not intended to be routed on the public internet. Unique local is a replacement of site-local address, that allows communication within a site while being routable to a multiple local networks.
FEC00::/7  – The unique local address range.

Multicast Address: This can also be refered to as One-to-Many. Packets addressed to multicast address are delivered to all interface identified by the multicast address. Multicast address types are easily notable because they normally  begins with FF.
FF00::/8  – The multicast range.

Anycast:  This form of ipv6 address is similar to the multicast address with a slight difference. Anycast address can also be refered to as One to Nearest. It can be used to address packets meant for multiple interfaces; but usually it sends packets to the first interface it finds as defined in the routing distance. This means it send packets to the closest interface as determined by routing protocols.
20000::/3  – The global unicast address range.

fe80::/10--> Unique Link-Local (169.254.x.x) [fe80:0000:0000:0000:0000:0000:0000:0000,febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]
fc00::/7 --> Unique Local-Unicast (10.x.x.x, 172.16.x.x, 192.168.x.x) []
2000::/3 --> Global Unicast
ff02::1 --> Multicast All Nodes
ff02::2 --> Multicast Router Nodes
Guess the IPv6 of a machine

Way 1

The IPv6 of fe80::/10 are based on the MAC. If you have the IPv6 of a device inside a network and you want to guess the IPv6 of another device of the network, you can get its MAC address using a ping (inside the arp table).

Way2

You can send a ping6 to the multicast and get the IPv6 address inside the arp table.

service ufw stop #Stop firewall
ping6 -I <IFACE> ff02::1 #You could also make: ping6 -I <IPV6> ff02::1 if you want to make a ping to a specific IP Address
ip -6 neigh
alive6
use auxiliary/scanner/discovery/ipv6_neighbor_router_advertisement; set INTERFACE eth1; run

IPv6 MitM

Man in the middle with spoofed ICMPv6 neighbor advertisement.

    Man in the middle with spoofed ICMPv6 router advertisement.

    Man in the middle using ICMPv6 redirect or ICMPv6 too big to implant route.

    Man in the middle to attack mobile IPv6 but requires ipsec to be disabled.

    Man in the middle with rogue DHCPv6 server

​
Discovering IPv6 addresses in the wild
Sudomains

You can use google and other browsers to search for subdomains like "ipv6.*"

site:ipv6./

DNS

You could also try to search "AXFR"(zone transfer), "AAAA"(IPv6) or even "ANY" (all) registry in DNS to find IPv6 addresses.
Ping6

Once some IPv6 devices of an organisation have been found, you could try to use ping6 to check nearby addresses.
References

    ​http://www.firewall.cx/networking-topics/protocols/877-ipv6-subnetting-how-to-subnet-ipv6.html​

    ​https://www.sans.org/reading-room/whitepapers/detection/complete-guide-ipv6-attack-defense-33904
