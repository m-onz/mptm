502 - Pentesting Modbus
Basic Information

Modbus Protocol is a messaging structure developed by Modicon in 1979. It is used to establish master-slave/client-server communication between intelligent devices.

Default port: 502

PORT    STATE SERVICE
502/tcp open  modbus

Enumeration

nmap --script modbus-discover -p 502 <IP>
msf> use auxiliary/scanner/scada/modbusdetect
msf> use auxiliary/scanner/scada/modbus_findunitid
