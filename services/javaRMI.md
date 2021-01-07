1098/1099 - Pentesting Java RMI
Basic Information

The Java Remote Method Invocation, or Java RMI, is a mechanism that allows an object that exists in one Java virtual machine to access and call methods that are contained in another Java virtual machine; This is basically the same thing as a remote procedure call, but in an object-oriented paradigm instead of a procedural one, which allows for communication between Java programs that are not in the same address space.

One of the major advantages of RMI is the ability for remote objects to load new classes that aren't explicitly defined already, extending the behavior and functionality of an application.
From here.

Default port: 1099, 1098

PORT     STATE SERVICE     REASON
1099/tcp open  rmiregistry syn-ack

Enumeration

The default configuration of rmiregistryallows loading classes from remote URLs, which can lead to remote code execution.

Basically this service could allow you to execute code.

msf> use auxiliary/scanner/misc/java_rmi_server
msf> use auxiliary/gather/java_rmi_registry
nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p <PORT> <IP>

RMI methods enumeration

​https://github.com/BishopFox/rmiscout to explore and try to find RCE vulnerabilities.
https://github.com/NickstaDB/BaRMIe to enumerate and attack
Reverse Shell
MSF

msf> use exploit/multi/browser/java_rmi_connection_impl

Shodan

    port:1099 java
