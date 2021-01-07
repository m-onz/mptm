135, 593 - Pentesting MSRPC
Basic Information

Microsoft Remote Procedure Call, also known as a function call or a subroutine call, is a protocol that uses the client-server model in order to allow one program to request service from a program on another computer without having to understand the details of that computer's network. MSRPC was originally derived from open source software but has been developed further and copyrighted by Microsoft.

Depending on the host configuration, the RPC endpoint mapper can be accessed through TCP and UDP port 135, via SMB with a null or authenticated session (TCP 139 and 445), and as a web service listening on TCP port 593.

135/tcp   open     msrpc         Microsoft Windows RPC

How does MSRPC work?

​The MSRPC process begins on the client side, with the client application calling a local stub procedure instead of code implementing the procedure. The client stub code retrieves the required parameters from the client address space and delivers them to the client runtime library, which then translates the parameters into a standard Network Data Representation format to transmit to the server.

The client stub then calls functions in the RPC client runtime library to send the request and parameters to the server. If the server is located remotely, the runtime library specifies an appropriate transport protocol and engine and passes the RPC to the network stack for transport to the server.
From here: https://www.extrahop.com/resources/protocols/msrpc/​

Image From book "Network Security Assesment 3rd Edition"
Identifying Exposed RPC Services

Section extracted from book "Network Security Assesment 3rd Edition"

You can query the RPC locator service and individual RPC endpoints to catalog interesting services running over TCP, UDP, HTTP, and SMB (via named pipes). Each IFID value gathered through this process denotes an RPC service (e.g., 5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc is the Messenger interface).

Todd Sabin’s rpcdump and ifids Windows utilities query both the RPC locator and specific RPC endpoints to list IFID values. The rpcdump syntax is as follows:

D:\rpctools> rpcdump [-p port] 192.168.189.1
IfId: 5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc version 1.0
Annotation: Messenger Service
UUID: 00000000-0000-0000-0000-000000000000
Binding: ncadg_ip_udp:192.168.189.1[1028]

You can access the RPC locator service by using four protocol sequences:

    ncacn_ip_tcp and ncadg_ip_udp (TCP and UDP port 135)

    ncacn_np (the \pipe\epmapper named pipe via SMB)

    ncacn_http (RPC over HTTP via TCP port 80, 593, and others)

use auxiliary/scanner/dcerpc/endpoint_mapper
use auxiliary/scanner/dcerpc/hidden
use auxiliary/scanner/dcerpc/management
use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor
rpcdump.py <IP> -p 135

Note that from the mentioned options all except of tcp_dcerpc_auditor can only be executed against msrpc in port 135.
Notable RPC interfaces

IFID value
	

Named pipe
	

Description

12345778-1234-abcd-ef00-0123456789ab
	

\pipe\lsarpc
	

LSA interface, used to enumerate users

3919286a-b10c-11d0-9ba8-00c04fd92ef5
	

\pipe\lsarpc
	

LSA Directory Services (DS) interface, used to enumerate domains and trust relationships

12345778-1234-abcd-ef00-0123456789ac
	

\pipe\samr
	

LSA SAMR interface, used to access public SAM database elements (e.g., usernames) and brute-force user passwords regardless of account lockout policya​

1ff70682-0a51-30e8-076d-740be8cee98b
	

\pipe\atsvc
	

Task scheduler, used to remotely execute commands

338cd001-2244-31f1-aaaa-900038001003
	

\pipe\winreg
	

Remote registry service, used to access the system registry

367abb81-9844-35f1-ad32-98f038001003
	

\pipe\svcctl
	

Service control manager and server services, used to remotely start and stop services and execute commands

4b324fc8-1670-01d3-1278-5a47bf6ee188
	

\pipe\srvsvc
	

Service control manager and server services, used to remotely start and stop services and execute commands

4d9f4ab8-7d1c-11cf-861e-0020af6e7c57
	

\pipe\epmapper
	

DCOM interface, supporting WMI
Identifying IP addresses

Using https://github.com/mubix/IOXIDResolver is possible to abuse the ServerAlive2 method inside the IOXIDResolver interface.
References:

    ​https://airbus-cyber-security.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/​

    ​https://airbus-cyber-security.com/the-oxid-resolver-part-2-accessing-a-remote-object-inside-dcom/​

Port 593

The rpcdump.exe from rpctools can interact with this port.
