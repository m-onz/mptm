631 - Internet Printing Protocol(IPP)
Internet Printing Protocol (IPP)

The Internet Printing Protocol (IPP) is defined in RFC2910 and RFC2911. It's an extendable protocol, for example ‘IPP Everywhere’ is a candidate for a standard in mobile and cloud printing and IPP extensions for 3D printing have been released.
Because IPP is based on HTTP, it inherits all existing security features like basic/digest authentication and SSL/TLS encryption. To submit a print job or to retrieve status information from the printer, an HTTP POST request is sent to the IPP server listening on port 631/tcp. A famous open-source IPP implementation is CUPS, which is the default printing system in many Linux distributions and OS X. Similar to LPD, IPP is a channel to deploy the actual data to be printed and can be abused as a carrier for malicious PostScript or PJL files.

If you want to learn more about
Pentesting Printers

Please, note that most of the content of all the info related to Pentesting Printers was taken from the huge and amazing research you can find on http://hacking-printers.net/. I tried to summarise that information here but you can always go to the source to learn more about the topic.
Fundamentals

A schematic relationship regarding the encapsulation of printer languages is given below:

Encapsulation of printer languages
Network printing protocols

Sending data to a printer device can be done by USB/parallel cable or over a network. This wiki focuses on network printing but most of the presented attacks can also be performed against local printers. There are various exotic protocols for network printing like Novell's NCP or AppleTalk. In the Windows world, SMB/CIFS printer shares have become quite popular. Furthermore, some devices support printing over generic protocols such as FTP or HTTP file uploads. The most common printing protocols supported directly by network printers however are LPD, IPP, and raw port 9100 printing. Network printing protocols can be attacked directly, for example by exploiting a buffer overflow in the printer's LPD daemon. In many attack scenarios however, they only act as a carrier/channel to deploy malicious Printer language code. Note that a network printer usually supports multiple protocols to ‘print’ a document which broadens the attack surface.
Learn more about raw port 9100 here.
Learn more about LPD in Pentesting 515 here.
Learn more about IPP in Petesting 631 here.
Printer Control Languages

A job control language manages settings like output trays for the current print job. While it usually sits as an optional layer in-between the printing protocol and the page description language, functions may be overlapping. Examples of vendor-specific job control languages are CPCA, XJCL, EJL and PJL – which is supported by a variety of printers and will be discussed below. In addition, printer control and management languages are designed to affect not only a single print job but the device as a whole. One approach to define a common standard for this task was NPAP. However, it has not established itself and is only supported by Lexmark. Other printer manufacturers instead use SNMP or its PJL-based metalanguage PML.
PJL

The Printer Job Language (PJL) was originally introduced by HP but soon became a de facto standard for print job control. ‘PJL resides above other printer languages’ and can be used to change settings like paper tray or size. It must however be pointed out that PJL is not limited to the current print job as some settings can be made permanent. PJL can also be used to change the printer's display or read/write files on the device. There are many dialects as vendors tend to support only a subset of the commands listed in the PJL reference and instead prefer to add proprietary ones. PJL is further used to set the file format of the actual print data to follow. Without such explicit language switching, the printer has to identify the page description language based on magic numbers. Typical PJL commands to set the paper size and the number of copies before switching the interpreter to PostScript mode are shown below:

@PJL SET PAPER=A4
@PJL SET COPIES=10
@PJL ENTER LANGUAGE=POSTSCRIPT

Inside the page about port 9100 'raw port' you can find more information about how to enumerate PJL.
PML

The Printer Management Language (PML) is a proprietary language to control HP printers. It basically combines the features of SNMP with PJL. Publicly available documentation has not been released, however parts of the standard were leaked by the LPRng project: the PJL Passthrough to PML and SNMP User’s Guide defines defines PML as ‘an object-oriented request-reply printer management protocol’ and gives an introduction to the basics of the syntax. PML is embedded within PJL and can be used to read and set SNMP values on a printer device. This is especially interesting if a firewall blocks access to SNMP services (161/udp). The use of PML within a print job retrieving the hrDeviceDescr value (OID 1.3.6.1.2.1.25.3.2.1.3, textual description of a device) is demonstrated below:

> @PJL DMINFO ASCIIHEX="000006030302010301"
< "8000000603030201030114106870204c617365724a65742034323530

The rear part of string responded by the printer, 6870204c617365724a65742034323530 is hexadecimal for hp LaserJet 4250. As can be seen, it is possible to invoke (a subset of) SNMP commands over PJL via PML. A security-sensitive use of PML is to reset HP printers to factory defaults via ordinary print jobs, therefore removing protection mechanisms like user-set passwords.
UEL

The Universal Exit Language (UEL) actually is not a real job control ‘language’ but a single command used to terminate the current data stream: the escape character (\x1b), followed by %-12345X. It was originally introduced with HP's PCL and is supported by most modern laser printers. A good practice of ‘printer drivers’ is to invoke the UEL at the beginning and at the end of each print job, so interpretation of the printer language is stopped/restarted and each job has its own, separate environment as shown below:

\x1b%-12345X
@PJL SET PAPER=A4
@PJL ENTER LANGUAGE=PCL
...
[PCL datastream]
...
\x1b%-12345X

Otherwise, for example PJL settings like paper media size or PostScript definitions set in one print job would influence the next job. UEL can be handy to string together multiple jobs into a single file/datastream sent to the printer. This can be used to fool hardware page counters or to switch the printing language in advances cross-site printing attacks.
Page Description Languages

A page description language (PDL) specifies the appearance of the actual document. It must however be pointed out that some PDLs offer limited job control, so a clear demarcation between page description and printer/job control language is not always possible. The function of a ‘printer driver’ is to translate the file to be printed into a PDL that is understood by the printer model. Note that some low cost inkjet printers do not support any high level page description language at all. So called host-based or GDI printers only accept simple bitmap datastreams like ZJS while the actual rendering is done by the printer driver. There are various proprietary page description languages like Kyocera's PRESCRIBE, SPL, XES, CaPSL, RPCS, ESC/P which is mostly used in dot matrix printers or HP-GL and HP-GL/2 which have been designed for plotters. Support for direct PDF and XPS printing is also common on newer printers. The most common ‘standard’ page description languages however are PostScript and PCL.
PostScript (PS)

The term ‘page description’ may be misleading though, as PostScript is capable of much more than just creating vector graphics. PostScript is a stack-based, Turing-complete programming language consisting of almost 400 operators for arithmetics, stack and graphic manipulation and various data types such as arrays or dictionaries and was created by Adobe.
Technically spoken, access to a PostScript interpreter can already be classified as code execution because any algorithmic function can theoretically be implemented in PostScript. Certainly, without access to the network stack or additional operating system libraries, possibilities are limited to arbitrary mathematical calculations like mining bitcoins. However, PostScript is capable of basic file system I/O to store frequently used code, graphics or font files.
Originally designed as a feature, the dangers of such functionality were limited before printers got interconnected and risks were mainly discussed in the context of host-based PostScript interpreters. In this regard, Encapsulated PostScript (EPS) is also noteworthy as it can be included in other file formats to be interpreted on the host such as LaTeX documents. Like PJL and PCL, PostScript supports bidirectional communication been host and printer.
Example PostScript code to echo Hello world to stdout is given below:

%!
(Hello world) print

Brother and Kyocera use their own PostScript clones: Br-Script and KPDL. Such flavours of the PostScript language are not 100% compatible, especially concerning security features like exiting the server loop. PostScript can be used for a variety of attacks such as denial of service (for example, through infinite loops), print job manipulation and retention as well as gaining access to the printer's file system.
Exiting the server loop

Normally, each print job is encapsulated in its own, separate environment. One interesting feature of PostScript is that a program can circumvent print job encapsulation and alter the initial VM for subsequent jobs. To do so, it can use either startjob, a Level 2 feature:

true 0 startjob

or exitserver (available in all implementations that include a job server):

serverdict begin 0 exitserver

This capability is controlled by the StartJobPassword which defaults to 0 (compare credential disclosure). Since the job server loop is generally responsible for cleaning up the state of the interpreter between jobs, any changes that are made outside the server loop will remain as part of the permanent state of the interpreter for all subsequent jobs. In other words, a print job can access and alter further jobs. Bingo!
Operator redefinition

When a PostScript document calls an operator, the first version found on the dictionary stack is used. Operators usually reside in the systemdict dictionary, however by placing a new version into the userdict dictionary, operators can be practically overwritten because the user-defined version is the first one found on the dictionary stack. Using the startjob/exitserver operators, such changes can be made permanent – at least until the printer is restarted. A scheme of the PostScript dictionary stack is given below:


​The PostScript dictionary stack​​


The potential impact of redefining operators is only limited by creativity. When further legitimate documents are printed and call a redefined operator, the attackers version will be executed. This can lead to a various attacks such as denial of service, print job retention and manipulation. Note however that this is not necessarily a security bug, but a 32 years old language feature, available in almost any PostScript printer and RIP.
PCL

PCL 3 and PCL 4 added support for fonts and macros which both can be permanently downloaded to the device – however only referenced to by a numeric id, not by a file name, as direct access to the file system is not intended. PCL 1 to 5 consist of escape sequences followed by one or more ASCII characters representing a command to be interpreted. PCL 6 Enhanced or ‘PCL XL’ uses a binary encoded, object-oriented protocol. An example PCL document to print ‘Hello world’ is given below:

<Esc>Hello world

Due to its limited capabilities, PCL is hard to exploit from a security perspective unless one discovers interesting proprietary commands in some printer manufacturers's PCL flavour. The PRET tool implements a virtual, PCL-based file system which uses macros to save file content and metadata in the printer's memory. This hack shows that even a device which supports only minimalist page description languages like PCL can be used to store arbitrary files like copyright infringing material. Although turning a printer into a file sharing service is not a security vulnerability per se, it may apply as ‘misuse of service’ depending on the corporate policy.
Misc Attacks
USB drive or cable

Data can be sent to and received from a local printer by USB or parallel cables. Both channels are supported by PRET to communicate with the device. In addition, printers and MFPs often ship with Type-A USB ports which allows users to print directly from an USB device.
While plugged-in USB drives do not offer a bidirectional channel, their usage in a crowded copy room may seem less conspicuous. Obviously, exploiting USB printers requires the attacker to gain physical access to the device. However, it is not completely unrealistic for most institutions and companies. Gaining physical access to printer can generally be considered as less hard than it is for other network components like servers or workstations.
Cross-site printing

Abusing client web request an attacker can abuse arbitrary printers inside the internal network of the client connected to his malicious web page.
Learn how can this be possible here.​
Abusing Spooler service in AD

If you can find any Spool service listening inside the domain, you may be able to abuse is to obtain new credentials and escalate privileges.
More information about how to find a abuse Spooler services here.​
Privilege Escalation
Factory Defaults

There are several possible ways to reset a device to factory defaults, and this is a security-critical functionality as it overwrites protection mechanisms like user-set passwords.
Learn more here.​
Accounting Bypass

You may be able to impersonate existent or non-existent users to print pages using their accounts or manipulate the hardware or software counter to be able to print more pages.
Learn how to do it here.​
Scanner and Fax

Accessing the Scanner of Fax functionalities you may be able to access other functionalities, but this all of this is vendor-dependent.
Learn more here.​
Print job access
Print Job Retention

Jobs can be retained in memory and be printed again in a later moment from the control panel, or using PostScript you can even remotely access all the jobs that are going to be printed, download them and print them.
Learn more here.​
Print Job Manipulation

You can add new content to the pages that are printed, change all the content that is going to be printed or even replace just certain letters or words.
Learn how to do it here.​
Information Disclosure
Memory access

You may be able to dump the NVRAM memory and extract sensitive info (like passwords) from there.
Read how to do that here.​
File system access

You may be able to access the file system abusing PJL or PostScript.
Read how to do that here.​
Credentials Disclosure/Brute-Force

You may be able to disclosure the password being using abusing SNMP or the LDAP settings or you could try to brute-force PJL or PostScript.
Read how to do that here.
Code Execution
Buffer Overflows

Several buffer overflows have been found already in PJL input and in the LPD daemon, and there could be more.
Read this for more information.​
Firmware updates

You may be able to make the printer update the driver to a malicious one specially crafted by you.
Read this for more information.​
Software Packages

 printer vendors have started to introduce the possibility to install custom software on their devices but information is not publicly available. The feature of writing customized software which runs on printers was intended and is reserved for resellers and contractors.
Read more about this here.​
Denial of service
Transmission channel

Occupying all the connections and increasing the timeout of the server could lead to a DoS.
Learn more about this here.​
Document Processing

You can use PostScript and PJL to perform infinite loops, redefine commands to avoid any printing, turn off any printing functionality or even set the printer in offline mode.
Learn more about this here.​
Physical damage
One could abuse PJL or PostScript to write in the NVRAM hundreds of thousands of times with the goal of breaking the chip or at least make the parameters be frozen intro the factory default ones.
Learn more about this here.
