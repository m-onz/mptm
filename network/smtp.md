25,465,587 - Pentesting SMTP/s
Basic Information

SMTP (Simple Mail Transfer Protocol) is a TCP/IP protocol used in sending and receiving e-mail. However, since it is limited in its ability to queue messages at the receiving end, it is usually used with one of two other protocols, POP3 or IMAP, that let the user save messages in a server mailbox and download them periodically from the server.

In other words, users typically use a program that uses SMTP for sending e-mail and either POP3 or IMAP for receiving e-mail. On Unix-based systems, sendmail is the most widely-used SMTP server for e-mail. A commercial package, Sendmail, includes a POP3 server. Microsoft Exchange includes an SMTP server and can also be set up to include POP3 support.
From here.

Default port: 25,465(ssl),587(ssl)

PORT   STATE SERVICE REASON  VERSION
25/tcp open  smtp    syn-ack Microsoft ESMTP 6.0.3790.3959

EMAIL Headers

If you have the opportunity to make the victim send you a email (via contact form of the web page for example), do it because you could learn about the internal topology of the victim seeing the headers of the mail.

You can also get an email from a SMTP server trying to send to that server an email to a non-existent address (because the server will send to the attacker a NDN mail). But, be sure that you send the email from an allowed address (check the SPF policy) and that you can receive NDN messages.

You should also try to send different contents because you can find more interesting information on the headers like: X-Virus-Scanned: by av.domain.com 
You should send the EICAR test file.
Detecting the AV may allow you to exploit known vulnerabilities.
Basic actions
Banner Grabbing/Basic connection

SMTP:

nc -vn <IP> 25

SMTPS:

openssl s_client -crlf -connect smtp.mailgun.org:465 #SSL/TLS without starttls command
openssl s_client -starttls smtp -crlf -connect smtp.mailgun.org:587

Finding MX servers of an organisation

dig +short mx google.com

Enumeration

nmap -p25 --script smtp-commands 10.10.10.10

NTLM Auth - Information disclosure

If the server supports NTLM auth (Windows) you can obtain sensitive info (versions). More info here.

root@kali: telnet example.com 587 
220 example.com SMTP Server Banner 
>> HELO 
250 example.com Hello [x.x.x.x] 
>> AUTH NTLM 334 
NTLM supported 
>> TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA= 
334 TlRMTVNTUAACAAAACgAKADgAAAAFgooCBqqVKFrKPCMAAAAAAAAAAEgASABCAAAABgOAJQAAAA9JAEkAUwAwADEAAgAKAEkASQBTADAAMQABAAoASQBJAFMAMAAxAAQACgBJAEkAUwAwADEAAwAKAEkASQBTADAAMQAHAAgAHwMI0VPy1QEAAAAA

Or automate this with nmap plugin smtp-ntlm-info.nse
Sniffing

Check if you sniff some password from the packets to port 25
​Auth bruteforce​
Username Bruteforce Enumeration

Authentication is not always needed
RCPT TO

$ telnet 10.0.10.1 25
Trying 10.0.10.1...
Connected to 10.0.10.1.
Escape character is '^]'.
220 myhost ESMTP Sendmail 8.9.3
HELO x
250 myhost Hello [10.0.0.99], pleased to meet you
MAIL FROM:test@test.org
250 2.1.0 test@test.org... Sender ok
RCPT TO:test
550 5.1.1 test... User unknown
RCPT TO:admin
550 5.1.1 admin... User unknown
RCPT TO:ed
250 2.1.5 ed... Recipient ok

VRFY

$ telnet 10.0.0.1 25
Trying 10.0.0.1...
Connected to 10.0.0.1.
Escape character is '^]'.
220 myhost ESMTP Sendmail 8.9.3
HELO
501 HELO requires domain address
HELO x
250 myhost Hello [10.0.0.99], pleased to meet you
VRFY root
250 Super-User <root@myhost>
VRFY blah
550 blah... User unknown

EXPN

$ telnet 10.0.10.1 25
Trying 10.0.10.1...
Connected to 10.0.10.1.
Escape character is '^]'.
220 myhost ESMTP Sendmail 8.9.3
HELO
501 HELO requires domain address
HELO x
EXPN test
550 5.1.1 test... User unknown
EXPN root
250 2.1.5 <ed.williams@myhost>
EXPN sshd
250 2.1.5 sshd privsep <sshd@mail2>

Extracted from: https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2015/june/username-enumeration-techniques-and-their-value/​
Automatic tools

Metasploit: auxiliary/scanner/smtp/smtp_enum
smtp-user-enum
nmap –script smtp-enum-users.nse <IP>

DSN Reports

Delivery Status Notification Reports: If you send an email to an organisation to an invalid address, the organisation will notify that the address was invalided sending a mail back to you. Headers of the returned email will contain possible sensitive information (like IP address of the mail services that interacted with the reports or anti-virus software info).
​Commands​
Send Email from linux console

root@kali:~# sendEmail -t itdept@victim.com -f techsupport@bestcomputers.com -s 192.168.8.131 -u Important Upgrade Instructions -a /tmp/BestComputers-UpgradeInstructions.pdf
Reading message body from STDIN because the '-m' option was not used.
If you are manually typing in a message:
  - First line must be received within 60 seconds.
  - End manual input with a CTRL-D on its own line.
​
IT Dept,
​
We are sending this important file to all our customers. It contains very important instructions for upgrading and securing your software. Please read and let us know if you have any problems.
​
Sincerely,

From: https://www.offensive-security.com/metasploit-unleashed/client-side-exploits/​
Mail Spoofing

Most of this section was extracted from the book Network Security Assessment 3rd Edition.

SMTP messages are easily spoofed, and so organizations use SPF, DKIM, and DMARC features to prevent parties from sending unauthorised email.

A complete guide of these countermeasures can be found in https://seanthegeek.net/459/demystifying-dmarc/​
SPF

Sender Policy Framework (SPF) provides a mechanism that allows MTAs to check if a host sending an email is authorized.
Then, the organisations can define a list of authorised mail servers and the MTAs can query for this lists to check if the email was spoofed or not.
In order to define IP addresses/ranges, domains and others that are allowed to send email on behalf a domain name, different "Mechanism" cam appear in the SPF registry.
Mechanisms

Mechanism
	

Description

ALL
	

Matches always; used for a default result like -all for all IPs not matched by prior mechanisms.

A
	

If the domain name has an address record (A or AAAA) that can be resolved to the sender's address, it will match.

IP4
	

If the sender is in a given IPv4 address range, match.

IP6
	

If the sender is in a given IPv6 address range, match.

MX
	

If the domain name has an MX record resolving to the sender's address, it will match (i.e. the mail comes from one of the domain's incoming mail servers).

PTR
	

If the domain name (PTR record) for the client's address is in the given domain and that domain name resolves to the client's address (forward-confirmed reverse DNS), match. This mechanism is discouraged and should be avoided, if possible.

EXISTS
	

If the given domain name resolves to any address, match (no matter the address it resolves to). This is rarely used. Along with the SPF macro language it offers more complex matches like DNSBL-queries.

INCLUDE
	

References the policy of another domain. If that domain's policy passes, this mechanism passes. However, if the included policy fails, processing continues. To fully delegate to another domain's policy, the redirect extension must be used.

REDIRECT
	

A redirect is a pointer to another domain name that hosts an SPF policy, it allows for multiple domains to share the same SPF policy. It is useful when working with a large amount of domains that share the same email infrastructure.

It SPF policy of the domain indicated in the redirect Mechanism will be used.

It's also possible to identify Qualifiers that indicates what should be done if a mechanism is matched. By default, the qualifier "+" is used (so if any mechanism is matched, that means it's allowed).
You usually will note at the end of each SPF policy something like: ~all or -all. This is used to indicate that if the sender doesn't match any SPF policy, you should tag the email as untrusted (~) or reject (-) the email.
Qualifiers

Each mechanism can be combined with one of four qualifiers:

    + for a PASS result. This can be omitted; e.g., +mx is the same as mx.

    ? for a NEUTRAL result interpreted like NONE (no policy).

    ~ (tilde) for SOFTFAIL, a debugging aid between NEUTRAL and FAIL. Typically, messages that return a SOFTFAIL are accepted but tagged.

    - (minus) for FAIL, the mail should be rejected (see below).

In the following example you can read the SPF policy of google.com. Note how the first SPF policy includes SPF policies of other domains:

kali@kali:~$ dig txt google.com | grep spf
google.com.             235     IN      TXT     "v=spf1 include:_spf.google.com ~all"
​
kali@kali:~$ dig txt _spf.google.com | grep spf
; <<>> DiG 9.11.3-1ubuntu1.7-Ubuntu <<>> txt _spf.google.com
;_spf.google.com.               IN      TXT
_spf.google.com.        235     IN      TXT     "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all"
​
kali@kali:~$ dig txt _netblocks.google.com | grep spf
_netblocks.google.com.  1606    IN      TXT     "v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ip4:66.102.0.0/20 ip4:66.249.80.0/20 ip4:72.14.192.0/18 ip4:74.125.0.0/16 ip4:108.177.8.0/21 ip4:173.194.0.0/16 ip4:209.85.128.0/17 ip4:216.58.192.0/19 ip4:216.239.32.0/19 ~all"
​
kali@kali:~$ dig txt _netblocks2.google.com | grep spf
_netblocks2.google.com. 1908    IN      TXT     "v=spf1 ip6:2001:4860:4000::/36 ip6:2404:6800:4000::/36 ip6:2607:f8b0:4000::/36 ip6:2800:3f0:4000::/36 ip6:2a00:1450:4000::/36 ip6:2c0f:fb50:4000::/36 ~all"
​
kali@kali:~$ dig txt _netblocks3.google.com | grep spf
_netblocks3.google.com. 1903    IN      TXT     "v=spf1 ip4:172.217.0.0/19 ip4:172.217.32.0/20 ip4:172.217.128.0/19 ip4:172.217.160.0/20 ip4:172.217.192.0/19 ip4:172.253.56.0/21 ip4:172.253.112.0/20 ip4:108.177.96.0/19 ip4:35.191.0.0/16 ip4:130.211.0.0/22 ~all"

Traditionally it was possible to spoof any domain name that didn't have a correct/any SPF record. Nowadays, if email comes from a domain without a valid SPF record is probably going to be rejected/marked as untrusted automatically.

To check the SPF of a domain you can use online tools like: https://www.kitterman.com/spf/validate.html​
DKIM

DomainKeys Identified Mail (DKIM) is a mechanism by which outbound email is signed and validated by foreign MTAs upon retrieving a domain’s public key via DNS. The DKIM public key is held within a TXT record for a domain; however, you must know both the selector and domain name to retrieve it.

Then, to ask for the key you need the domain name and the selector of the mail from the mail header DKIM-Signature for example: d=gmail.com;s=20120113

dig 20120113._domainkey.gmail.com TXT | grep p=
20120113._domainkey.gmail.com. 280 IN   TXT    "k=rsa\; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCg
KCAQEA1Kd87/UeJjenpabgbFwh+eBCsSTrqmwIYYvywlbhbqoo2DymndFkbjOVIPIldNs/m40KF+yzMn1skyoxcTUGCQs8g3

DMARC

Domain-based Message Authentication, Reporting & Conformance (DMARC) is a method of mail authentication that expands upon SPF and DKIM. Policies instruct mail servers how to process email for a given domain and report upon actions performed.

To obtain the DMARC record, you need to query the subdomain _dmarc

root@kali:~# dig _dmarc.yahoo.com txt | grep DMARC
_dmarc.yahoo.com.  1785 IN TXT "v=DMARC1\; p=reject\; sp=none\; pct=100\; 
rua=mailto:dmarc-yahoo-rua@yahoo-inc.com, mailto:dmarc_y_rua@yahoo.com\;"
​
root@kali:~# dig _dmarc.google.com txt | grep DMARC
_dmarc.google.com. 600 IN TXT "v=DMARC1\; p=quarantine\; rua=mailto:mailauth-reports@google.com"
​
root@kali:~# dig _dmarc.paypal.com txt | grep DMARC
_dmarc.paypal.com. 300 IN TXT "v=DMARC1\; p=reject\; rua=mailto:d@rua.agari.com\; 
ruf=mailto:dk@bounce.paypal.com,mailto:d@ruf.agari.com"

PayPal and Yahoo instruct mail servers to reject messages that contain invalid DKIM signatures or do not originate from their networks. Notifications are then sent to the respective email addresses within each organization. Google is configured in a similar way, although it instructs mail servers to quarantine messages and not outright reject them.
DMARC tags

Tag Name
	

Purpose
	

Sample

v
	

Protocol version
	

v=DMARC1

pct
	

Percentage of messages subjected to filtering
	

pct=20

ruf
	

Reporting URI for forensic reports
	

ruf=mailto:authfail@example.com

rua
	

Reporting URI of aggregate reports
	

rua=mailto:aggrep@example.com

p
	

Policy for organizational domain
	

p=quarantine

sp
	

Policy for subdomains of the OD
	

sp=reject

adkim
	

Alignment mode for DKIM
	

adkim=s

aspf
	

Alignment mode for SPF
	

aspf=r
What about Subdomains?

From here.
You need to have separate SPF records for each subdomain you wish to send mail from.
The following was originally posted on openspf.org, which used to be a great resource for this kind of thing.

    The Demon Question: What about subdomains?

    If I get mail from pielovers.demon.co.uk, and there's no SPF data for pielovers, should I go back one level and test SPF for demon.co.uk? No. Each subdomain at Demon is a different customer, and each customer might have their own policy. It wouldn't make sense for Demon's policy to apply to all its customers by default; if Demon wants to do that, it can set up SPF records for each subdomain.

    So the advice to SPF publishers is this: you should add an SPF record for each subdomain or hostname that has an A or MX record.

    Sites with wildcard A or MX records should also have a wildcard SPF record, of the form: * IN TXT "v=spf1 -all"

This makes sense - a subdomain may very well be in a different geographical location and have a very different SPF definition.
Tools

    ​https://github.com/carlospolop-forks/mailspoof Check for SPF and DMARC misconfigurations

    ​https://pypi.org/project/checkdmarc/ Automatically get SPF and DMARC configs

You can attack some characteristics of mail clients to make the user think that the mail is coming from any address, more info: https://www.mailsploit.com/index​
More info

Find more information about these protections in https://seanthegeek.net/459/demystifying-dmarc/​
Other phishing indicators

    Domain’s age

    Links pointing to IP addresses

    Link manipulation techniques

    Suspicious (uncommon) attachments

    Broken email content

    Values used that are different to those of the mail headers

    Existence of a valid and trusted SSL certificate

    Submission of the page to web content filtering sites

Exfiltration through SMTP

If you can send data via SMTP read this.
Config file

sendmail.cf
submit.cf

SMTP - Commands

Extracted from: https://serversmtp.com/smtp-commands/​

HELO
It’s the first SMTP command: is starts the conversation identifying the sender server and is generally followed by its domain name.

EHLO
An alternative command to start the conversation, underlying that the server is using the Extended SMTP protocol.

MAIL FROM
With this SMTP command the operations begin: the sender states the source email address in the “From” field and actually starts the email transfer.

RCPT TO
It identifies the recipient of the email; if there are more than one, the command is simply repeated address by address.

SIZE
This SMTP command informs the remote server about the estimated size (in terms of bytes) of the attached email. It can also be used to report the maximum size of a message to be accepted by the server.

DATA
With the DATA command the email content begins to be transferred; it’s generally followed by a 354 reply code given by the server, giving the permission to start the actual transmission.

VRFY
The server is asked to verify whether a particular email address or username actually exists.

TURN
This command is used to invert roles between the client and the server, without the need to run a new connaction.

AUTH
With the AUTH command, the client authenticates itself to the server, giving its username and password. It’s another layer of security to guarantee a proper transmission.

RSET
It communicates the server that the ongoing email transmission is going to be terminated, though the SMTP conversation won’t be closed (like in the case of QUIT).

EXPN
This SMTP command asks for a confirmation about the identification of a mailing list.

HELP
It’s a client’s request for some information that can be useful for the a successful transfer of the email.

QUIT
It terminates the SMTP conversation.
