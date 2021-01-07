# phishin

Phishing Methodology
Methodology

    Recon the victim

        Select the victim domain.

        Perform some basic web enumeration searching for login portals used by the victim and decide which one you will impersonate.

        Use some OSINT to find emails.

    Prepare the environment

        Buy the domain you are going to use for the phishing assessment

        Configure the email service related records (SPF, DMARC, DKIM, rDNS)

        Configure the VPS with gophish

    Prepare the campaign

        Prepare the email template

        Prepare the web page to steal the credentials

    Launch the campaign!

Generate similar domain names or buy a trusted domain
Domain Name Variation Techniques

    Keyword: The domain name contains an important keyword of the original domain (e.g., zelster.com-management.com).

    hypened subdomain: Change the dot for a hyphen of a subdomain (e.g., www-zelster.com).

    New TLD: Same domain using a new TLD (e.g., zelster.org)

    Homoglyph: It replaces a letter in the domain name with letters that look similar (e.g., zelfser.com).

    Transposition: It swaps two letters within the domain name (e.g., zelster.com).

    Singularization/Pluralization: Adds or removes “s” at the end of the domain name (e.g., zeltsers.com).

    Omission: It removes one of the letters from the domain name (e.g., zelser.com).

    Repetition: It repeats one of the letters in the domain name (e.g., zeltsser.com).

    Replacement: Like homoglyph but less stealthy. It replaces one of the letters in the domain name, perhaps with a letter in proximity of the original letter on the keyboard (e.g, zektser.com).

    Subdomained: Introduce a dot inside the domain name (e.g., ze.lster.com).

    Insertion: It inserts a letter into the domain name (e.g., zerltser.com).

    Bitsquatting: It anticipates a small portion of systems encountering hardware errors, resulting in the mutation of the resolved domain name by 1 bit. (e.g., xeltser.com).

    Missing dot: Append the TLD to the domain name. (e.g., zelstercom.com)

Automatic Tools

    ​dnstwist​

    ​urlcrazy​

Websites

    ​https://dnstwist.it/​

    ​https://dnstwister.report/​

    ​https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/​

Buy a trusted domain

You can search in https://www.expireddomains.net/ for a expired domain that you could use.
In order to make sure that the expired domain that you are going to buy has already a good SEO you could search how is it categorized in:

    ​http://www.fortiguard.com/webfilter​

    ​https://urlfiltering.paloaltonetworks.com/query/​

Discovering Emails

    ​https://github.com/laramies/theHarvester (100% free)

    ​https://phonebook.cz/ (100% free)

    ​https://maildb.io/​

    ​https://hunter.io/​

    ​https://anymailfinder.com/​

In order to discover more valid email addresses or verify the ones you have already discovered you can check if you can brute-force them smtp servers of the victim. Learn how to verify/discover email address here.
Moreover, don't forget that if the users use any web portal to access their mails, you can check if it's vulnerable to username brute force, and exploit the vulnerability if possible.
Configuring GoPhish
Installation

You can download it from https://github.com/gophish/gophish/releases/tag/v0.11.0​

Download and decompress it inside /opt/gophish and execute  /opt/gophish/gophish
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local: 

ssh -L 333:127.0.0.1:3333 <user>@<ip>

Configuration
TLS certificate configuration

Before this step you should have already bought the domain you are going to use and it must be pointing to the IP of the VPS where you are configuring gophish.

DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​

Mail configuration

Start installing:  apt-get install postfix

Then add the domain to the following files:

    /etc/postfix/virtual_domains 

    /etc/postfix/transport

    /etc/postfix/virtual_regexp

Change also the values of the following variables inside /etc/postfix/main.cf

myhostname = <domain>
mydestination = $myhostname, <domain>, localhost.com, localhost

Finally modify the files /etc/hostname and /etc/mailname to your domain name and restart your VPS.

Now, create a DNS A record of mail.<domain> pointing to the ip address of the VPS and a DNS MX record pointing to mail.<domain> 

Now lets test to send an email:

apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com

Gophish configuration

Stop the execution of gophish and lets configure it.
Modify /opt/gophish/config.json to the following (note the use of https):

{
        "admin_server": {
                "listen_url": "127.0.0.1:3333",
                "use_tls": true,
                "cert_path": "gophish_admin.crt",
                "key_path": "gophish_admin.key"
        },
        "phish_server": {
                "listen_url": "0.0.0.0:443",
                "use_tls": true,
                "cert_path": "/opt/gophish/ssl_keys/key.crt",
                "key_path": "/opt/gophish/ssl_keys/key.pem"
        },
        "db_name": "sqlite3",
        "db_path": "gophish.db",
        "migrations_prefix": "db/db_",
        "contact_address": "",
        "logging": {
                "filename": "",
                "level": ""
        }
}

Configure gophish service

In order to create the gophish service so it can be started automatically and managed a service you can create the file /etc/init.d/gophish with the following content:

#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586
​
# define script variables
​
processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error
​
start() {
    echo 'Starting '${processName}'...'
    cd ${appDirectory}
    nohup ./$process >>$logfile 2>>$errfile &
    sleep 1
}
​
stop() {
    echo 'Stopping '${processName}'...'
    pid=$(/bin/pidof ${process})
    kill ${pid}
    sleep 1 
}
​
status() {
    pid=$(/bin/pidof ${process})
    if [["$pid" != ""| "$pid" != "" ]]; then
        echo ${processName}' is running...'
    else
        echo ${processName}' is not running...'
    fi
}
​
case $1 in
    start|stop|status) "$1" ;;
esac

Finish configuring the service and checking it doing:

mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop

Configuring mail server and domain
Wait

The older a domain is the less probable it's going to be caught as spam. Then you should wait as much time as possible (at least 1week) before the phishing assessment.
Note that even if you have to wait a week you can finish configuring everything now. 
Configure Reverse DNS (rDNS) record

Set a rDNS (PTR) record that resolves the IP address of the VPS to the domain name.
Sender Policy Framework (SPF) Record

You must configure a SPF record for the new domain. If you don't know what is a SPF record read the following page:
25,465,587 - Pentesting SMTP/s
/pentesting/pentesting-smtp

You can use https://www.spfwizard.net/ to generate your SPF policy (use the IP of the VPS machine)

This is the content that must be set inside a TXT record inside the domain:

v=spf1 mx a ip4:ip.ip.ip.ip ?all

Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

You must configure a DMARC record for the new domain. If you don't know what is a DMARC record read the following page:
25,465,587 - Pentesting SMTP/s
/pentesting/pentesting-smtp

You have to create a new DNS TXT record pointing the hostname _dmarc.<domain> with the following content:

v=DMARC1; p=none

DomainKeys Identified Mail (DKIM)

You must configure a DKIM for the new domain. If you don't know what is a DMARC record read the following page:
25,465,587 - Pentesting SMTP/s
/pentesting/pentesting-smtp

This tutorial is based on: https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy​

You need to concatenate both B64 values that the DKIM key generates:

v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB

Test your email configuration score

You can do that using https://www.mail-tester.com/
Just access the page and send an email to the address they give you:

echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com

You can also check your email configuration sending an email to check-auth@verifier.port25.com and reading the response (for this you will need to open port 25 and see the response in the file /var/mail/root if you send the email a as root).
Check that you pass all the tests:

==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham

Alternatively, you can send a message to a Gmail address that you control, view the received email’s headers in your Gmail inbox, dkim=pass should be present in the Authentication-Results header field.

Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;

​Removing from Spamhouse Blacklist

The page www.mail-tester.com can indicate you if you your domain is being blocked by spamhouse. You can request your domain/IP to be removed at: ​https://www.spamhaus.org/lookup/​
Removing from Microsoft Blacklist

​​You can request your domain/IP to be removed at https://sender.office.com/.
Create & Launch GoPhish Campaign
Sending Profile

    Set some name to identify the sender profile

    Decide from which account are you going to send the phishing emails. Suggestions: noreply, support, servicedesk, salesforce...

    You can leave blank the username and password, but make sure to check the Ignore Certificate Errors

It's recommended to use the "Send Test Email" functionality to test that everything is working.
I would recommend to send the test emails to 10min mails addresses in order to avoid getting blacklisted making tests.
Email Template

    Set some name to identify the template

    Then write a subject (nothing estrange, just something you could expect to read in a regular email)

    Make sure you have checked "Add Tracking Image"

    Write the email template (you can use variables like in the following example):

<html>
<head>
	<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
​
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">As you may be aware, due to the large number of employees working from home, the "PLATFORM NAME" platform is being migrated to a new domain with an improved and more secure version. To finalize account migration, please use the following link to log into the new HR portal and move your account to the new site: <a href="{{.URL}}"> "PLATFORM NAME" login portal </a><br />
<br />
Please Note: We require all users to move their accounts by 04/01/2021. Failure to confirm account migration may prevent you from logging into the application after the migration process is complete.<br />
<br />
Regards,</span></p>
​
WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY
​
<p>{{.Tracker}}</p>
</body>
</html>

Note that in order to increase the credibility of the email, it's recommended to use some signature from an email from the client. Suggestions: 

    Send an email to a non existent address and check if the response has any signature.

    Search for public emails like info@ex.com or press@ex.com or public@ex.com and send them an email and wait for the response.

    Try to contact some valid discovered email and wait for the response

The Email Template also allows to attach files to send. If you would also like to steal NTLM challenges using some specially crafted files/documents read this page.
Landing Page

    Write a name

    Write the HTML code of the web page. Note that you can import web pages.

    Mark Capture Submitted Data and Capture Passwords

    Set a redirection

Usually you will need to modify the HTML code of the page and make some tests in local (maybe using some Apache server) until you like the results. Then, write that HTML code in the box.
Note that if you need to use some static resources for the HTML (maybe some CSS and JS pages) you can save them in /opt/gophish/static/endpoint and then access them from /static/<filename>

For the redirection you could redirect the users to the legit main web page of the victim, or redirect them to /static/migration.html for example, put some spinning wheel (https://loading.io/) for 5 seconds and then indicate that the process was successful.
Users & Groups

    Set a name

    Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)

Campaign

Finally, create a campaign selecting a name, the email template, the landing page, the URL, the sending profile and the group. Note that the URL will be the link sent to the victims

Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like:

I would recommend to send the test emails to 10min mails addresses in order to avoid getting blacklisted making tests.

Once everything is ready, just launch the campaign!
Detecting the detection

Obviously one of the best ways to know if you have been busted is to search your domain inside blacklists. If it appears listed, somehow your domain was detected as suspicions.
One easy way to check if you domain appears in any blacklist is to use https://malwareworld.com/​

However, there are other ways to know if the victim is actively looking for suspicions phishing activity in the wild as explained in:
Detecting Phising
/phishing-methodology/detecting-phising

You can buy a domain with a very similar name to the victims domain and/or generate a certificate for a subdomain of a domain controlled by you containing the keyword of the victim's domain. If the victim perform any kind of DNS or HTTP interaction with them, you will now that he is actively looking for suspicious domains and you will need to very very stealth.
References

    ​https://zeltser.com/domain-name-variations-in-phishing/​

    ​https://0xpatrik.com/phishing-domains/​
