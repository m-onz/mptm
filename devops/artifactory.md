Artifactory Hacking guide

This content was taken from https://www.errno.fr/artifactory/Attacking_Artifactory​
Artifactory basics
Default users and passwords

Artifactory’s default accounts are:

Account
	

Default password
	

Notes

admin
	

password
	

common administration account

access-admin
	

password (<6.8.0) or a random value (>= 6.8.0)
	

used for local administration operations only

anonymous
	

’’
	

anonymous user to retrieve packages remotely, not enabled by default

By default, no password locking policy is in place which makes Artifactory a prime target for credential stuffing and password spraying attacks.
Authorizations

Ideally, this is what you should see when connecting to Artifactory:
Login page

On the other hand, if you’re greeted with something more akin to this:
Default page

It means that “Anonymous access” has been enabled in the administration panel, which is a common setting used to let applications retrieve artifacts without hassle but lets you, the attacker, see more than is preferable.
Checking account rights

Sometimes, because of a misconfiguration, anonymous is allowed to deploy files to some repositories!

To check which repositories the anonymous user can deploy to, use the following request:

curl http://localhost:8081/artifactory/ui/repodata?deploy=true
{"repoList":["artifactory-build-info","example-repo-local"]}

If there are any repoKey entries in the request, anonymous can deploy to these, which is really really bad. You definitely should be authenticated to deploy any files.

This can be generalized to other accounts once you get a password or token for them.
Listing users

For some reason listing users is a right reserved to admins only. I found an alternate way to list users (those that are actively deploying at least) that relies on the “Deployed By” value of artifacts:
Deployed By

​This script simply tries to recursively find all the users that have deployed artifacts. Note that it could take a while to complete if there are a lot of repositories (>1000).

./artifactory_list_users.py http://127.0.0.1:8081/artifactory
There are 23 repositories to process
Found user admin
Found user test
Found user user
Found user test_deploy

Permissions

Here are the basic permissions and their usefulness:

    Manage: ?

    Delete/Overwrite: interesting for pentest

    Deploy/Cache: interesting for pentest

    Annotate: necessary for CVE-2020-7931

    Read: usually a default permission

Known vulnerabilities

Here is a curated list of high impact public vulnerabilities:
CVE-2016-10036: Arbitrary File Upload & RCE (<4.8.6)

​Details here.​

This one is getting a bit old and it’s unlikely you’ll stumble on such an outdated Artifactory version. Nevertheless it’s quite effective, as it is a simple directory traversal which nets arbitrary code execution at the Tomcat level.
CVE-2019-9733: Authentication bypass (<6.8.6)

​Original advisory here.​

On older versions of Artifactory (up to 6.7.3), the access-admin account used a default password password.

This local account is normally forbidden to access the UI or API, but until version 6.8.6 Artifactory could be tricked into believing the request emanated locally if the X-Forwarded-For HTTP header was set to 127.0.0.1.
CVE-2020-7931: Server-Side Template Injection (Artifactory Pro)

​Original advisory here.​

Here’s a tool I wrote to automate the exploitation of this vulnerability.

These are required for exploitation:

    a user with deploy (create files) and annotate (set filtered) rights

    Artifactory Pro

The vulnerability is rather simple: if a deployed resource is set to filtered it is interpreted as a Freemarker Template, which gives the attacker a SSTI attack window. Filtered Resource​

Here are the implemented primitives:

    basic filesystem reads

    limited filesystem writes

These should be enough to give you remote code execution in a number of manners, from the easiest/quietest to the hardest/noisiest:

    reading a secret on the filesystem that lets you pivot (/home/user/.bash_history, /home/user/password.txt, /home/user/.ssh/id_rsa …)

    adding an SSH key to the user

    deploying a .war to execute a servlet

    deploying an Artifactory Groovy user script

.war stories: Java renameTo() shenanigans

This is a little story of how I banged my head against the wall for hours if not days during a pentest. I came accross an outdated Artifactory which I knew was vulnerable to CVE-2020-7931. I deployed the original’s advisory SSTI template and started perusing through the filesystem. It seemed that Artifactory had been installed in a non-standard location, which isn’t too unusual as admins like to keep separated partitions between application binaries, data, logs and configuration (this is a good thing!). There were no SSH keys or passwords in the user’s home directory that would have provided me with an easy pivot, so there came the time to be less discreet and write to the filesystem. Dropping the initial payload (a public key) in Artifactory’s upload directory went fine, but I just couldn’t manage to move it to the SSH keys directory. So I went back to my exploitation sandbox, tested it again and lo and behold, it worked fine. So there had to be a different configuration that prevented me from completing the renameTo() method. At this point it’s always a good idea to check the documentation … which clearly states that you cannot rename files accross different filesystems, which I guess makes sense depending on the implementation of the method, i.e. if it works at an inode level. Arg.

Remember what I said about admins liking partitions? Well, this is a case of an admin unbeknownstingly hardening his setup against my exploit! So I had to dig into what is essentially a Java jail to find another method that would let me write a file to disk. And that wasn’t fun at all, as I’m not familiar with any of the things involved: FTL Templates, Java, Tomcat/Catalina. I quickly discovered that regular Java jail escapes just wouldn’t cut it, as instatiating new classes was forbidden. After hours of reading the Java and Catalina classes documentation, I finally found a write() method on a object which I could reach. But it was limited to the web application’s base path… So then I thought of combining the write to another filesystem and the renameTo() accross this newly reachable filesystem to hopefully be able to write anywhere? And it kinda worked. I managed to write out of the temporary upload dir … but not so far from it as now I was stuck on another filesystem which was the mountpoint to all things artifactory: configuration, application and stuff. So still no SSH key for me.

Okay, I could write to the artifactory root folder, surely I could do something here? Hey, default Tomcat automatically does deploy WAR files written to its application path, doesn’t it? So I used msfvenom to generate a JSP webshell packed in a WAR file and tested it in my sandbox… well it got deployed alright, but netted me no command execution. Seems like default Tomcat doesn’t handle JSPs. Ugh. Getting increasingly frustrated, I looked for another way to execute code in Tomcat, and found another execution method using servlets. Couldn’t find an appropriate payload so fuck it, I’m all in at this point and rolled my own which you can find here. Tested it in the sandbox, works, ok. Put it on target, deploys and … nada. Turns out, there was a proxy in front of artifactory that rewrote all URLs to /artifactory. So even though my backdoor was deployed and running, there was no way for me to access it… If there was some remote code execution to achieve at this point, it would have to be in Artifactory’s context, not Tomcat’s.

Come next morning, I’m sobbing at my desk looking a last time at Artifactory’s documentation in vain hopes of an epiphany. And then the magical words “Groovy scripts” appeared. Turns out there’s a convoluted way to execute Groovy scripts, by writing them to disk then reloading them through the API. Saved at last! So I popped a Groovy reverseshell to machine and that was the end of that. Still wish I had found a cleaner method that would have written anywhere on the filesystem using the SSTI, but I sure wasn’t going to back to developping!

Fortunately, all pentests don’t go like this :)
Post-Exploitation

The following are only useful once you’ve achieved remote code execution or arbitrary file read on the server and might help you pivoting to another machine.
Storage of passwords and external secrets
Local passwords

Local artifactory passwords are stored in either salted MD5 or bcrypt form, the former being deprecated.

MD5 passwords are always salted with the hardcoded the spring value {CAFEBABEEBABEFAC}, and are using simple concatenation with no rounds, i.e. hash = md5(password + salt). The database says the salt is CAFEBABEEBABEFAC but trust me, it’s {CAFEBABEEBABEFAC}, I had a hard time finding it :)

Cracking these MD5 passwords requires using a dynamic mode for JtR:

cat artifactory.hashes
user:1f70548d73baca61aab8660733c7de81${CAFEBABEEBABEFAC}
john artifactory.hashes --format=dynamic_1
Loaded 1 password hash (dynamic_1 [md5($p.$s) (joomla) 256/256 AVX2 8x3])
password         (user)

The other type of bcrypt password requires nothing special, it’s just a standard bcrypt hash:

cat artifactory_bcrypt.hashes
admin:$2a$08$EbfHSAjPLoJnG/yHS/zmi.VizaWSipUuKAo7laKt6b8LePPTfDVeW
john artifactory_bcrypt.hashes
Loaded 1 password hash (bcrypt [Blowfish 32/64 X2])
password          (admin)

Remote secrets

Artifactory may need to store secrets to identify to remote services. These secrets aren’t hashed of course, they’re stored encrypted on the disk, with the key next to them. There are two types of secrets mentionned in the official documentation.

Old format (<5.9): DES-EDE

TODO. Open an issue if you have sample encrypted data.

New format (>=5.9): AES128-CBC encryption, stored as base58

External secrets (such as passwords of remote servers) are found in the configuration descriptors, e.g. /var/opt/jfrog/artifactory/etc/artifactory.config.latest.xml and look like:

<keyStorePassword>AM.25rLQ.AES128.vJMeKkaK6RBRQCUKJWvYEHUw6zs394X1CrRugvJsQGPanhMgQ5be8yjWDhJYC4BEz2KRE</keyStorePassword>

Where:

    AM always denotes an artifactory encrypted secret

    25rLQ is the secret identifier that has to match the key’s identifier

    AES128 obviously is the algorithm used

    vJMeK...KRE is the base58 encoding of IV_SIZE|IV|secret|CRC

More secrets can be found (tokens, configuration backups …) by using the following regexp:

grep -r 'AM\..*\.AES128\.' /var/opt/jfrog/artifactory/

The key is stored in /var/opt/jfrog/artifactory/etc/security/artifactory.key and looks like:

JS.25rLQ.AES128.7fcJFd3Y2ib3wi4EHnhbvZuxu

Where:

    JS denotes a key

    25rLQ is a unique key identifier that keeps track of which key can decrypt which secrets

    AES128 obviously is the algorithm used

    7fcJFd3Y2ib3wi4EHnhbvZuxu is the base58 encoding of the key and 2 bytes of CRC

This tool I wrote can be used offline to decrypt Artifactory secrets: ArtifactoryDecryptor.
Defending Artifactory

If you’re the blue team or an Artifactory admin, by now you should have a pretty good idea of what to do:

    keep Artifactory up to date, especially when criticial updates are issued

    implement a sound password policy (no default passwords, mandatory strong passwords, lockouts), preferably deferred to an external LDAP for better supervision

    restrict accesses (respect the principle of least privilege), especially for the anonymous user
