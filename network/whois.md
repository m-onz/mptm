43 - Pentesting WHOIS
Basic Information

 WHOIS (pronounced as the phrase "who is") is a query and response protocol that is widely used for querying databases that store the registered users or assignees of an Internet resource, such as a domain name, an IP address block or an autonomous system, but is also used for a wider range of other information. (From here)

Default port: 43

PORT   STATE  SERVICE
43/tcp open   whois?

Enumerate

Get all the information that a whois service has about a domain:

whois -h <HOST> -p <PORT> "domain.tld"
echo "domain.ltd" | nc -vn <HOST> <PORT>

Notice than sometimes when requesting for some information to a WHOIS service the database being used appears in the response:

Also, the WHOIS service always needs to use a database to store and extract the information. So, a possible SQLInjection could be present when querying the database from some information provided by the user. For example doing: whois -h 10.10.10.155 -p 43 "a') or 1=1#" you could be able to extract all the information saved in the database.
Shodan

    port:43 whois
