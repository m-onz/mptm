JBOSS
Enumeration

The /web-console/ServerInfo.jsp and /status?full=true web pages often reveal server details.

You can expose management servlets via the following paths within JBoss (depending on the version): /admin-console, /jmx-console, /management, and /web-console. Default credentials are admin/admin. Upon gaining access, you can use available invoker servlets to interact with exposed MBeans:

    /web-console/Invoker (JBoss versions 6 and 7)

    /invoker/JMXInvokerServlet and /invoker/EJBInvokerServlet (JBoss 5 and prior)

You can enumerate and even exploit a JBOSS service using clusterd
Or using metasploit: 
msf > use auxiliary/scanner/http/jboss_vulnscan
Exploitation

​https://github.com/joaomatosf/jexboss​
Google Dork

inurl:status EJInvokerServlet
