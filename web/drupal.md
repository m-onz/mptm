Drupal
Username enumeration
Register

In /user/register just try to create a username and if the name is already taken it will be notified:
Request new password

If you request a new password for an existing username:

If you request a new password for a non-existent username:
Number of users enumeration

Accessing /user/<number> you can see the number of existing users, in this case is 2 as /users/3 returns a not found error:
Hidden pages enumeration

Fuzz /node/$ where $ is a number (from 1 to 500 for example).
You could find hidden pages (test, dev) which are not referenced by the search engines.
Code execution inside Drupal with admin creds

You need the plugin php to be installed (check it accessing to /modules/php and if it returns a 403 then, exists, if not found, then the plugin php isn't installed)

Go to Modules -> (Check) PHP Filter  -> Save configuration

Then click on Add content -> Select Basic Page or Article -> Write php shellcode on the body -> Select PHP code in Text format -> Select Preview
