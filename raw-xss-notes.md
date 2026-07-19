***XSS NOTES PORTSWIGGER***

Its basically an attack that injects some JS into a user website

there are 3 types of attacks

Reflected -> requests come from current HTTP request

https://insecure-website.com/status?message=All+is+well.

<p>Status: All is well.</p>

If the user interacts with any of the attacker's website then the scripted would be executed

to use alert we just inject

using <script>alert(1)</script>

The location of reflected data reveals what kind of payload we should be using



What is the difference between reflected XSS and self-XSS? Self-XSS involves similar application behavior to regular reflected XSS, however it cannot be triggered in normal ways via a crafted URL or a cross-domain request. Instead, the vulnerability is only triggered if the victim themselves submits the XSS payload from their browser. Delivering a self-XSS attack normally involves socially engineering the victim to paste some attacker-supplied input into their browser. As such, it is normally considered to be a lame, low-impact issue.



Stored -> comes from website's database

the data would be submitted via HTTP requests for eg using a comment on a blog site EG

<p> HEllo, This is my message </p>

could be

<p><script>/\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\* Badd stuff... \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*/</script></p>



DOM -> vulnerability exists in client side code rather than server side

DOM is Document Object Model

That is an attacker could control the input field and inject some malicious JS

for: <img src=1 onerror='/\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\* Bad stuff here... \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*/'>

Manually testing for DOM-based XSS arising from URL parameters involves a similar process: placing some simple unique input in the parameter, using the browser's developer tools to search the DOM for this input, and testing each location to determine whether it is exploitable. However, other types of DOM XSS are harder to detect. To find DOM-based vulnerabilities in non-URL-based input (such as document.cookie) or non-HTML-based sinks (like setTimeout), there is no substitute for reviewing JavaScript code, which can be extremely time-consuming. Burp Suite's web vulnerability scanner combines static and dynamic analysis of JavaScript to reliably automate the detection of DOM-based vulnerabilities.



DOM-based XSS vulnerabilities usually arise when JavaScript takes data from an attacker-controllable source, such as the URL, and passes it to a sink that supports dynamic code execution, such as eval() or innerHTML



Commonly how we use XSS or rather if a website is XSS vulnerable

by using alert() but by 2021 the chrome browser had updated its security JS features hence now we use print()

 

A DOM commonly uses a source and a sink where in a source is where an attacker controlled input can be put which would be then transferred to the sink

Sources

A source is a JavaScript property that accepts data that is potentially attacker-controlled. An example of a source is the location.search property because it reads input from the query string, which is relatively simple for an attacker to control. Ultimately, any property that can be controlled by the attacker is a potential source. This includes the referring URL (exposed by the document.referrer string), the user's cookies (exposed by the document.cookie string), and web messages.

A sink is a potentially dangerous JavaScript function or DOM object that can cause undesirable effects if attacker-controlled data is passed to it. For example, the eval() function is a sink because it processes the argument that is passed to it as JavaScript. An example of an HTML sink is document.body.innerHTML because it potentially allows an attacker to inject malicious HTML and execute arbitrary JavaScript.



Fundamentally, DOM-based vulnerabilities arise when a website passes data from a source to a sink, which then handles the data in an unsafe way in the context of the client's session.



So we can use XSS exploit using \&storeId="></select><img%20src=1%20onerror=alert(1)>

%20 is space in just encoding

we could first inject alphanumeric characters into the storeid

then we could just have the above exploit in the browser



if we want to use innerHTML as sink and source as location.search

we would wanna inject something in the search bar itself



if javascripts's jQuery is being used use attr() function that can change the attributes of the DOM elements



In lab 4 of DOM we just change the returnUrl in the address bar then find out in inspect element that the random alphanumeric has been placed in href

https://

'''<iframe src="https://#" onload="this.src+='<img src=1 onerror=alert(1)>'">'''



What is an iframe?

An iframe is like a small browser window inside another webpage.

So it opens a mini window on your webpage

the src part is the vulnerable website and the hash is the main part in this lab after the hash everything is location hash

so whenever the hash changes the code runs this payload

old url -> iframe

<img src=x onerror=print()>

since x is not a real image the error presents itself with the print() pop up



In angular js there is no need for the traditional JS <> angular brackets for the code to execute we only require {{expression}}



the angular js would automatically detect the code inside and execute it

eg {{alert(1)}}  this would bypass any block filters as they would be automatically executed



User input

   ↓

Inserted into HTML

   ↓

AngularJS processes {{ }}

   ↓

JavaScript executes



***When testing DOM XSS always check:***



***ng-app***

***ng-controller***

***{{ }}***

***ng-bind***



for the next lab

we use {{$on.constructor('alert(1)')()}}

In AngularJS, $on is a built-in function used for events.

$on.constructor



points to the Function constructor.



Meaning we now have access to something that can create and run JavaScript code.

we use () to immediately run the function as we create it

the above constructor creates a function with alert then run it with () empty brackets





DOM XSS combined with reflected XSS and stored XSS



DOM XSS combined with reflected and stored data

Some pure DOM-based vulnerabilities are self-contained within a single page. If a script reads some data from the URL and writes it to a dangerous sink, then the vulnerability is entirely client-side.



However, sources aren't limited to data that is directly exposed by browsers - they can also originate from the website. For example, websites often reflect URL parameters in the HTML response from the server. This is commonly associated with normal XSS, but it can also lead to reflected DOM XSS vulnerabilities.



In a reflected DOM XSS vulnerability, the server processes data from the request, and echoes the data into the response. The reflected data might be placed into a JavaScript string literal, or a data item within the DOM, such as a form field. A script on the page then processes the reflected data in an unsafe way, ultimately writing it to a dangerous sink.



eval('var data = "reflected string"');



In pure DOM XSS everything happens inside the browser the server isn't involved but in Reflected DOM its a two step process

1. The user clicks the malicious payload then the server reads this data and echoes it back into the html but the server doesn't do anything with the script it just puts it back into a 'harmless' place such as JAVASCRIPT variable



2\. Now when the browser loads and page and accidently thinking that is a harmless variable executes the script by putting it into a sink



What the eval() function does??

The eval () function is a dangerous sink that tells the browser

"Take wtv is inside the parenthesis and run it as actual code"



In this lab we need to design our payload according to the eval tab  as seen in the site map in burp

  eval('var searchResultsObj = ' + this.responseText);

            displaySearchResults(searchResultsObj);

        }

    };

this is the current so we cannot just put a " to break out of the searchTerm text box as javascript would just put \\" to override this.

So we need smthg else

If we do this the quote would be trapped inside a string

eg eval would see {"searchTerm":'\\""}

the only way to counteract this is to send a backslash of our  own before the quote (\\")

If we send this the server would add a backslash of its own and in JS two backslashes(\\\\) mean print one literal backslash character so this would close the searchTerm string early!



Now since we closed the text box we need to run alert(1) but we cannot just slap a function and a string side by side so we need to convert it to a mathematical function

{"searchTerm":"\\\\" - alert(1)}

it makes no sense to subtract even nothing from a pop up box but JS would still do it and it would execute our alert

 and the // comments out the rest



so the final payload would be

**\\"-alert(1)}//**





 In the stored DOM XSS lab we just use <> at the starting as the website has a replace() keyword that would encode the angular brackets so we bypass it by placing them first then writing our payload in the other angular brackets



as we know that for (document.cookie) we use a <script></script>

inside that document.cookie



syntax: <script>alert(document.domain)</script>

okey so in the third lab we see that normal tags are blocked and custom tags are allowed like

So the question is that can we use these custom tags to execute some javascript in this website so

we test it out

Can i trigger an event?

like in browsers onfocus, onclick , onmouseover , onload it can support these events

So we know that these tags only checks for attributes and tags

so we need something that could

Inject a custom tag -> make it run JS -> trigger it automatically



Okey so in this lab we use <script> as we are using a vulnerable server to redirect out malicious link onto the site

that's why we use this crafted url

so script then location points this bad url to our target site

***<script>***

***location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';***

***</script>***



so in this we see our lab id then some encoded script the id would be 'x' which i would get into later the onfocus alert would ofc alert our webpage the basic xss function using document.cookie as JS is involved here we have tabindex now this is the most important function that is missed this would make onfocus work without this onefocus would never work this would be vital

\-> tabindex=1 makes the element focus in using tab keys

ALTHOUGH IT IS NOT ADVISABLE TO USE POSITIVE NO'S IN REAL LIFE



negative no's would just not be controlled using tab key



At last the #x this is another clever trick that i learned in this lab which points the site back to id=x in our url so that it triggers that event specifically



LAB: SVG



\-> svg is scalable vector graphics that is an image that can behave as an html page in its entirety it can even have events and more and the best part most filters just let it walkthrough it is mostly stored in DOM (document object Module)



eg-> <svg width="200" height="100">

&#x20; <rect width="200" height="100" fill="red" />

</svg> 

for testing which tag would work we would insert <$$>

and using xss cheatsheet we would copy all the tags



so we find out svg with animatetransform is showing 200

so we just put <svg><animatetransform onbegin=alert(1)>

(we find onbegin using events in intruder)

then we percent encode this and copy paste into url then it would run



There are times when the html is encoded that is we cannot insert < or > so we find a way around it we use

" autofocus onfocus=alert(1) x="

the x= attribute is used as a dummy attribute so that the website doesn't get confused as only onfocus would confuse it



sometimes we don't need to break out of the html we could use the attribute to our advantage using the href anchor tag as it specifies which url to point to

so it just points to some other links

but some browsers support smthg else ie

javascript:

this is a special protocol that tell it instead of going somewhere else run this code

so we could just do

javascript:alert(document.domain)

document.domain tells us which website or domain this webpage belongs to ie who is the owner



LAB : Canonical link

In this lab there appears to be a

<link rel="canonical' 'User\\\\\\\_input'> vulnerability

so this means that only user input could be processed and then turned into an alert ie we need to inject the xss in the url itself for this lab to work



he application is reading input from the query string



Example:



https://lab-id.web-security-academy.net/?input=HELLO



Server does:



<body HELLO>



So if you send:



?input='accesskey='x'onclick='alert(1)



It becomes:



<body 'accesskey='x'onclick='alert(1)>





Terminating the existing script

In the simplest case, it is possible to simply close the script tag that is enclosing the existing JavaScript, and introduce some new HTML tags that will trigger execution of JavaScript. For example, if the XSS context is as follows:



<script>

...

//var input = 'controllable data here';

...


then you can use the following payload to break out of the existing JavaScript and execute your own:








***Lab: Reflected XSS into a JavaScript string with single quote and backslash escaped***



First we check that if we insert any alphanumeric character in the search box it gets executed using javascript

Second add a quote in the search box . in the elements we see that the quote gets a backslash so as we cannot break out of the element



//eg :var searchTerms = 'test\\'payload';

&#x20;                       document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');



so we need to get out of this script

//for that we use the above method by injecting

</script><script>alert(1)</script>



so we get this output

//<script> var searchTerms = '</script>        

<script>alert(1)</script>



In cases where the XSS context is inside a quoted string literal, it is often possible to break out of the string and execute JavaScript directly. It is essential to repair the script following the XSS context, because any syntax errors there will prevent the whole script from executing.



Some useful ways of breaking out of a string literal are:



'-alert(document.domain)-'

';alert(document.domain)//



so using this we could do something like this



var searchTerms = **''-alert(document.domain)-''**;

&#x20;                       document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');

&#x20;

the quotes we just close them at each turn

'-' is used as a minus operator that just turns our input into a

mathematical operation which executes



if a webpage resists or closes the quote by a backslash we just use this payload

\\';alert(document.domain)//

the semicolon here tells the browser to end the current instruction and start a new one



If a WAF (Web Application Firewall) is difficult to bust

The following code assigns the alert() function to the global exception handler and the throw statement passes the 1 to the exception handler (in this case alert). The end result is that the alert() function is called with 1 as an argument.



onerror=alert;throw 1



For example, if the XSS context is as follows:



//<a href="#" onclick="... //var input='controllable data here'; ...">

and the application blocks or escapes single quote characters, you can use the following payload to break out of the JavaScript string and execute your own script:



\&apos;-alert(document.domain)-\&apos;

The \&apos; sequence is an HTML entity representing an apostrophe or single quote. Because the browser HTML-decodes the value of the onclick attribute before the JavaScript is interpreted, the entities are decoded as quotes, which become string delimiters, and so the attack succeeds.



AS we know that html encoding happens first before java script so we can pass through some poorly guarded filters

then java script code would execute



Lab: Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

In this lab we find that in website we need to match the specific requirements

//so using http:\&apos;-alert(document.domain)-\&apos;

we bypass the filter and alert the site

this was my first try and solution


Lab: **Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped**

So in the last lab of this particular topic

we cannot use any of the mentioned characters above so we go with something more creative since our content is inserted into java script literal we can simply use 

//${alert(1)} that would be executed 

If u see this format ie

<script>

...

// var input = `controllable data here`;

...

//</script>

**then we can easily use this maneuver**
**Exploiting XSS vulnerabilities**

//&#x20;

