---
layout: post
title:  "Cross-site scripting (XSS) in Sophos Web Appliance - 4.1.1-0.9"
date:   2023-04-30 19:51:02 +0700 
categories: [cve]
---

Vendor: Sophos

Product: Sophos Web Appliance

Version affected: 4.1.1-0.9

This worked also on the latest v4.3.9.1 version (as of 05 Jan 2020)
I used Firefox Browser, 71.1(64-bit) on Windows 10.

#### Product description:
The Sophos Web Appliance is designed to function as a web proxy that provides HTTP security at. the gateway. 
Potentially risky content is scanned for various forms of malware.

"Sophos Web Appliance (SWA) and Sophos Management Appliance (SMA) will reach End of Life (EOL) on 20 July 2023. When this happens, the products will continue to pass traffic but will no longer receive security or software updates. Cloud services with functions such as support services and LiveConnect will be turned off."

* CVE ID: awaiting, initially reported to Sophos on 05 Jan 2020 via Bugcrowd. Requested for CVE on Apr 28, 2023
* CWE ID: CWE-79

#### Proof of Concept:

Reflected cross-site scripting (XSS) vulnerability was discovered in the product.

It was possible to inject malicious code and input was successfully reflected between doubles quotes.
It's a systemic XSS, which definitely increases risk compared to standard XSS.

Vulnerable input section was possible to set to:
status
reports
configuration

The following Proof of Concept (PoC) demonstrates the attack as well as displaying evidence of the script payload being returned in the response. 

{% highlight ruby %}
Sample GET request:
https://10.0.0.17/index.php?c=trend_suspect&period=0&section=reports" onmouseover%3dprompt(1) bad%3d"&STYLE=34f6ad4ed0b9f19a094041a234feb5e3
{% endhighlight %}

![Java Script executed when the page loads in the user's browser](/static/img/swa-4.1.1.png)

Authenticated reflected XSS with the privileges of admin user.
Sophos Virtual Web Appliance used to demonstrate the vulnerability was the latest available from Sophos trials website. 

#### References:
1. https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
2. https://support.sophos.com/support/s/article/KB-000039441?language=en_US
3. https://docs.sophos.com/nsg/swa/help/en-us/nsg/swa/concepts/AboutYourAppliance.html
