---
layout: post
title:  "Cross-site scripting (XSS) in Opmantek (FirstWave company), NMIS module before 9.4.3"
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

#### Proof of Concept

Reflected cross-site scripting (XSS) vulnerability was discovered in the product.

A cross-site scripting vulnerability was identified on the cgi-bin/config.pl page.

The following Proof of Concept (PoC) demonstrates the attack as well as displaying evidence of the script payload being returned in the response. 

#### Request:
{% highlight ruby %}
POC:

TBA
{% endhighlight %}

#### References:
1. https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
2. https://firstwave.com/products/network-management-information-system/
3. https://support.opmantek.com/browse/SUPPORT-10209
4. https://community.opmantek.com/display/NMIS/NMIS+9+Release+Notes
5. https://dl-nmis.opmantek.com/nmis9-9.4.3.run
