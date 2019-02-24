# DNS-Vicious
STOP Offensive DNS

#### Overview
dnsvicious is a simple Perl script that will compare list of DNS's against list of URL's. Idea is to find rogue DNS servers, locate spoofed domains and poisoned .js files.

#### Example
```
root@dnsvicious:~# perl dnsvicious.pl 
[OK] This 93.91.146.150 sounds good.

[!] WARNING 93.91.146.150 is fucked up!
[!] Possibly spoofed: google.com
[!] Google Inc. != SuperNetwork s.r.o.
[!] http://whois.domaintools.com/74.125.71.100
[!] http://whois.domaintools.com/95.168.222.98

[OK] This 93.91.146.150 sounds good.

[!] WARNING 93.91.146.150 is fucked up!
[!] Possibly spoofed: youtube.com
[!] Google Inc. != SuperNetwork s.r.o.
[!] http://whois.domaintools.com/74.125.71.136
[!] http://whois.domaintools.com/95.168.222.118

[OK] This 93.91.146.150 sounds good.

[!] WARNING 93.91.146.150 is fucked up!
[!] Possibly spoofed: amazon.com
[!] PROD IAD != Amazon.com, Inc.
[!] http://whois.domaintools.com/176.32.98.166
[!] http://whois.domaintools.com/72.21.206.6

[OK] This 85.13.106.14 sounds good.

[OK] This 85.13.106.14 sounds good.

[OK] This 85.13.106.14 sounds good.

[OK] This 85.13.106.14 sounds good.

^C
root@dnsvicious:~# 
```
