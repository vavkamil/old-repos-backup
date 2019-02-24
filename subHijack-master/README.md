# subHijack
Hijacking forgotten &amp; misconfigured subdomains

#### Description

http://www.xexexe.cz/2016/02/hijacking-forgotten-misconfigured.html

#### Example

```
vavkamil@localhost:~/Documents/perl/subHijack$ perl subHijack.pl -domain zo*****o.com

            _     _   _ _  _            _     
  ___ _   _| |__ | | | (_)(_) __ _  ___| | __ 
 / __| | | | '_ \| |_| | || |/ _` |/ __| |/ / 
 \__ \ |_| | |_) |  _  | || | (_| | (__|   <  
 |___/\__,_|_.__/|_| |_|_|/ |\__,_|\___|_|\_\ 
                        |__/                  


[i] Checking zo*****o.com for subdomain hijacking
[i] Found 3 nameservers
[i] Trying zone transfer:
	[NS] dns2.zo*****o.com ~ OK
	[NS] dns3.zo*****o.com ~ OK
	[NS] dns1.zo*****o.com ~ Failed
[i] Found 99 subdomains
[i] Checking CNAME records
[i] Found 10 unique CNAME domains
[i] Checking whois records
[!] Found expired domain
	[x] email.zo*****o.com > CNAME > mkt*****20218.com
	[x] mkt*****20218.com is expired!

vavkamil@localhost:~/Documents/perl/subHijack$ 
```

#### TODO

1) Clean and comment code

2) Add output support (.txt, .xml, ...)

3) Add input support for Fierce.pl (Fierce::Parser)
http://search.cpan.org/~jabra/Fierce-Parser-0.08/lib/Fierce/Parser.pod

4) Add silent and verbose mode