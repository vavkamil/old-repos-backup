### Glastopf Analytics :: easy honeypot statistics v2.0

[Glastopf](https://github.com/glastopf/glastopf) is a Python web application honeypot founded by Lukas Rist.

---

This Perl script provides simple statistics for the Glastopf. While accessing default SQLite glastopf.db, it can retrieve some basic informations about your honeypot.

#### Requirements

DBI - apt-get install libcpan-sqlite-perl

Dancer2 - cpanm Dancer2

Geo::IP - apt-get install libgeo-ip-perl

#### Installation

```
root@honeypot::~# git clone https://github.com/vavkamil/Glastopf-Analytics.git
```

#### Usage

First edit path to glastopf database & change username and password in ./lib/MyWeb/App.pm at lines 9-11:

set 'database'  =>  '/opt/myhoneypot/db/glastopf.db';

set 'username'  =>  'admin';

set 'password'  =>  'password';

```
root@honeypot:~/Glastopf-Analytics$ perl ./bin/app.pl
```

#### Example

[![IMAGE ALT TEXT HERE](http://img.youtube.com/vi/NuucT_l8Nhg/0.jpg)](http://www.youtube.com/watch?v=NuucT_l8Nhg)