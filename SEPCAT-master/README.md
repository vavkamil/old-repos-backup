### SEPCAT :: Static Exploitable PHP Code Analysis Tool v0.5 Alpha

SEPCAT is a simple PHP Static Code Analysis (SCA) tool written in Perl.
It could be used to quickly test a PHP project that you think may have some potential vulnerabilities.

#### WARNING

This is an alpha version. It is not recommended to use in a production environment yet. I'm sharing this code only for testing. There will be a lot of changes, before release of usable version.

#### Usage

```
vavkamil@localhost:~/SEPCAT$ perl sepcat.pl -help

Usage: perl sepcat.pl -folder /var/www/wp_plugins/

Overview:
    SEPCAT is a simple PHP Static Code Analysis (SCA) tool written in Perl.
    It could be used to quickly test a PHP project that you think
    may have some potential vulnerabilities.

Options:
    -file       Scan a single PHP file.
    -folder     Recursive deep scan for a specific directory.
    -result     Save result to a given output file.
    -version    Print current version.
    -help       This help message.
```

#### Example

```
vavkamil@localhost:~/SEPCAT$ perl sepcat.pl -folder test_vuln_files/

[SEPCAT] Static Exploitable PHP Code Analysis Tool
[+] Scanning folder: test_vuln_files/

[+] Vulnerable file: test_vuln_files/RFI_test.php
[-] Line 13: PHP File Inclusion in 'include' via '$rfi'

[+] Vulnerable file: test_vuln_files/XSS_test.php
[-] Line 16: Cross-Site Scripting (XSS) in 'print' via '$age'

[+] Vulnerable file: test_vuln_files/SQLi_test.php
[-] Line 13: SQL Injection in 'mysql_query' via '$id'

[+] Thank you for using SEPCAT, version 0.5 Alpha


```

#### TODO
1) Write a better PHP parser (maybe with Regexp::Grammars).

2) Check inputs which aren't stored in a variables (echo $_GET['xss'];).

3) Add more sinks for different vulnerabilities (OWASP top 10).

4) Whole logic is bad, need to rewrite all parts of this crappy code.

#### Credits

Functionality based on DevBug (http://devbug.co.uk).

DevBug was created by Ryan Dewhurst (www.dewhurstsecurity.com)

as part of his undergraduate university thesis.