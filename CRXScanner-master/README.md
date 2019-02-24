# CRXScanner
Fingerprinting Chrome Extensions (manifest v2.0)

Blog post: http://www.xexexe.cz/2015/12/fingerprinting-chrome-extensions.html

Chrome PoC: http://www.hacktheplanet.cz/crxscanner/chrome-poc.html

#### Example

```
vavkamil@localhost:~/CRXScanner$ perl crxscanner.pl -e extensions.txt

 __ .__ \ / __.     version 0.1
/  `[__) X (__  _ _ __ __  _ __
\__.|  \/ \.__)(_(_|| || |(/.|\

[i] Extensions in the queue: 3757
[i] Extensions in the output: 666
[i] Output saved to ./crxscanner/addons.json
[i] Results are in ./crxscanner/chrome-poc.html

vavkamil@localhost:~/CRXScanner$ 
```

#### TODO

Code is a huge mess, but it's somehow works :) I will rewrite it soon properly. Working on a blog post now ...