#!/usr/bin/perl

# DNS-Vicious v0.1 - Identify malicious DNS
#
# http://www.mathematik.uni-ulm.de/help/perl5/doc/Net/DNS.html
# http://public-dns.tk/

use strict;
use warnings;

use Net::DNS;
use Net::Whois::IP qw(whoisip_query);

    my $timeout = 5;
    my @dns     = "8.8.8.8";    # OpenDNS 208.67.222.222 || Google 8.8.8.8
    my @domains = (
        "paypal.com", "google.com", "facebook.com", "youtube.com",
        "baidu.com",  "amazon.com"
    );

    while (<DATA>) {
        chomp;
        my @ns = $_;
        foreach my $domain (@domains) {
            my ( $ip_legit,   $check1 ) = dns_query( \@dns, $domain, $timeout );
            my ( $ip_compare, $check2 ) = dns_query( \@ns,  $domain, $timeout );

            if ( defined($check2) ) {
                print "[x] " . $_ . " timed out after $timeout seconds\n\n";
                next;
            }
            if ( not defined($ip_compare) ) {
                print "[wtf] no answer / skip.\n\n";
                next;
            }

            if ( $ip_legit ne $ip_compare ) {
                my $ip_legit_whoisname = whois($ip_legit);
                my $second_whoisname   = whois($ip_compare);

                if ( $ip_legit_whoisname ne $second_whoisname ) {
                    print "[!] WARNING " . $_ . " is fucked up!\n";
                    print "[!] Possibly spoofed: " . $domain . "\n";
                    print "[!] " . $ip_legit_whoisname . " != " . $second_whoisname . "\n";
                    print "[!] http://whois.domaintools.com/" . $ip_legit . "\n";
                    print "[!] http://whois.domaintools.com/" . $ip_compare . "\n\n";
                }
                else {
                    print "[OK] This " . $_ . " sounds good.\n\n";
                }
            }
            else {
                print "[OK] This " . $_ . " sounds good.\n\n";
            }
        }
    }

sub dns_query {
    my ( $aref, $domain, $timeout ) = @_;

    my $res = Net::DNS::Resolver->new(
        nameservers => $aref,
        recurse     => 1,
    );

    my $error;
    my $ip_addr;
    my $bgsock = $res->bgsend( $domain, 'A' );
    my $sel    = IO::Select->new($bgsock);
    my @ready  = $sel->can_read($timeout);

    if (@ready) {
        my $packet = $res->bgread($bgsock);
        my ($answer) = $packet->answer;

        if ($answer->type eq "CNAME") {
            ($ip_addr) = dns_query( \@dns, $answer->cname, $timeout );
                        print $answer->cname."\n";
        }
        else {
            $ip_addr = $answer->address;
        }
    }
    else {
        $error = "1";
    }

    return ( $ip_addr, $error );
}

sub whois {
    my $addr     = shift;
    my $response = whoisip_query($addr);
    my $whoisname =
         $response->{OrgName}
      || $response->{NetName}
      || $response->{netname}
      || $response->{orgname}
      || $response->{descr}
      || $response->{owner};

    return ($whoisname);
}

__DATA__
93.91.146.150
85.13.106.14
46.29.230.145
213.168.191.194
217.196.212.162
195.250.146.67
213.216.46.38
91.220.122.217
77.48.209.165
213.226.197.43
93.99.247.7
90.182.75.79
188.75.185.1
91.139.3.69
77.237.149.240
193.85.149.243
213.226.232.203
77.237.152.239
95.168.194.244
88.86.106.35
62.141.29.50
193.107.252.152
178.77.228.143
93.89.101.250
178.248.57.80
93.91.51.136
178.77.228.51
193.179.179.64
109.235.7.47
213.226.197.5
195.250.149.18
