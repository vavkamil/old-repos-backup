#!/usr/bin/perl
#
# DNS check
# Hijacking expired subdomains
#

use strict;
use warnings;

use Net::DNS;
use Net::Ping;
use Try::Tiny;
use Getopt::Long;
use Time::Out qw(timeout);

# Command line options
my $help;
my $version;
my $version_num = 'version 0.1 Alpha';
my $opt_domain;
my $opt_file;
my $opt_result;
my $backup = "0";

my $options = GetOptions(
    "help"    => \$help,
    "version" => \$version,
    "domain"  => \$opt_domain,
    "file"    => \$opt_file,
    "result"  => \$opt_result    # TODO
);

my ( $target, $result ) = @ARGV;

show_header();

help() if $help;
quit($version_num) if $version;

start_scan();

sub start_scan {
	if ( not defined( $opt_domain or $opt_file ) ) {
		print "Usage: perl $0 -domain github.com\n";
		print "Usage: perl $0 -file axfr.txt\n";
		die "Usage: perl $0 -help\n\n";
	}
	if ( defined( $opt_domain and $target ) ) {
		scan_domain($target);
	}
	elsif ( defined( $opt_file and $target ) ) {
		open (F, $target) || die "Could not open $ARGV[0]: $!\n";
		my @f = <F>;
		close F;

		foreach my $dom (@f) {
			chomp($dom);
			scan_domain($dom);
		}
	}
}

sub scan_domain {
	my ($dom) = @_;

	my @ns;
	my @subdomains;
	my @cname_domains;

	print "\n[i] Checking ".$dom." for subdomain hijacking\n";

	my $res = Net::DNS::Resolver->new;
	# dns object
	my $query = $res->query($dom,"NS");
	# query method call for nameservers
	if($query) {
		# query of NS was successful
		foreach my $rr (grep{$_->type eq 'NS'} $query->answer) {
			push (@ns, $rr->nsdname);
		}
		print "[i] Found ".scalar(@ns)." nameservers\n";

		print "[i] Trying zone transfer:\n";

		foreach my $ns (@ns) {
			try {
        		$res->nameservers($ns);
			} catch {
        		# warn "caught NS error: ".$dom;
			};

			# set the name server
			my @subs = timeout 2 => sub {
				try {
        			return $res->axfr($dom);
				} catch {
        			# warn "caught axfr error: ".$dom;
				};
			};
			if ($#subs > 0) {
				print "\t[NS] ".$ns." ~ OK\n";
				push(@subdomains, @subs);
			}
			else {
				print "\t[NS] ".$ns." ~ Failed\n";
			}
		}
		if (scalar @subdomains > 0) {
			my @filtered = uniq(@subdomains);
			print "[i] Found ".scalar(@filtered)." subdomains\n";
			print "[i] Checking CNAME records\n";
			foreach my $subdomain (@filtered) {
				if ($subdomain->type eq 'CNAME') {
					my @cname_domain = split(/\./, $subdomain->cname);
					my $cname_tld = pop(@cname_domain); #org
					my $cname_baredomain = pop(@cname_domain); #zoelife4u
					my $cname_domain = $cname_baredomain.".".$cname_tld;
					if ($cname_domain ne $dom) {
						push(@cname_domains, $cname_domain);
					}
				}
			}
			my @cname_filtered = uniq2(@cname_domains);
			print "[i] Found ".scalar(@cname_filtered)." unique CNAME domains\n";
			print "[i] Checking whois records\n";
			foreach my $check_domain (@cname_filtered) {
				if (`whois $check_domain` =~ "No match for") {
					foreach my $subdomain (@filtered) {
						if (($subdomain->type eq 'CNAME') and ($subdomain->cname eq $check_domain)) {
							print "[!] Found expired domain\n";
							print "\t[x] ".$subdomain->name." > CNAME > ".$check_domain."\n";
							print "\t[x] ".$check_domain." is expired!\n\n";
							select(undef, undef, undef, 0.5); # Sleep for 500 milliseconds
						}
					}
				}
			}
		}
		else {
			print "[i] No subdomains :(\n";
		}
	}
	else {
		# Something went wrong:
		warn "[q] query failed: ", $res->errorstring,"\n";
	}
}

sub show_header {
	system("clear");
    print <<EndHead;
            _     _   _ _  _            _     
  ___ _   _| |__ | | | (_)(_) __ _  ___| | __ 
 / __| | | | '_ \\| |_| | || |/ _` |/ __| |/ / 
 \\__ \\ |_| | |_) |  _  | || | (_| | (__|   <  
 |___/\\__,_|_.__/|_| |_|_|/ |\\__,_|\\___|_|\\_\\ 
                        |__/                  

EndHead
}

sub help {
    print <<EOHELP;
subHijack.pl at https://github.com/vavkamil/subHijack
	Usage: perl $0 -domain github.com
	Usage: perl $0 -file axfr.txt
Overview:
	Hijacking forgotten & misconfigured subdomains
Options:
	-domain     	Single domain input.
	-file		File with domains.
	-output		Output file.
	-version    	Print current version.
	-help       	This help message.
EOHELP
    exit;
}

sub uniq {
    my %seen;
    grep !$seen{$_->name}++, @_;
}
sub uniq2 {
    my %seen;
    grep !$seen{$_}++, @_;
}

sub quit {
    my ($text) = @_;
    print "$text\n\n";
    exit;
}