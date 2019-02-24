#!/usr/bin/perl
#

use strict;
use warnings;

use URI;
use utf8;
use JSON qw//;
use File::Slurp;
use Getopt::Long;
use File::Basename;
use WWW::Mechanize;
use List::Util 'first';

$|=1; #autoflush
my %extension_hash;
my $i             = 0;  # Number of current line
my $nlines        = 0;  # Number of lines in wordlist file
my $oklist        = 0;  # Number of affected extensions

# Command line options
my $help;
my $version;
my $version_num = 'version 0.1 Alpha';
my $opt_extensionlist;

my $options = GetOptions(
	"help"    => \$help,				# Help message
	"version" => \$version,				# Print current version (above)
	"e"       => \$opt_extensionlist	# Path to wordlist file
);

my ( $input ) = @ARGV;

help() if $help;
quit($version_num) if $version;

show_header();
start_scan();

sub start_scan {

	if ( not defined( $opt_extensionlist ) ) {
		die "Usage: perl $0 -e extensions.txt\n\n";
	}

	open (F, $input) || die "Could not open $ARGV[0]: $!\n";
	my @f = <F>;
	close F;
	$nlines = @f; # Number of lines in file

	print "[i] Extensions in the queue: ".$nlines."\n";


	foreach my $extension (@f) {
		chomp($extension);
		# print "Downloading extension: $extension\n";

		$i++;
		my $per = int(($i/$nlines)*100);
		print "\033[J[i] Completed status: ${per}%\033[G"; # man console_codes, ECMA-48 CSI sequences, "CHA"

		my $service			= "https://clients2.google.com/service/update2/crx";
		my $response		= "?response=redirect";
		my $prodversion		= "&prodversion=38.0";
		my $installsource	= "&x=id%3D".$extension."%26installsource%3Dondemand%26uc";
		my $url = $service.$response.$prodversion.$installsource;
		my $mech = WWW::Mechanize->new(autocheck => 0, agent => 'SecurityResearch');
		$mech->max_redirect(0);
		$mech->get($url);

		my $status = $mech->status();
		if (($status >= 300) && ($status < 400)) {
			my $location = $mech->response()->header('Location');
			my $file = basename($location);

			$file =~ s/extension/$extension/g;
			$file =~ s/.crx/.zip/g;
			my $local_file_name = $file;
			$mech->get( $location, ":content_file" => "./downloads/".$local_file_name );
			next if ($mech->status() == 404);
			# print "Downloaded: $local_file_name\n";

			# print "Extracted to $extension\n";
			system("unzip ./downloads/$local_file_name -d ./downloads/$extension >/dev/null 2>&1");

			if (-e "./downloads/".$extension."/manifest.json") { 
				# print "File Exists!";
			}
			else {
				delete_it($local_file_name, $extension);
				next;
			}
			my $text = read_file("./downloads/".$extension."/manifest.json");
			my $json = new JSON;
			my $data;

			eval {
				$data = JSON::decode_json($text);
				1;
			}
			or do {
				delete_it($local_file_name, $extension);
				next;
			};

			my $json_name						= $data->{'name'};
			my $json_version					= $data->{'version'};
			my $json_manifest_version			= $data->{'manifest_version'};
			my $json_web_accessible_resources	= $data->{'web_accessible_resources'};

			if (defined $json_web_accessible_resources) {

				if ($json_name =~ /__MSG_(.*?)__/) {
					my $json_default_locale = $data->{'default_locale'};
					my $locales_name = $1;

					my $filename = "./downloads/".$extension."/_locales/".$json_default_locale."/messages.json";
					if (-e $filename) {
						# print "File Exists!\n";
						my $locale = read_file("./downloads/".$extension."/_locales/".$json_default_locale."/messages.json");

						my $locale_data;

						eval {
							$locale_data = JSON::decode_json($locale);
							1;
						}
						or do {
							delete_it($local_file_name, $extension);
							next;
						};
						$json_name = $locale_data->{$locales_name}->{'message'};
					}
				}

				if (defined $json_name) {
					utf8::encode($json_name);
				}
				else {
					delete_it($local_file_name, $extension);
					next;
				}

				my $match;
				my $sink;
				
				if (!defined $match) {
					$match = first { /(?<![*]).png$/ } @{$data->{'web_accessible_resources'}};
					if (defined $match) { $sink = "img"; }
				}
				if (!defined $match) {
					$match = first { /(?<![*]).gif$/ } @{$data->{'web_accessible_resources'}};
					if (defined $match) { $sink = "img"; }
				}
				if (!defined $match) {
					$match = first { /(?<![*]).svg$/ } @{$data->{'web_accessible_resources'}};
					if (defined $match) { $sink = "img"; }
				}
				if (!defined $match) {
					$match = first { /(?<![*]).js$/ } @{$data->{'web_accessible_resources'}};
					if (defined $match) { $sink = "js"; }
				}
				if (!defined $match) {
					$match = first { /(?<![*]).css$/ } @{$data->{'web_accessible_resources'}};
					if (defined $match) { $sink = "css"; }
				}
				# if (!defined $match) {
				# 	$match = first { /(?<![*]).html$/ } @{$data->{'web_accessible_resources'}};
				# 	if (defined $match) { $sink = "html"; }
				# }
				if (!defined $match) {
					delete_it($local_file_name, $extension);
					next;
				}
				if( $match =~ /^\// ) { $match =~ s/^.//; }

				$extension_hash{$extension}{name}		= $json_name;
				$extension_hash{$extension}{version}	= $json_version;
				$extension_hash{$extension}{resource}	= $match;
				$extension_hash{$extension}{sink}		= $sink;
				$oklist++;
			}

			delete_it($local_file_name, $extension);
			# print "Deleted: $local_file_name\n";
			# print "Deleted: $extension\n";
		}
	}

	print "[i] Extensions in the output: ".$oklist."\n";
	my $extensions_json = JSON::encode_json(\%extension_hash);
	save($extensions_json);
}

sub show_header {

    print <<EndHead;

 __ .__ \\ / __.     version 0.1
/  `[__) X (__  _ _ __ __  _ __
\\__.|  \\/ \\.__)(_(_|| || |(/.|\\

EndHead
}

sub help {
    print <<EOHELP;
crxscanner.pl at https://github.com/vavkamil/CRXScanner
Usage: perl crxscanner.pl -e extensions.txt
Overview:
    Fingerprinting Chrome Extensions (manifest v2.0)
Options:
    -e          List of extensions.
    -version    Print current version.
    -help       This help message.
EOHELP
    exit;
}

sub save {
	my ($output)	= @_;
	open( my $fh, ">", "./crxscanner/addons.json" ) or die "Output: $!";
	print $fh "$output";
	close($fh);
	print "[i] Output saved to ./crxscanner/addons.json\n";
	print "[i] Results are in ./crxscanner/chrome-poc.html\n";
}

sub quit {
    my ($text) = @_;
    print "$text\n\n";
    exit;
}

sub delete_it {
	my ($local_file_name, $extension) = @_;
	unlink("./downloads/$local_file_name");
	system("rm -rf ./downloads/$extension >/dev/null 2>&1");
}