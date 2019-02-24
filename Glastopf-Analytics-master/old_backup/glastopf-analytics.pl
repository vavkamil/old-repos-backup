#!/usr/bin/perl

# Glastopf Analytics v1.0
# Author: Kamil Vavra (http://www.xexexe.cz)
# Credits to: 
# Thyrst' (https://www.github.com/Thyrst)
# Johannes Schroeter (http://devwerks.net/en/research/tools/)

use strict;
use warnings;

use DBI;
use Socket;
use Geo::IP;

my $dbname = "/opt/myhoneypot/db/glastopf.db";

my $dbh = DBI->connect(
    "dbi:SQLite:dbname=$dbname",
    { RaiseError => 1 }
) or die $DBI::errstr;

our @responses = (
    "* Show last 10 events:\n*\n",
    "* Show last 10 files:\n*\n",
    "* Show top 10 countries:\n*\n",
    "* Show top 10 user-agents:\n*\n",
    "* Show top 10 event patterns:\n*\n",
    "* Show top 10 requested filetypes:\n*\n",
    "* Show top 10 attackers:\n*\n",
    "* Show top 10 files:\n*\n",
    "* Delete IP address from events:\n*\n",
    "*  Kamil Vavra; www.xexexe.cz; vavkamil(at)gmail.com  *\n".
    "* * * * * * * * * * * * * * * * * * * * * * * * * * * *\n".
    "* You are awesome - thank you *\n".
    "* * * * * * * * * * * * * * * *\n\n"
);

our @functions = (
    sub { return last_ten_events() },
    sub { return last_ten_files() },
    sub { return top_ten_countries() },
    sub { return top_ten_agents() },
    sub { return top_ten_patterns() },
    sub { return top_ten_filetypes() },
    sub { return top_ten_attackers() },
    sub { return top_ten_files() },
    sub { return delete_events() },
    sub { exit(0); }
);

while(1) {
    header();
    print "* What to do?\n";
    print "*\n";
    print "* 1) Show last 10 events\n";
    print "* 2) Show last 10 files\n";
    print "* 3) Show top 10 countries\n";
    print "* 4) Show top 10 user-agents\n";
    print "* 5) Show top 10 event patterns\n";
    print "* 6) Show top 10 requested filetypes\n";
    print "* 7) Show top 10 attackers\n";
    print "* 8) Show top 10 files\n";
    print "* 9) Delete IP address from events\n";
    print "* 10) Exit\n*\n";

    print "* Enter number of your choice (1-10): ";
    chomp( my $input = <> );

    if ( $input-- !~ /\D/ && 0 <= $input && $input < scalar(@functions) ) {
        show($input);
    }
}

sub show {
    my $what = shift();

    header();
    print $responses[$what] if $responses[$what];
    
    $functions[$what]();
    press_any_key();
}

sub header {
    system("clear");
    print "* * * * * * * * * * * * * * * * * * * * * * * * * * * *\n";
    print "* Glastopf Analytics :: easy honeypot statistics v1.0 *\n";
    print "* * * * * * * * * * * * * * * * * * * * * * * * * * * *\n";
}

sub press_any_key {
    print "*\n* Press any key to continue.";
    <>;
}

sub last_ten_events {
    my $sth = $dbh->prepare("SELECT time, request_url, SUBSTR(source,-20,14) FROM events ORDER BY time DESC LIMIT 10");
    $sth->execute();

    while ( my @data = $sth->fetchrow_array() ) {
        my $time        = $data[0];
        my $request_url = $data[1];
        my $source_ip   = $data[2];
        my $gi          = Geo::IP->new(GEOIP_MEMORY_CACHE);
        my $country     = $gi->country_name_by_addr($source_ip);
        my $hostname  = gethostbyaddr( inet_aton($source_ip), AF_INET );
        if ( defined($hostname) ) {
            # TODO: rewrite this
        }
        else {
            $hostname = "Unknown";
        }
        if ( defined($country) ) {
            # TODO: rewrite this
        }
        else {
            $country = "Unknown";
        }
        printf( "* %-22s %-17s %-17.25s %-40s %s\n", $time, $source_ip, $country, $hostname, $request_url );
    }
    $sth->finish();
}

sub last_ten_files {
    my $sth = $dbh->prepare("SELECT time, filename FROM events WHERE filename is not null ORDER BY time DESC LIMIT 10");
    $sth->execute();

    while ( my @data = $sth->fetchrow_array() ) {
        my $time = $data[0];
        my $file = $data[1];
        printf( "* %-22s %s\n", $time, $file );
    }
    $sth->finish();
}

sub top_ten_countries {
    my $sth = $dbh->prepare("SELECT SUBSTR(source,-20,14) FROM events");
    $sth->execute();

    my %countries;
    while ( my @data = $sth->fetchrow_array() ) {
        my $source_ip = $data[0];
        my $gi        = Geo::IP->new(GEOIP_MEMORY_CACHE);
        my $country   = $gi->country_name_by_addr($source_ip);
        if ( defined($country) ) {
            $countries{$country}++;
        }
        else {
            $country = "Unknown";
            $countries{$country}++;
        }
    }
    $sth->finish();
    my $i = 0;
    foreach my $source_ip ( sort { $countries{$b} <=> $countries{$a}; } keys %countries ) {
        if ( $i == 10 ) { last(); }
        printf "* %6d %s\n", $countries{$source_ip}, $source_ip;
        $i++;
    }
}

sub top_ten_agents {
    my %seen = ();
    my $sth  = $dbh->prepare("SELECT request_raw FROM events");
    $sth->execute();

    while ( my @data = $sth->fetchrow_array() ) {
        my $request_raw = $data[0];
        if ( $request_raw =~ /User-Agent: (.*?)$/m ) {
            my $user_agent = $1;
            $seen{$user_agent}{count}++;
            $seen{$user_agent}{agent} = $user_agent;
        }
    }
    my $i = 0;
    for my $key ( sort { $seen{$b}->{count} <=> $seen{$a}->{count} } keys %seen ) {
        if ( $i == 10 ) { last(); }
        print "* $seen{$key}{count} events, $seen{$key}{agent}\n";
        $i++;
    }
    $sth->finish();
}

sub top_ten_patterns {
    my $sth = $dbh->prepare("SELECT count(pattern), pattern FROM events GROUP BY pattern ORDER BY count(pattern) DESC LIMIT 10");
    $sth->execute();

    while ( my @data = $sth->fetchrow_array() ) {
        my $count   = $data[0];
        my $pattern = $data[1];
        printf( "* %6d %s\n", $count, $pattern );
    }
    $sth->finish();
}

sub top_ten_filetypes {
    my $sth = $dbh->prepare("SELECT count, content FROM filetype ORDER BY count DESC LIMIT 10");
    $sth->execute();

    while ( my @data = $sth->fetchrow_array() ) {
        my $count    = $data[0];
        my $filetype = $data[1];
        printf( "* %6d %s\n", $count, $filetype );
    }
    $sth->finish();
}

sub top_ten_attackers {
    my $sth = $dbh->prepare("SELECT COUNT(source), SUBSTR(source,-20,14) AS stripped FROM events GROUP BY stripped ORDER BY COUNT(stripped) DESC LIMIT 10");
    $sth->execute();

    while ( my @data = $sth->fetchrow_array() ) {
        my $count    = $data[0];
        my $source_ip = $data[1];
        my $gi        = Geo::IP->new(GEOIP_MEMORY_CACHE);
        my $country   = $gi->country_name_by_addr($source_ip);
        my $hostname  = gethostbyaddr( inet_aton($source_ip), AF_INET );
        if ( defined($hostname) ) {
            # TODO: rewrite this
        }
        else {
            $hostname = "Unknown";
        }
        if ( defined($country) ) {
            # TODO: rewrite this
        }
        else {
            $country = "Unknown";
        }
        printf( "* %-05.10s %-17s %-17.25s %s\n", $count, $source_ip, $country, $hostname );
    }
    $sth->finish();
}

sub top_ten_files {
    my $sth = $dbh->prepare("SELECT filename, COUNT(filename) FROM events WHERE filename is not null GROUP BY filename ORDER BY COUNT(filename) DESC LIMIT 10");
    $sth->execute();

    while ( my @data = $sth->fetchrow_array() ) {
        my $file = $data[0];
        my $count = $data[1];
        printf( "* %6d %s\n", $count, $file );
    }
    $sth->finish();
}

sub delete_events {
	print "* Please enter source IP address: ";
	my $source_ip = <>;
	chomp ($source_ip);
    my $sth = $dbh->prepare("DELETE FROM events WHERE SUBSTR(source,-20,14) = '$source_ip'");
    $sth->execute();
    print "* IP $source_ip successfully deleted from events.\n";
    $sth->finish();
}

END {
    $dbh->disconnect() if $dbh;
}