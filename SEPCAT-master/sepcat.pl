#!/usr/bin/perl

# [SEPCAT] Static Exploitable PHP Code Analysis Tool
# Version: 0.5
#
# https://github.com/vavkamil/SEPCAT

# Functionality based on DevBug (http://devbug.co.uk)
# DevBug is a basic PHP Static Code Analysis tool written mostly in JavaScript.
#
# DevBug was created by Ryan Dewhurst (www.dewhurstsecurity.com)
# as part of his undergraduate university thesis.

use strict;
use warnings;
use Getopt::Long;
use File::Basename;
use File::Find::Rule;

# Command line options
my $help;
my $version;
my $version_num = 'version 0.5 Alpha';
my $opt_folder;
my $opt_file;
my $opt_result;
my $backup = "0";

my $options = GetOptions(
    "help"    => \$help,
    "version" => \$version,
    "folder"  => \$opt_folder,
    "file"    => \$opt_file,
    "result"  => \$opt_result    # TODO
);

my ( $target, $result ) = @ARGV;
my $tokenSeperator = "<:::>";    # the token name/value seperator

# Arrays bellow declares all the possible sources, sinks and securing functions.
# All of this data originated from RIPS v0.51 http://sourceforge.net/projects/rips-scanner/
#
# Sources of tainted variables
my @tainted_variables = ( '$_GET', '$_POST', '$_COOKIE', '$_REQUEST', '$_FILES', '$_SERVER',
    '$_ENV', '$HTTP_GET_VARS', '$HTTP_POST_VARS', '$HTTP_COOKIE_VARS', '$HTTP_REQUEST_VARS',
    '$HTTP_POST_FILES', '$HTTP_SERVER_VARS', '$HTTP_ENV_VARS', 'HTTP_RAW_POST_DATA', 'argc',
    'argv' );
my $tainted_variables = "\\" . join "|\\", @tainted_variables;

# Potential Vulnerable Functions
my @XSS = ( "echo", "print", "exit", "die", "printf", "vprintf" );
my $XSS = join "|", @XSS;

my @fileInclude = ( "include", "include_once", "php_check_syntax", "require", "require_once",
    "runkit_import", "set_cinlude_path", "virtual" );
my $fileInclude = join "|", @fileInclude;

my @sqlInjection = ( "dba_open", "dba_popen", "dba_insert", "dba_fetch", "dba_delete",
	"dbx_query", "odbc_do", "odbc_exec", "odbc_execute", "db2_exec", "db2_execute",
	"fbsql_db_query", "fbsql_query", "ibase_query", "ibase_execute", "ifx_query", "ifx_do",
	"ingres_query", "ingres_execute", "ingres_unbuffered_query", "msql_db_query", "msql_query",
	"msql", "mssql_query", "mssql_execute", "mysql_db_query", "mysql_query",
	"mysql_unbuffered_query", "mysqli_stmt_execute", "mysqli_query", "mysqli_real_query",
	"mysqli_master_query", "oci_execute", "ociexecute", "ovrimos_exec", "ovrimos_execute",
	"ora_do", "ora_exec", "pg_query", "pg_send_query", "pg_send_query_params", "pg_send_prepare",
	"pg_prepare", "sqlite_open", "sqlite_popen", "sqlite_array_query", "arrayQuery", "singleQuery",
	"sqlite_query", "sqlite_exec", "sqlite_single_query", "sqlite_unbuffered_query", "sybase_query",
	"sybase_unbuffered_query" );
my $sqlInjection = join "|", @sqlInjection;

# Secured Functions
my @securingXSS = ( "esc_attr", "esc_url", "htmlentities", "htmlspecialchars" );
my $securingXSS = '(?:' . ( join "|", @securingXSS ) . ')';

help() if $help;
quit($version_num) if $version;

BEGIN {
    print "\n[SEPCAT] Static Exploitable PHP Code Analysis Tool\n";
}

start_scan();

END {
    quit("[+] Thank you for using SEPCAT, ".$version_num);
}

sub start_scan {
    if ( not defined( $opt_folder or $opt_file ) ) {

        # Usage: perl $0 -folder /var/www/wp_plugins/ -result wp_plugins.txt
        die "Usage: perl $0 -folder /var/www/wp_plugins/\n\n";
    }
    if ( defined( $opt_result and $result ) ) {
        $backup = "1";
    }
    if ( defined( $opt_folder and $target ) ) {
        my @files = scan_folder($target);   # Scan folder for .php files
        php_tokenizer(@files);              # Get PHP tokens from source code
    }
    elsif ( defined( $opt_file and $target ) ) {
        my @files = scan_file($target);     # Scan single .php file
        php_tokenizer(@files);              # Get PHP tokens from source code
    }
}

sub scan_folder {
    my ($target) = @_;
    quit( "Target " . $target . " is not a folder." ) if ( not -d $target );
    print "[+] Scanning folder: " . $target . "\n\n";

    # my @files = File::Find::Rule->file()->name('*.php')->grep(qr/($tainted_variables)/)->in($target);
    my @files = File::Find::Rule->file()->name('*.php')->in($target);
    return @files;
}

sub scan_file {
    my ($target) = @_;
    quit( "Target " . $target . " is not a file." ) if ( not -f $target );
    print "[+] Scanning file: " . $target . "\n";
    ( $target, my $filepath ) = fileparse($target);
    if ( $filepath eq "./" ) { $filepath = "." }
    my @files = File::Find::Rule->file()->name($target)->in($filepath);
    return @files;
}

sub php_tokenizer {
    my (@files) = @_;
    my ( $file, $filepath );
    foreach (@files) {
        my $i          = 0;
        my $InsideCode = 0;
        ( $file, $filepath ) = fileparse($_);
        my @tokens;
        push( @tokens, "$filepath$file<:::>\n" );
        if ( $filepath eq "./" ) { $filepath = "." }
        open( my $fh, "<", $_ ) or die "Failed to open file: $!\n";

        while (<$fh>) {

            my @Data = split( "\n", $_ );

            #  OK, go through the remaining line fragments.
            $i++;
            foreach (@Data) {
                $_ =~ s/^\s*//;			# Remove any white space characters
                next if (/^\s*$/);		# Skip blank lines
                next if (/^\/\/.*$/);	# Skip // comments

                #  If we're inside an opening block, watch for the
                #  closing block.

                if ( $InsideCode == 1 ) {
                    if (/^(.*)\?>/) {

                        #print "T_CLOSE_TAG<:::>?><:::>" . $i . "\n";
                        push( @tokens, "T_CLOSE_TAG<:::>$_<:::>$i\n" );
                        $InsideCode = 0;
                    }
                    else {

                        my $reg_T_VARIABLE                 = '\$\w+';
                        my $reg_T_NOTOKEN                  = '=|;|\[|\]|\(|\)';
                        my $reg_T_CONSTANT_ENCAPSED_STRING = '\'[^\']*\'';
                        my $reg_T_ECHO                     = 'echo';
                        my $reg_T_PRINT                    = '\bprint\b';
                        my $reg_T_EXIT                     = '\bexit\b|\bdie\b';
                        my $reg_T_INCLUDE                  = '\binclude\b';
                        my $reg_T_INCLUDE_ONCE             = '\binclude_once\b';
                        my $reg_T_REQUIRE                  = '\brequire\b';
                        my $reg_T_REQUIRE_ONCE             = '\brequire_once\b';
                        my $reg_T_STRING                   = '\bprintf\b|\bvprintf\b|\bphp_check_syntax\b|' .
                                                             '\brunkit_import\b|\bset_cinlude_path\b|\bvirtual\b';
                        my $reg_all_tokens                 = $reg_T_VARIABLE                 . "|" .
                                                             $reg_T_NOTOKEN                  . "|" .
                                                             $reg_T_CONSTANT_ENCAPSED_STRING . "|" .
                                                             $reg_T_ECHO                     . "|" .
                                                             $reg_T_PRINT                    . "|" .
                                                             $reg_T_EXIT                     . "|" .
                                                             $reg_T_INCLUDE                  . "|" .
                                                             $reg_T_INCLUDE_ONCE             . "|" .
                                                             $reg_T_REQUIRE                  . "|" .
                                                             $reg_T_REQUIRE_ONCE             . "|" .
                                                             $reg_T_STRING;
                        my @raw_php                        = split( "\n", $_ );

                        foreach my $raw_line (@raw_php) {

                            my @matches;
                            my $token;
                            if ( @matches = $raw_line =~ /($reg_all_tokens|$securingXSS|$sqlInjection)/g ) {
                                foreach my $match (@matches) {
                                    if ( ($token) = $match =~ /($reg_T_VARIABLE)/g ) {
                                        push( @tokens, "T_VARIABLE<:::>$token<:::>$i" );
                                    }
                                    elsif ( ($token) = $match =~ /($reg_T_NOTOKEN)/g ) {
                                        push( @tokens, "T_NOTOKEN<:::>$token<:::>$i" );
                                    }
                                    elsif ( ($token) = $match =~ /($reg_T_ECHO)/g ) {
                                        push( @tokens, "T_ECHO<:::>$token<:::>$i" );
                                    }
                                    elsif ( ($token) = $match =~ /($reg_T_PRINT)/g ) {
                                        push( @tokens, "T_PRINT<:::>$token<:::>$i" );
                                    }
                                    elsif ( ($token) = $match =~ /($reg_T_EXIT)/g ) {
                                        push( @tokens, "T_EXIT<:::>$token<:::>$i" );
                                    }
                                    elsif ( ($token) = $match =~ /($reg_T_INCLUDE)/g ) {
                                        push( @tokens, "T_INCLUDE<:::>$token<:::>$i" );
                                    }
                                    elsif ( ($token) = $match =~ /($reg_T_CONSTANT_ENCAPSED_STRING)/g ) {
                                        push( @tokens, "T_CONSTANT_ENCAPSED_STRING<:::>$token<:::>$i" );
                                    }
                                    elsif ( ($token) = $match =~ /$securingXSS|$reg_T_STRING|$sqlInjection/g ) {
                                        push( @tokens, "T_STRING<:::>$token<:::>$i" );
                                    }
                                }
                            }
                        }
                    }
                }
                else {

                    #  Otherwise watch for the opening block.

                    if (/<\?php(.*)\?>/) {

                        # print "$1";
                    }
                    elsif (/<\?php(.*)$/) {

                        #print "T_OPEN_TAG<:::><?php<:::>" . $i . "\n";
                        push( @tokens, "T_OPEN_TAG<:::>$_<:::>$i" );
                        $InsideCode = 1;
                    }
                    else {
                        #print "T_INLINE_HTML<:::>" . $_ . "<:::>" . $i . "\n";
                        push( @tokens, "T_INLINE_HTML<:::>$_<:::>$i" );
                    }
                }
            }
        }
        close $fh;
        codeAnalysis(@tokens, $filepath.$file);  # Check variables for user input sources
    }
}

sub codeAnalysis {
    my ( @tokens ) = @_;
    my @tainted;    # the array that will keep track of tainted variables
    foreach my $tokenCount ( 0 .. $#tokens - 1 ) {
        my @splitToken = split( $tokenSeperator, $tokens[$tokenCount] );
        my $TokenName  = $splitToken[0];
        my $TokenValue = $splitToken[1];
        my $TokenLine  = $splitToken[2];

        my @splitNextToken = split( $tokenSeperator, $tokens[ $tokenCount + 1 ] );
        my $nextTokenName  = $splitNextToken[0];
        my $nextTokenValue = $splitNextToken[1];
        my $nextTokenLine  = $splitNextToken[2];

        # Sources: User Input.
        # if variable assignment
        if ( ( $TokenName eq "T_VARIABLE" ) and ( $nextTokenName eq "T_NOTOKEN" ) and ( $nextTokenValue eq "=" ) ) {

            my @splitVarToken = split( $tokenSeperator, $tokens[ $tokenCount + 2 ] );
            my $varTokenName  = $splitVarToken[0];
            my $varTokenValue = $splitVarToken[1];
            if ( ( $varTokenName eq "T_VARIABLE" ) and ( $varTokenValue =~ /$tainted_variables/ ) ) {
                push( @tainted, $TokenValue );
            }
        }
    }
    unsecured( \@tainted, \@tokens );   # Is variable unsecured?
}

sub unsecured {
    my ( $tainted, $tokens ) = @_;
    my @secured;
    my @unsecured;
    my $secured;
    foreach my $tainted_var (@$tainted) {

        #print $tainted_var;
        foreach my $token ( 0 .. $#$tokens - 1 ) {
            my @splitToken = split( $tokenSeperator, $tokens->[$token] );
            my $TokenName  = $splitToken[0];
            my $TokenValue = $splitToken[1];
            my $TokenLine  = $splitToken[2];

            #print $TokenName." - ".$TokenValue."\n";

            my @splitNextToken = split( $tokenSeperator, $tokens->[ $token + 1 ] );
            my $nextTokenName  = $splitNextToken[0];
            my $nextTokenValue = $splitNextToken[1];
            my $nextTokenLine  = $splitNextToken[2];

            if ( ( $TokenValue eq $tainted_var ) and ( $nextTokenValue eq "=" ) ) {
                my @splitVarToken = split( $tokenSeperator, $tokens->[ $token + 2 ] );
                my $varTokenName  = $splitVarToken[0];
                my $varTokenValue = $splitVarToken[1];
                my $varTokenLine  = $splitVarToken[1];
                if ( $varTokenValue =~ /$securingXSS/ ) {
                    #print $TokenValue." - ".$varTokenValue." is secured.\n";
                    push( @secured, $TokenValue );
                }
            }
        }
    }
    if ( @secured == 0 ) {
        $secured = "(null)";
    }
    else {
        $secured = "(\\" . ( join "|\\", @secured ) . ")";
    }
    foreach my $tainted_var (@$tainted) {
        if ( $tainted_var !~ /$secured/ ) {
            push( @unsecured, $tainted_var );
        }
    }
    vulnerable( \@unsecured, \@$tokens );   # See if vars end up in sensitive sinks
}

sub vulnerable {
    my ( $unsecured, $tokens ) = @_;
    my $file = $tokens->[0];
    chomp ($file) && $file =~ s/<:::>//;
    my $XSS_sink;
    my $XSS_line = "0";
    my $fileInclude_sink;
    my $fileInclude_line = "0";
    my $sqlInjection_sink;
    my $sqlInjection_line = "0";
    foreach my $variable (@$unsecured) {
        # print $variable."\n";
        foreach my $token ( 0 .. $#$tokens - 1 ) {
            my @splitToken = split( $tokenSeperator, $tokens->[$token] );
            my $TokenName  = $splitToken[0];
            my $TokenValue = $splitToken[1];
            my $TokenLine  = $splitToken[2];

            # print $TokenName." - ".$TokenValue."\n";
            if ( $TokenValue =~ /$XSS/ ) {
                $XSS_sink = $TokenValue;
                $XSS_line = $TokenLine;
            }
            if ( ( $TokenValue eq $variable ) and ( $TokenLine eq $XSS_line ) ) {
                if ( $backup eq "1" ) {
                    backup($result, "[+] Vulnerable file: $file\n");
                    backup($result, "[-] Line " . $TokenLine .
                    ": Cross-Site Scripting (XSS) in '" .
                    $XSS_sink . "' via '" . $TokenValue . "'\n\n");
                }
                else {
                    print "[+] Vulnerable file: $file\n";
                    print "[-] Line " . $TokenLine .
                    ": Cross-Site Scripting (XSS) in '" .
                    $XSS_sink . "' via '" . $TokenValue . "'\n\n";
                }
            }
            if ( $TokenValue =~ /$fileInclude/ ) {
                $fileInclude_sink = $TokenValue;
                $fileInclude_line = $TokenLine;
            }
            if ( ( $TokenValue eq $variable ) and ( $TokenLine eq $fileInclude_line ) ) {
                if ( $backup eq "1" ) {
                    backup($result, "[+] Vulnerable file: $file\n");
                    backup($result, "[-] Line " . $TokenLine .
                    ": PHP File Inclusion in '" .
                    $fileInclude_sink . "' via '" . $TokenValue . "'\n\n");
                }
                else {
                    print "[+] Vulnerable file: $file\n";
                    print "[-] Line " . $TokenLine .
                    ": PHP File Inclusion in '" .
                    $fileInclude_sink . "' via '" . $TokenValue . "'\n\n";
                }
            }
            if ( $TokenValue =~ /$sqlInjection/ ) {
                $sqlInjection_sink = $TokenValue;
                $sqlInjection_line = $TokenLine;
            }
            if ( ( $TokenValue eq $variable ) and ( $TokenLine eq $sqlInjection_line ) ) {
                if ( $backup eq "1" ) {
                    backup($result, "[+] Vulnerable file: $file\n");
                    backup($result, "[-] Line " . $TokenLine .
                    ": SQL Injection in '" .
                    $sqlInjection_sink . "' via '" . $TokenValue . "'\n\n");
                }
                else {
                    print "[+] Vulnerable file: $file\n";
                    print "[-] Line " . $TokenLine .
                    ": SQL Injection in '" .
                    $sqlInjection_sink . "' via '" . $TokenValue . "'\n\n";
                }
            }
        }
    }
}

sub backup {
    my ( $result, $log )    = @_;
    open( my $fh, ">>", "$result" ) or die "$result: $!";
    print $fh "$log";
    close($fh);
}

sub quit {
    my ($text) = @_;
    print "$text\n\n";
    exit;
}

sub help {
    print <<EOHELP;

sepcat.pl at https://github.com/vavkamil/SEPCAT
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

EOHELP
    exit;
}