#!/usr/bin/perl
#######################################################################
# Created on:  01/06/08
# File:        dnsview.pl
# Version:	   0.1
# Description: Reads pcap file (offline) to conduct both header and
# packet analysis.  Initially written for DNS packet captures but can
# be applied to all types.
#
# @author(s) labgeek@gmail.com
#
######################################################

use strict;
use warnings;
use Net::Pcap;
use File::Find;
use File::Basename;
use NetPacket::IP;
use POSIX qw(strftime);
use NetPacket::TCP;
use NetPacket::UDP;
use NetPacket::Ethernet;
use NetPacket::ICMP;
use Getopt::Std;

# DNS port
use constant DNS_PORT => 53;
my ( $pcapfiles, $gzfiles, $corruptfiles, $sigfileread, $PacketsProcessed,
	$dnspackets )
  = 0;
my $sigfile    = "headersig\.txt";
my $configfile = "searchterms.txt";
my @termlist   = ();
my (
	$pcap, $err, $result, $net, $mask, $filter, $s,   $s1,
	$d,    $d1,  $src,    $dst, $pair, $num,    $two, $key
  )
  = "";
my ( %sigs, %opt, %sources, %dests, %toptalkers, @spair, %h1 ) = ();
my %conf = readconfig($configfile);

foreach $key ( sort keys %conf ) {
	print "$key";
}

# command-line functionality
getopts( "hd:", \%opt );

# bomb
unless ( $opt{d} ) {
	printUsage();
}
if ( $opt{h} ) {
	printUsage();
}

# lets throw in a signal catcher if we want to stop the perl script
# midway, it then calls givemestats()
$SIG{'INT'} = \&givemestats;

# make sure our directory is defined
if ( defined $opt{d} ) {

	# read in configuration file (contains list of term we will be using)
	#	@termlist = readconfig($configfile);
	if ( -e $sigfile ) {
		if ( readsigfile($sigfile) ) {
			print "Signature file sucessfully read.\n";
			$sigfileread = 1;
			foreach ( keys %sigs ) {
				my @list = @{ $sigs{$_} };
			}
		}
	}
	else {
		print "Signature file not read\n";
	}

	# using find for recursion into lower levels of directories
	# goes as far as *nix will allow it, 255 directories
	find( \&search, $opt{d} );

	# Test
	printf "%-30s\t%s\n", "Total valid pcap files",  $pcapfiles;
	printf "%-30s\t%s\n", "Total GZIPPED files",     $gzfiles;
	printf "%-30s\t%s\n", "Total corrupted files",   $corruptfiles;
	printf "%-30s\t%s\n", "Total packets processed", $PacketsProcessed;
	printf "%-30s\t%s\n", "DNS packets processed",   $dnspackets;
	&givemestats;
}

# packet capture descriptor $pcap, loop forever and call process_pkt
#  The header information is a reference to a hash containing the following fields.
#    * len - the total length of the packet.
#    * caplen - the actual captured length of the packet data. This corresponds to the snapshot length parameter passed to open_live().
#    * tv_sec - seconds value of the packet timestamp.
#    * tv_usec - microseconds value of the packet timestamp.
sub process_pkt {
	my ( $UserData, $Hdr, $Pkt ) = @_;
	my $EthObj = NetPacket::Ethernet->decode($Pkt);
	my $IPObj  = NetPacket::IP->decode( $EthObj->{data} );

	# add in loop for udp searching here (for terms)
	if ( $IPObj->{proto} == 17 ) {    #UDP
		my $UDPObj  = NetPacket::UDP->decode( $IPObj->{data} );
		my $Payload = $UDPObj->{data};
		if ( $UDPObj->{dest_port} == DNS_PORT ) {
			my $timestamp =
			  strftime( "%Y-%m-%d %H:%M:%S", gmtime( $Hdr->{'tv_sec'} ) );
			foreach $key ( sort keys %conf ) {
				chomp($key);
				if ( $Payload =~ /$key/ ) {
					open( FILE, ">>/tmp/output/$key" );
					print FILE
"$IPObj->{src_ip},$UDPObj->{src_port},$IPObj->{dest_ip},$UDPObj->{dest_port},$UDPObj->{len}, $timestamp\n";
					close(FILE);
					$dnspackets++;
				}
			}
		}
	}
	else {    #Generic packets, do nothing
	}
	$PacketsProcessed++;
}

# Function:  search:  goes through each directory looking for a certain filetype.
# After it finds the file, it tests the file to see if it is in the headersig.txt
# file.  But for our use today, we will only be looking for all tcpdump, gzipped,
# or "bad" signature files.  After it determines if it is a tcpdump file, runs a comparison
# of search terms, same goes for the gzipped file (but uses zcat piped to tcpdump -r)
sub search {
	my $fpath = $File::Find::name;
	my $fname = basename($fpath);

	# hard-coded for now but can be passed in via command line later
	if ( $fname =~ /log*/ ) {
		my ( $hex, $resp ) = getsig($fpath);
		my $match = 0;

		# looping through parsed headersig file
		foreach my $key ( keys %sigs ) {

			# check to see if we match the hex value of the file with the hex
			# value found in the headersig file
			if ( $hex =~ m/^$key/ ) {

				# good, match, lets see if its a valid tcpdump file
				if ( grep( /pcap/i, @{ $sigs{$key} } ) ) {
					$pcapfiles++;
					print "PCAP-$fpath...\n";
					$pcap = Net::Pcap::open_offline( $fpath, \$err )
					  || die("$err");
					Net::Pcap::loop( $pcap, -1, \&process_pkt, 0 );
					$match = 1;
				}

			   # do we match a .gz file?  We are assuming that when the .gz file
			   # is unzipped, it is a valid pcap file, I need to add this in
			   # as a secondary check later.
				if ( grep( /gz/i, @{ $sigs{$key} } ) ) {
					$gzfiles++;
					print "GZ-$fpath($hex) = @{$sigs{$key}}\n";
					$match = 1;
				}
			}
		}

		# lets find those ones that did not match our list
		if ( $match == 0 ) {
			$corruptfiles++;
			print "File signature not listed - $fpath\n";
		}
	}
}

# function to print out stats based on packets processed
# signal handler function so if an interrupt is called, will print
# out stats up to that point.
sub givemestats {
	print "\nSTATISTICS\n";
	print "Source IP Addresses:\n";
	foreach my $ip (
		( sort { $sources{$b} <=> $sources{$a} } keys %sources )[ 0 .. 19 ] )
	{
		printf "%-20s\t%s\n", $ip, $sources{$ip};
	}
	print "\nDestination IP Addresses:\n";
	foreach
	  my $ip ( ( sort { $dests{$b} <=> $dests{$a} } keys %dests )[ 0 .. 19 ] )
	{
		printf "%-20s\t%s\n", $ip, $dests{$ip};
	}
	print "\nMost Frequent Talkers\n";
	foreach $src ( keys %toptalkers ) {
		foreach $dst ( keys %{ $toptalkers{$src} } ) {
			push( @spair, "$src:$dst:$toptalkers{$src}{$dst}" );
		}
	}
	foreach my $pair (@spair) {
		( $s, $d, $num ) = split( ':', $pair );
		$two = "$s:$d";
		$h1{$two} = $num;
	}
	foreach ( ( sort { $h1{$b} <=> $h1{$a} } keys(%h1) )[ 0 .. 19 ] ) {
		( $s1, $d1 ) = split( ':', $_ );
		printf "%-20s\t%-20s\t%s\n", $s1, $d1, $h1{$_};
	}
	Net::Pcap::close($pcap);
	exit(0);
}

# reads in list of terms we want to search for...assuming we will have a huge list here
sub readconfig {
	my $configfilename = shift;
	my %conf           = ();
	my @termlist       = ();
	my ( $keyword, $arg1 );
	if ( -e $configfilename ) {
		open( FH, $configfilename )
		  || die " Could not open $configfilename : $! \n ";
		while ( my $terms = <FH> ) {

			# skip lines that begin w/ # or are blank
			next if ( $terms =~ m/^#/ || $terms =~ m/^\s+$/ );
			$conf{$terms} = 1;
		}
	}

	# lets return our list of search terms back
	return %conf;
}

# gets the extension of a passed in filename
sub getext {
	my $file = shift;
	my $ext;
	my @filelist = split( /\./, $file );
	( @filelist > 1 )
	  ? ( $ext = $filelist[ @filelist - 1 ] )
	  : ( $ext = " none " );
	return $ext;
}

# reads the header signature file and parses out the file into three parts
sub readsigfile {
	my $file = shift;
	if ( -e $file ) {
		open( FH, $file ) || die " Could not open $file : $! \n ";
		while (<FH>) {

			# skip lines that begin w/ # or are blank
			next if ( $_ =~ m/^#/ || $_ =~ m/^\s+$/ );
			chomp;
			my ( $sig, $tag ) = ( split( /,/, $_, 3 ) )[ 0, 1 ];
			my @list = split( /;/, $tag );    # split on ";
			foreach (@list) {
				$_ =~ s/\s//;                 #remove space
				$_ =~ s/\.//;                 # remove period
			}

			$sigs{$sig} = [@list];
		}
		close(FH);
		return 1;
	}
	else {
		return undef;
	}
}

# simple USAGE routine
sub printUsage {
	print " Usage: \tdnsview.pl
		  [d] <location of tcpdump directory> -
		  [o] <output directory> \n ";
	print "\tDate: 01/06/08- <labgeek\@gmail.com> \n ";
	print "\nOptions : \n ";
	print "\t-h - print help (optional) \n ";
	print "\t -d - directory \n ";
	print "\t -o - output directory\n";
	exit;
}

# gets the first 20 bytes of the binary header
# returns the hex and whether or not it was a success or not (0 or 1)
sub getsig {
	my $file    = shift;
	my $success = 0;
	my $hex;
	eval {
		if ( open( FH, $file ) )
		{
			binmode(FH);
			my $bin;
			sysread( FH, $bin, 20 );
			close(FH);
			$hex = uc( unpack( "H*", $bin ) );
			$success = 1;
		}
	};
	return ( $hex, $success );
}
__END__



					#					$sources{ $IPObj->{src_ip} }++;
					#					$dests{ $IPObj->{dest_ip} }++;
					#					$toptalkers{ $IPObj->{src_ip} }
					#					  { $IPObj->{dest_ip} }++;