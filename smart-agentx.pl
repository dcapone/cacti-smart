#!/usr/bin/env perl

use strict;
use NetSNMP::OID;
use NetSNMP::ASN (':all');
use NetSNMP::agent (':all');

my %cache = ();			# Cache
my @cache_oids = ();		# Keys, sorted
my $cache_updated = 0;
my $base = ".1.3.6.1.4.1.39178.100.10.1";

my $STORE = '/var/local/snmp';
my $PREFIX = 'smart-';
# how should we index/identify devices
my $INDEX = 'dev';
#my $INDEX = 'serial';


# Update cache

sub update_stats {

    return if time() - $cache_updated < 30;

    %cache = ();

	# run through current drives
	#opendir LS, "/dev" or die "FATAL - can't list /dev: $!\n";
	my @drives;
	#while ( defined ( my $drive = readdir LS ) ) {
	#	if ( $drive !~ /^sd[a-z]+$/ ) { next; }	# skip non drives
	#	push @drives, $drive
	#}
	#closedir LS;
	@drives = glob ( "$STORE/$PREFIX*" );
	@drives = map {local $_=$_; s/^.*\/smart-//; $_} @drives;

	my $devicecount = 0;
	foreach my $drive (sort @drives) {
		# deal with missing files
	#	if ( ! -f "$STORE/$PREFIX$drive" ) {
	#		print "NotVisible:$STORE/$PREFIX$drive\n";
	#		next;
	#	} elsif ( ! -r "$STORE/$PREFIX$drive" ) {
		#if ( ! -r "$STORE/$PREFIX$drive" ) {
		#	print "NotReadable:$STORE/$PREFIX$drive\n";
		#	next;
		#}
		# grab the parameter from the file
		if ( ! open DR, "$STORE/$PREFIX$drive" ) {
			print "$!:$STORE/$PREFIX$drive\n";
			next;
		}
		my $line;
		my $family;
		my $model;
		my $serial;
		my $firmware;
		my $capacity;
		my $oid = "$base.1.$devicecount.1";
		while ( defined ( $line = <DR> )
			and $line !~ /^ID#\s+ATTRIBUTE_NAME\s+FLAG\s+VALUE\s+WORST\s+THRESH/ )
			{
			if ( $line =~ /^Model Family:\s*(\w.*)$/ ) {
				$family = $1;
				$oid .= ".1";
				$cache{$oid} = $family;
			} elsif ( $line =~ /^Device Model:\s*(\w.*)$/ ) {
				$model = $1;
				$oid .= ".2";
				$cache{$oid} = $model;
			} elsif ( $line =~ /^Serial Number:\s*(\w.*)$/ ) {
				$serial = $1;
				$oid .= ".3";
				$cache{$oid} = $serial;
			} elsif ( $line =~ /^Firmware Version:\s*(\w.*)$/ ) {
				$firmware = $1;
				$oid .= ".4";
				$cache{$oid} = $firmware;
			} elsif ( $line =~ /^User Capacity:\s*(\d[\d\,]*) bytes/ ) {
				my $cap = $1;
				my $unit = 'B';
				for ('kB','MB','GB','TB','PB') {
					if ( $cap !~ s/,\d{3}$// ) { last; }
					$unit = $_;
				}
				$capacity = "$cap $unit"
				$oid .= ".5";
				$cache{$oid} = $capacity;
			}
		}
		
		my $worstcase = 255;
		my $health;
		while ( defined ( my $line = <DR> ) ) {
			chomp $line;
			if ( $line eq '' ) { last; }
			$line =~ s/^\s*//;
			my @fields = split /\s+/, $line;
			if ( $worstparam and $fields[3] ne '---' and $fields[5] ne '---' ) {
				$health = $fields[3] - $fields[5];
				if ( $fields[5] < 100 ) {
					# we assume we can scale against 100
					$health *= 100 / ( 100 - $fields[5] )
				}
				if ( $health < $worstcase ) {
					$worstcase = $health;
				}
				$oid = "$base.1.$devicecount.2.$fields[0]";
				$cache{$oid} = $health;
				next;	# go no further
			}
			if ( $fields[0] != $param ) { next; }
			if ( $raw ) {
				$health = $fields[9];
				# we want the raw value
				print "$health\n";
			} else {
				my $value = $fields[3];
				if ( $worst ) { $value = $fields[4]; }
				if ( $value eq '---' or $fields[5] eq '---' ) {
					print "U\n";
					last;
				}
				# how close are we to threshold?
				$health = $value - $fields[5];
				if ( defined $family
					and exists $SCALEBYFAMILY{$family}{$param} ) {
					$health *= $SCALEBYFAMILY{$family}{$param};
				} elsif ( defined $model
					and exists $SCALEBYMODEL{$model}{$param} ) {
					if ( $SCALEBYMODEL{$model}{$param} eq 'U' ) {
						$health = 'U';
					} else {
						$health *= $SCALEBYMODEL{$model}{$param};
					}
				} elsif ( $fields[5] < 100 ) {
					# we assume we can scale against 100
					$health *= 100 / ( 100 - $fields[5] );
				}
				# limit the parameter to 101
				if ( $health ne 'U' and $health > 101 ) { $health = 101; }
				print "$health\n";
				last;
			}
		}
		close DR;
		if ( $worstparam ) {
			print "$worstcase\n";
		} elsif ( ! defined ( $health ) ) {	# TODO this is broken - when worst is specified we should display the worst parameter - if last is undef then we get U
			# didn't get the parameter
			print "U\n";
		}
	}



    # We grab interfaces from /sys/class/net

    my @interfaces = </sys/class/net/*>;

    foreach my $interface (@interfaces) {

	# Get index of this interface

	open(IFINDEX, "$interface/ifindex") or next;

	my $index = int(<IFINDEX>);

	close(IFINDEX);

	

	# Call ethtool

	$interface =~ s/^.*\///;

	open(ETHTOOL, "ethtool -S $interface 2>/dev/null |") or next;

	while (<ETHTOOL>) {

	    # Extract name and value

	    /^\s+(\w+): (\d+)$/ or next;

	    my $name = $1;

	    my $value = int($2);

	    # Compute OID

	    my $oid = "$base.$index";

	    foreach my $char (split //, $name) {

		$oid .= ".";

		$oid .= ord($char);

	    }

	    # Put in the cache

	    $cache{$oid} = $value;

	}

	close(ETHTOOL);

    }

    @cache_oids = sort { new NetSNMP::OID($a) <=> new NetSNMP::OID($b) } (keys %cache);

    $cache_updated = time();

}



# Handle request

sub handle_stats {

    my ($handler, $registration_info, $request_info, $requests) = @_;

    update_stats;		# Maybe we should do this in a thread...

    for (my $request = $requests; $request; $request = $request->next()) {

	$SNMP::use_numeric = 1;

	my $oid = $request->getOID();

	my $noid=SNMP::translateObj($oid);

	if ($request_info->getMode() == MODE_GET) {

	    # For a GET request, we just check the cache

	    if (exists $cache{$noid}) {

		$request->setValue(ASN_COUNTER64, $cache{$noid});

	    }

	} elsif ($request_info->getMode() == MODE_GETNEXT) {

	    # For a GETNEXT, we need to find a best match. This is the

	    # first match strictly superior to the requested OID.

	    my $bestoid = undef;

	    foreach my $currentoid (@cache_oids) {

		$currentoid = new NetSNMP::OID($currentoid);

		next if $currentoid <= $oid;

		$bestoid = $currentoid;

		last;

	    }

	    if (defined $bestoid) {

		$SNMP::use_numeric = 1;

		my $noid=SNMP::translateObj($bestoid);

		$request->setOID($bestoid);

		$request->setValue(ASN_COUNTER64, $cache{$noid});

	    }

	}

    }

}



my $agent = new NetSNMP::agent(

    'Name' => "ethtool",

    'AgentX' => 1);



# Register MIB

$agent->register("ethtool-stats", $base,

		 \&handle_stats) or die "registration of handler failed!\n";



# Main loop

$SIG{'INT'} = \&shutdown;

$SIG{'QUIT'} = \&shutdown;

my $running = 1;

while ($running) {

    $agent->agent_check_and_process(1);

}

$agent->shutdown();



sub shutdown {

    # Shutdown requested

    $running = 0;

}