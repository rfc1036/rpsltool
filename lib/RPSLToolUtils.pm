use warnings;
use strict;

use Storable qw(dclone);

# configuration directives which can benefit from some special handling
use constant FIELDS_NEIGH_BOOLEAN => qw(
	template customer default_aspath_filter asn32_supported disabled
);
use constant FIELDS_NEIGH_ARRAY => qw(
	import unimport global_unimport bgp_commands
);
use constant FIELDS_AFI_BOOLEAN => qw(
	default_aspath_filter asn32_supported
);
use constant FIELDS_AFI_ARRAY => qw(
	import unimport global_unimport bgp_commands
);
use constant FIELDS_FROM_NEIGH => qw(
	import unimport localpref maxpref metric peergroup
	asn32_supported default_aspath_filter in_community in_policy
);
use constant FIELDS_FROM_GLOBALS => qw(
	asn32_supported default_aspath_filter in_community in_policy
);


use constant AFIS => qw(ipv4 ipv6 ipv4m ipv6m);

# Does a first pass over the configuration and normalizes some fields.
sub process_peers_config {
	my ($peers, $param) = @_;

	my (%conf);
	my $default = { };
	foreach my $peer (@$peers) {
		# normalize these fields
		make_boolean($peer, FIELDS_NEIGH_BOOLEAN);
		make_array($peer, FIELDS_NEIGH_ARRAY);

		# store the defaults
		if ($peer->{template}) {
			$default = $peer;
			delete $default->{template};
			next;
		}

		# skip disabled entries
		next if $peer->{disabled} or $default->{disabled};

		# sanity check for the mandatory options
		foreach my $field (qw(ip as)) {
			die "This entry lacks the '$field' field:\n"
					. join("\n", map { "$_: $peer->{$_}" } keys %$peer) . "\n"
				if not $peer->{$field};
		}

		# if no AFI is defined, choose unicast IPv4 or IPv6 by looking at
		# the peer IP address
		my $found_afi;
		foreach my $afi (AFIS) {
			next if not exists $peer->{$afi};
			$found_afi = 1;
			last;
		}
		if (not $found_afi) {
			my $afi = ($peer->{ip} =~ /:/ ? 6 : 0) ? 'ipv6' : 'ipv4';
			$afi .= 'm' if $peer->{multicast};
			$peer->{$afi} = { };
		}

		# import the default values from the latest template processed
		foreach my $attr (keys %$default) {
			next if exists $peer->{$attr} or not exists $default->{$attr};
			$peer->{$attr} = $default->{$attr};
		}

		# import the default values from the global parameters
		foreach my $attr (FIELDS_FROM_GLOBALS) {
			next if exists $peer->{$attr} or not exists $param->{$attr};
			$peer->{$attr} = $param->{$attr};
		}

		$conf{$peer->{ip}} = dclone($peer);

		foreach my $afi (AFIS) {
			next if not exists $peer->{$afi};
			make_boolean($peer->{$afi}, FIELDS_AFI_BOOLEAN);
			make_array($peer->{$afi}, FIELDS_AFI_ARRAY);

			# import some values from the global (AFI-independent) neighbor
			# configuration, if they are not defined for the AFI
			foreach my $attr (FIELDS_FROM_NEIGH) {
				next if exists $peer->{$afi}->{$attr} or
					not exists $peer->{$attr};
				$peer->{$afi}->{$attr} = $peer->{$attr};
			}

			$conf{$peer->{ip}}->{$afi} = dclone($peer->{$afi});
		} # $afi
	}

	return \%conf;
}

sub make_boolean {
	my ($hash, @elements) = @_;

	foreach my $key (@elements) {
		next if not exists $hash->{$key};
		$hash->{$key} = ($hash->{$key} =~ /^(y|yes|t|true|on|1)$/i) ? 1 : 0;
	}
}

sub make_array {
	my ($hash, @elements) = @_;

	foreach my $key (@elements) {
		next if not exists $hash->{$key} or ref $hash->{$key};
		$hash->{$key} = [ $hash->{$key} ];
	}
}

##############################################################################
sub iterate_peers {
	my ($peers, $run) = @_;

	foreach my $peer (values %$peers) {
		foreach my $afi (AFIS) {
			next unless exists $peer->{$afi};
			$run->($peer, $afi);
		}
	}
}

##############################################################################
# Beware: if the AFI is not specified the result may be ambiguous
sub neigh_by_asn {
	my ($peers, $asn, $afi) = @_;

	foreach my $peer (values %$peers) {
		next if $afi and not exists $peer->{$afi};
		return $peer->{ip} if $peer->{as} and $peer->{as} eq $asn;
	}
	return undef;
}

##############################################################################
# sort by IP
sub by_ip {
	my @a = $a =~ /^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/;
	my @b = $b =~ /^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/;

	$a[0] <=> $b[0] || $a[1] <=> $b[1] || $a[2] <=> $b[2] || $a[3] <=> $b[3]
}

sub by_ipv46 {
	if      ($a =~ /:/ and $b =~ /:/) {
		my @a = map { hex $_ } split(/:/, $a);
		my @b = map { hex $_ } split(/:/, $b);

		return
		$a[0] <=> $b[0] || $a[1] <=> $b[1] || $a[2] <=> $b[2] || $a[3]<=>$b[3];
	} elsif ($a !~ /:/ and $b !~ /:/) {
		my @a = $a =~ /^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/;
		my @b = $b =~ /^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/;

		return
		$a[0] <=> $b[0] || $a[1] <=> $b[1] || $a[2] <=> $b[2] || $a[3]<=>$b[3];
	} elsif ($a =~ /:/) {
		return 1;
	} else {
		return -1;
	}
}

# sort by ASN
sub by_asn {
	my ($as1hi, $as1lo) = $a =~ /^(?:[Aa][Ss])([0-9]+)(\.[0-9]+)?/;
	my ($as2hi, $as2lo) = $b =~ /^(?:[Aa][Ss])([0-9]+)(\.[0-9]+)?/;

	if (defined $as1lo and defined $as2lo) {
		return $as1hi <=> $as2hi || $as1lo <=> $as2lo;
	} else {
		return $as1hi <=> $as2hi;
	}
}

##############################################################################
sub difference {
	my ($list1, $list2) = @_;

	my %items2 = map { $_ => undef } @$list2;

	my @diff;
	foreach (@$list1) {
		next if exists $items2{$_};
		push(@diff, $_);
	}

	return \@diff;
}

sub common {
	my ($list1, $list2) = @_;

	my %items2 = map { $_ => undef } @$list2;

	my @diff;
	foreach (@$list1) {
		next if not exists $items2{$_};
		push(@diff, $_);
	}

	return \@diff;
}

##############################################################################
sub read_file {
	my ($file) = @_;

	open(FILE, $file) or die "Cannot open $file: $!\n";
	my @input = <FILE>;
	close FILE;
	chomp @input;
	return \@input;
}

# look for the YAML marker in the first 40 lines of the input
sub is_yaml {
	my ($input) = @_;

	my $max_read = 40;
	foreach (@$input) {
		last if $max_read-- == 0;
		return 1 if /^---\s+#YAML:1\./;		# found
	}

	return 0;								# not found
}

##############################################################################
sub read_commented_list {
	my ($file) = @_;

	if ($file) {
		open(FILE, $file) or die "Cannot open $file: $!\n";
	} else {
		open(FILE, '<&DATA') or die "Cannot dup DATA: $!\n";
	}

	my @input;
	foreach (<FILE>) {
		chomp;
		next if /^#/;
		s/#.*$//; s/\s+$//;
		next if /^$/;

		push(@input, $_);
	}
	close FILE;

	return \@input;
}

sub read_routes {
	my ($file, $routes, $paths) = @_;

	open(FILE, $file) or die "Cannot open $file: $!\n";
	foreach (<FILE>) {
		chomp;
		my ($r, $p) = split(/\s+/, $_, 2);
		push(@$routes, $r);
		$paths->{$r} = $p if $paths;
	}
	close FILE;
}

##############################################################################
sub origin2asn {
	my ($paths) = @_;

	my %asn;
	foreach my $path (keys %$paths) {
		my @p = split(/\s+/, $paths->{$path});
		$asn{$p[$#p]} = undef;
	}
	return [ keys %asn ];
}

sub paths2asn {
	my ($paths) = @_;

	my %asn;
	foreach my $path (keys %$paths) {
		$asn{$_} = undef foreach split(/\s+/, $paths->{$path});
	}
	return [ keys %asn ];
}

1;
