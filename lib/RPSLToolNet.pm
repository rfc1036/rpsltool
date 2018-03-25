use warnings;
use strict;

use Net::IP::XS qw($IP_NO_OVERLAP $IP_PARTIAL_OVERLAP $IP_A_IN_B_OVERLAP $IP_B_IN_A_OVERLAP);

=head2 sort_networks

This function sorts in place a list of prefixes represented by Net::IP::XS
objects.

=cut

sub sort_networks {
	my $addrs = $_[0];

	@$addrs = sort {
		$a->bincomp('lt', $b) ? -1 : ($a->bincomp('gt', $b) ? 1 : 0);
	} @$addrs;
}

=head2 aggregate_networks

This function aggregates in place a B<sorted> list of prefixes represented
by Net::IP::XS objects.

=cut

sub aggregate_networks {
	my $addrs = $_[0];
	return if not @$addrs;

	# continue aggregating until there are no more changes to do
	my $changed = 1;
	while ($changed) {
		$changed = 0;
		my @new_addrs;
		my $prev = $addrs->[0];
		foreach my $cur (@$addrs[1 .. $#{$addrs}]) {
			if (my $aggregated = $prev->aggregate($cur)) {
				$prev = $aggregated;
				$changed = 1;
			} elsif ($cur->overlaps($prev) == $IP_A_IN_B_OVERLAP) {
				$changed = 1;
			} else {
				push(@new_addrs, $prev);
				$prev = $cur;
			}
		}
		push(@new_addrs, $prev);
		@$addrs = @new_addrs;
	}
}

=head2 filter_networks

=cut

# It assumes that all routes are normalized (have the host part set to 0).

sub filter_networks {
	my ($routes, $filters, $reverse) = @_;

	return [ @$routes ] if not @$filters;

	# cache the objects representing the parsed filters
	my @filter_objects = map {
		my ($froute, $flen, $frange) =
			$_ =~ m#^([\da-fA-F:\.]+/(\d+))(?:\^([\d\+\-]+))?$#;
		die "invalid filter '$_'\n" if not defined $froute;
		my $filter = new Net::IP::XS("$froute");
		die Net::IP::XS::Error() . "\n" if not defined $filter;
		$filter->{flen} = $flen;
		$filter->{frange} = $frange;
		$filter;
	} @$filters;

	# compare each route against the filters
	my @ok;
	foreach my $rroute (@$routes) {
		my $route = new Net::IP::XS($rroute) or die Net::IP::XS::Error() . "\n";
		my $match;
		foreach (@filter_objects) {
			my $rf = $route->rpsl_filter($_);
			die Net::IP::XS::Error() . "\n" if not defined $rf;
			if ($rf) { $match = 1; last };
		}
		push(@ok, $rroute) if $match xor $reverse;
	}
	return \@ok;
}

##############################################################################
package Net::IP::XS;

use warnings;
use strict;

use Net::IP::XS qw($IP_NO_OVERLAP $IP_PARTIAL_OVERLAP $IP_A_IN_B_OVERLAP $IP_B_IN_A_OVERLAP);

=head2 rpsl_filter

This function checks the prefix with a route filter expressed in the RPSL
syntax. It returns true if $ip is allowed by the $filter.
The $filter may be a string or a Net::IP::XS object with additional B<frange>
and B<flen> members.

C<@list = $ip-E<gt>rpsl_filter($filter));>

=over

=item *

^+: inclusive more specifics

=item *

^-: exclusive more specifics

=item *

^n: length n more specifics

=item *

^n-m: length n-m more specifics

=back

=cut

sub rpsl_filter {
	my ($self, $f) = @_;

	my ($froute, $flen, $frange, $filter);
	if (ref $f) {
		die if ref ne 'Net::IP::XS';
		$filter = $f;
		$flen = $filter->{flen};
		$frange = $filter->{frange};
	} else {
		($froute, $flen, $frange) =
			$f =~ m#^([\da-fA-F:\.]+/(\d+))(?:\^([\d\+\-]+))?$#;
		if (not defined $froute) {
			$self->{error} = $Net::IP::XS::ERROR = "Invalid filter $f\n";
			$self->{errno} = $Net::IP::XS::ERRNO = 107;
			return undef;
		}
		my $filter = new Net::IP::XS("$froute") or return undef;
	}

	# silently ignore filters for a different AFI
	return 0 if $self->{ipversion} ne $filter->{ipversion};

	# since the overlaps method is very slow we first check for the easy
	# (and common) case
	if (not $frange) {
		return 0 if $self->{ip} ne $filter->{ip} or
					$self->{prefixlen} ne $filter->{prefixlen};
	}

	my $overlap = $self->overlaps($filter); # A: route, B: filter
	return undef if not defined $overlap;
	return 0 if $overlap == $IP_NO_OVERLAP
			 or $overlap == $IP_PARTIAL_OVERLAP
			 or $overlap == $IP_B_IN_A_OVERLAP;

	my ($lmin, $lmax);
	if    (not defined $frange)			{ $lmin =          $lmax = $flen; }
	elsif ($frange eq '+')				{ $lmin = $flen;   $lmax = 128; }
	elsif ($frange eq '-')				{ $lmin = $flen+1; $lmax = 128; }
	elsif ($frange =~ /^\d+$/)			{ $lmin =          $lmax = $frange; }
	elsif ($frange =~ /^(\d+)-(\d+)$/)	{ $lmin = $1;      $lmax = $2; }
	else {
		$self->{error} = $Net::IP::XS::ERROR = "invalid filter '$filter'";
		return undef;
	}

	# $IP_IDENTICAL, $IP_A_IN_B_OVERLAP
	return 1 if $self->{prefixlen} >= $lmin and $self->{prefixlen} <= $lmax;
	return 0;
}

1;
