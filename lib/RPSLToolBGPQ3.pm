use warnings;
use strict;

use BGPQ3;
use Cache::FileCache;

# should be moved to a different module?
sub bgpq3_factory {
	my ($param) = @_;

	my $bgpq3 = BGPQ3->new or die;
	$bgpq3->host($param->{whois_server}) if $param->{whois_server};

	$bgpq3->debug(1) if $param->{whois_debug};
	$bgpq3->sources($param->{whois_source}) if $param->{whois_source};

	# setup the query cache
	my $cache = new Cache::FileCache({
		cache_root	=> $param->{cache_root},
		cache_depth	=> ($param->{cache_depth} || 0),
	}) if $param->{cache_root};
	$bgpq3->cache($cache) if $cache;

	return $bgpq3;
}

##############################################################################
package BGPQ3;

use warnings;
use strict;

my ($v6route, $v4route, $aut_num, $as_set, $route_set, $routes_range);

$v6route		= qr/[:0-9a-fA-F\/^\-\+]+/;
$v4route		= qr/[\.0-9\/^\-\+]+/;
$aut_num		= qr/[Aa][Ss][0-9]+/;
$as_set			= qr/(?:$aut_num:)?[Aa][Ss]-[:A-Za-z0-9_\-]+/;
$route_set		= qr/(?:$aut_num:)?[Rr][Ss]-[:A-Za-z0-9_\-]+/;
$routes_range	= qr/[0-9\+\-]+/;

sub import {
	my ($self, $import, $ipv6, $default_aspath_filter) = @_;

	$import = [ $import ] if not ref $import;

	$self->ipv6($ipv6);
	my $saved_sources = $self->sources;

	my (@routes, @aspathlist, $query_sources);
	foreach (@$import) {
		next if not defined $_;
		# ask for an as-path instead of a list of routes
		my $aspath_query = 1 if s/^<(.+)>$/$1/;

		# augment the RPSL language by allowing to override the object
		# source(s) by prefixing objects with "SOURCE,SOURCE::"
		if (s/^([A-Z0-9,-]+):://) {
			$self->sources($1);
		} elsif ($saved_sources) {
			$self->sources($saved_sources);
		}

		if      (/^$aut_num$/o and $aspath_query) {
			s/^AS//;
			push(@aspathlist, $_);
		} elsif (/^$as_set$/o and $aspath_query) {
			push(@aspathlist, $self->aspath($_));
		} elsif (/^$aut_num$/o) {
			push(@routes, $self->query($_));
			s/^AS//;
			push(@aspathlist, $_) if $default_aspath_filter;
		} elsif (/^$as_set$/o) {
			push(@routes, $self->query($_));
			push(@aspathlist, $self->aspath($_)) if $default_aspath_filter;
		} elsif (/^$route_set/o) {
			push(@routes, $self->query($_));
		} elsif ($ipv6     and /^$v6route$/o) {
			push(@routes, $_);
		} elsif (not $ipv6 and /^$v4route$/o) {
			push(@routes, $_);
		} else {
			die "cannot parse '$_'\n";
		}
	}

	# restore the original value
	$self->sources($saved_sources) if $saved_sources;

	return (\@routes, \@aspathlist);
}

##############################################################################
sub expand_as_set {
	my ($self, $name) = @_;

	# just return the argument if it is an aut-num
	if ($name =~ /^$aut_num$/o) {
		$name =~ s/^AS//;
		return $name;
	}

	return map { s/^AS//; $_; } $self->aspath($name);
}

sub expand_route_set {
	my ($self, $name, $ipv6) = @_;

	# just return the argument if it is a route
	return ($name) if $name =~ /^[\.:\da-fA-F\/^\-\+]+$/;

	my $globalrange;
	$globalrange = $2 if $name =~ s/^(.+)\^($routes_range)$/$1/o;

	$self->ipv6($ipv6);
	my @routes = $self->routes($name);

	@routes = @{ rpsl_filter(\@routes, [ '0.0.0.0/0^' . $globalrange ]) }
		if $globalrange;

	return @routes;
}

##############################################################################
sub asn_to_networks {
	my ($self, $name, $ipv6) = @_;

	$self->ipv6($ipv6);
	return $self->routes($name);
}

1;
