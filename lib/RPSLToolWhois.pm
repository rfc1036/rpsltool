use warnings;
use strict;

use Net::Whois::RIPE '1.22.1';
use Cache::FileCache;

# should be moved to a different module?
sub whois_factory {
	my ($param) = @_;

	die "whois_server has not been set" if not $param->{whois_server};

	my $whois = Net::Whois::RIPE->new($param->{whois_server}) or die;

	foreach my $name qw(die_on_error warn_on_error warn_on_recursive_error) {
		$whois->{"_$name"} = $param->{"whois_$name"}
			if defined $param->{"whois_$name"};
	};
	$whois->persistant;
	$whois->no_recursive;
	$whois->debug(1) if $param->{whois_debug};
	$whois->source($param->{whois_source}) if $param->{whois_source};

	# This is used by the whois server operator to identify different clients
	# and should be changed if you use this function with your own programs.
	$whois->{FLAG_V} =
		$param->{client_name} ? '-V'.$param->{client_name} : '-Vrpsltool-1.3';

	# setup the query cache
	my $cache = new Cache::FileCache({
		cache_root	=> $param->{cache_root},
		cache_depth	=> ($param->{cache_depth} || 0),
	}) if $param->{cache_root};
	$whois->cache($cache) if $cache;

	# some debugging code to show when an object is not in cache
	show_cache_misses()
		if $param->{whois_show_cache_misses} or $ENV{WHOIS_SHOW_CACHE_MISSES};

	return $whois;
}

##############################################################################
sub show_cache_misses {
	my $real_cache_get = \&Cache::BaseCache::get;

	no warnings 'redefine';
	*Cache::BaseCache::get = sub {
		my $result = &$real_cache_get(@_);
		print STDERR "============> CACHE MISS: $_[1]\n"
			if not defined $result;
		return $result;
	};
}

##############################################################################
package Net::Whois::RIPE;

use warnings;
use strict;

my ($v6route, $v4route, $aut_num, $as_set, $route_set, $routes_range);

$v6route		= qr/[:0-9a-fA-F\/^\-\+]+/;
$v4route		= qr/[\.0-9\/^\-\+]+/;
$aut_num		= qr/[Aa][Ss][0-9]+(?:\.[0-9]+)?/;
$as_set			= qr/(?:$aut_num:)?[Aa][Ss]-[:A-Za-z0-9_\-]+/;
$route_set		= qr/(?:$aut_num:)?[Rr][Ss]-[:A-Za-z0-9_\-]+/;
$routes_range	= qr/[0-9\+\-]+/;

sub import {
	my ($self, $import, $ipv6, $default_aspath_filter) = @_;

	my (@aslist, @aslist2, @aspathlist, @routes);
	foreach (@$import) {
		if      (/^<($aut_num|$as_set)>$/o) {
			push(@aspathlist, $self->expand_as_set($1));
		} elsif (/^$aut_num$/o) {
			push(@aslist, $_);
		} elsif (/^$as_set$/o) {
			push(@aslist2, $self->expand_as_set($_));
		} elsif (/^$route_set/o) {
			push(@routes, $self->expand_route_set($_, $ipv6));
		} elsif ($ipv6     and /^$v6route$/o) {
			push(@routes, $_);
		} elsif (not $ipv6 and /^$v4route$/o) {
			push(@routes, $_);
		} else {
			die "cannot parse '$_'\n";
		}
	}

	# Get the list of routes announced by each ASN.
	# The second set of queries is for the result of as-set expansion,
	# so they are considered "recursive" for the purpose of suppressing
	# errors and warnings.
	push(@routes, $self->asn_to_networks($_, $ipv6, 0)) foreach @aslist;
	push(@routes, $self->asn_to_networks($_, $ipv6, 1)) foreach @aslist2;

	push(@aspathlist, @aslist, @aslist2) if $default_aspath_filter;

	return (\@routes, \@aspathlist);
}

##############################################################################
sub expand_as_set {
	my ($self, $name, $recursive, $seen) = @_;
	$seen ||= { };

	# just return the argument if it is an aut-num
	return ($name) if $name =~ /^$aut_num$/o;

	$self->type('as-set');
	my $object = $self->safe_query($name, $recursive);

	return if not $object or not $object->members;

	my @list;
	foreach ($object->members) {
		s/\s*,\s*/ /g; s/^\s+//; s/\s+$//;
		foreach (split(/\s+/, uc $_)) {
			next if exists $seen->{$_};
			$seen->{$_} = 1;

			if      (/^$aut_num$/o) {
				push(@list, $_);
			} elsif (/^$as_set$/o) {
				my @rlist = $self->expand_as_set($_, 1, $seen);
				push(@list, @rlist) if @rlist;
			} else {
				warn "Cannot parse the following element in $name:\n$_\n";
					#? if not $recursive;
			}
		}
	}

	return @list unless $object->mbrs_by_ref;

	$self->type('aut-num');
	$self->inverse_lookup('member-of');
	my @objects = $self->safe_query($object->as_set, 1);
	$self->inverse_lookup('');

	foreach my $obj (@objects) {
		push(@list, $obj->aut_num) unless exists $seen->{$obj->aut_num};
	}

	return @list;
}

sub expand_route_set {
	my ($self, $name, $ipv6, $recursive, $seen) = @_;
	$seen ||= { };

	# just return the argument if it is a route
	return ($name) if $name =~ /^[\.:\da-fA-F\/^\-\+]+$/;

	my $globalrange;
	$globalrange = $2 if $name =~ s/^(.+)\^($routes_range)$/$1/o;

	$self->type('route-set');
	my $object = $self->safe_query($name, $recursive);

	return if not $object or not ($object->members or $object->mp_members);

	my @routes;
	foreach ($object->members, $object->mp_members) {
		next if not $_;
		s/\s*,\s*/ /g; s/^\s+//; s/\s+$//;
		foreach (split(/\s+/, lc $_)) {
			next if exists $seen->{$_};
			$seen->{$_} = 1;

			# routes of the wrong AFI are silently ignored
			if      (/^$v6route$/o) {
				push(@routes, $_) if $ipv6;
			} elsif (/^$v4route$/o) {
				push(@routes, $_) if not $ipv6;
			} elsif (/^$route_set$/o) {
				push(@routes, $self->expand_route_set($_, $ipv6, 1, $seen));
			} elsif (/^($route_set)\^($routes_range)$/o) {
				my $rs = $1; my $range = $2;
				my @temproutes = $self->expand_route_set($rs, $ipv6, 1, $seen);
				@temproutes =
					@{ rpsl_filter(\@temproutes, [ '0.0.0.0/0^' . $range ]) };
				push(@routes, @temproutes);
			} elsif (/^($as_set|$aut_num)(?:\^($routes_range))?$/o) {
				my $as = $1; my $range = $2;
				my @temproutes;
				push(@temproutes, $self->asn_to_networks($_, $ipv6, 1))
					foreach $self->expand_as_set($as, 1);
				@temproutes =
					@{ rpsl_filter(\@temproutes, [ '0.0.0.0/0^' . $range ]) }
						if $range;
				push(@routes, @temproutes);
			} else {
				warn "Cannot parse the following element in $name (v6: $ipv6):\n$_\n";
					#? if not $recursive;
			}
		}
	}

	return @routes unless $object->mbrs_by_ref;

	$self->type($ipv6 ? 'route6' : 'route');
	$self->inverse_lookup('member-of');
	$self->primary_only(1);
	my @objects = $self->safe_query($object->route_set, 1);
	$self->inverse_lookup('');
	$self->primary_only(0);

	foreach my $obj (@objects) {
		push(@routes, $obj->route) unless exists $seen->{$obj->route};
	}

	@routes = @{ rpsl_filter(\@routes, [ '0.0.0.0/0^' . $globalrange ]) }
		if $globalrange;

	return @routes;
}

##############################################################################
sub asn_to_networks {
	my ($self, $name, $ipv6, $recursive) = @_;

	$self->type($ipv6 ? 'route6' : 'route');
	$self->inverse_lookup('origin');
	$self->primary_only(1);
	my @objects = $self->safe_query($name, $recursive);
	$self->inverse_lookup('');
	$self->primary_only(0);

	my @list;
	foreach my $obj (@objects) {
		my $route = ($ipv6 ? $obj->route6 : $obj->route) || next;
		push(@list, $route);
	}

	return @list;
}

##############################################################################
# Hides errors handling from the caller.
# Provides special handling for error 101 ("no such object").

sub safe_query {
	my ($self, $name, $recursive) = @_;

	my @objects = $self->query($name) or die;
	my $object = $objects[0];

	return wantarray ? @objects : $object if $object->success;

	# defaults
	my $die_on_error =
		(defined $self->{_die_on_error})  ? $self->{_die_on_error}  : 0;
	my $warn_on_error =
		(defined $self->{_warn_on_error}) ? $self->{_warn_on_error} : 0;
	my $warn_on_recursive_error	=
		(defined $self->{_warn_on_recursive_error}) ?
				$self->{_warn_on_recursive_error} : 0;

	my $warn = 0;
	if ($recursive) {
		$warn = 1 if $warn_on_recursive_error;
	} else {
		$warn = 1 if $warn_on_error;
	}

	if ($object->error =~ /^101:/) {
		warn "QUERY FAILED ($name): " . $object->error . "\n"
			if $warn or $die_on_error;
		exit 1 if $die_on_error;
		return;
	}
	die "QUERY FAILED ($name): " . $object->error . "\n";
}

1;
