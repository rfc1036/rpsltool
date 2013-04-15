use warnings;
use strict;

#use RPSLToolUtils;
#use Net::IP;

sub Template::create_whois_vmethods {
	my ($template, $whois) = @_;

	my $context = $template->context;

$context->define_vmethod('scalar', v4routes => sub {
	return if not $_[0];
	$whois->asn_to_networks($_[0], 0);
});

$context->define_vmethod('scalar', v6routes => sub {
	return if not $_[0];
	$whois->asn_to_networks($_[0], 1);
});

$context->define_vmethod('scalar', expand_as_set => sub {
	return if not $_[0];
	$whois->expand_as_set($_[0]);
});

$context->define_vmethod('scalar', expand_route_set => sub {
	return if not $_[0];
	$whois->expand_route_set($_[0], 0);
});

$context->define_vmethod('scalar', expand_route6_set => sub {
	return if not $_[0];
	$whois->expand_route_set($_[0], 1);
});

}

##############################################################################
sub Template::create_net_vmethods {
	my ($template) = @_;

	my $context = $template->context;

$context->define_vmethod('list', 'dotescape' => sub {
	return map { s/\./\\./g; $_; } @{$_[0]};
});

$context->define_vmethod('list', 'asnsort' => sub {
	return sort by_asn @{$_[0]};
});

$context->define_vmethod('list', 'ipsort' => sub {
	my $networks = $_[0];

	return map {
		$_->[0]
	} sort {
		 $a->[1]->bincomp('lt', $b->[1]) ? -1 :
		($a->[1]->bincomp('gt', $b->[1]) ?  1 : 0)
	} map {
		[ $_, (Net::IP->new($_) or die "Not an IP: $_") ]
	} @$networks;
});

$context->define_vmethod('list', 'aggregate' => sub {
	my $networks = $_[0];

	my @nets = map { Net::IP->new($_) or die "Not an IP: $_" } @$networks;
	sort_networks(\@nets);
	aggregate_networks(\@nets);
	return map {
		$_->{ipversion} eq '4' ? $_->prefix : $_->short . '/' . $_->prefixlen
	} @nets;
});

}

1;
