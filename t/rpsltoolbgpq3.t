#!/usr/bin/perl

use warnings;
use strict;

use Test::More;

# manually create this directory to use a queries cache
my $cache_root = 'cache'; 

use RPSLToolBGPQ3;

my $b = bgpq3_factory({
	whois_source	=> [ qw(RIPE) ],
	whois_debug		=> 1,
	cache_root		=> (-d $cache_root ? $cache_root : undef),
	cache_depth		=> 0,
});
isa_ok($b, 'BGPQ3');
can_ok($b, qw(import));

my ($r, $a);

$r = $b->sources;
is_deeply($r, ['RIPE'], 'temporary source');

($r, $a) = $b->import(['RADB::AS12637']);
is_deeply($r, []);

$r = $b->sources;
is_deeply($r, ['RIPE'], 'temporary source');

($r, $a) = $b->import('<AS12637:AS-TEST-1>');
is_deeply($r, [], 'query for an as-set (no routes)');
is_deeply($a, [qw(112)], 'query for an as-set (asn)');

($r, $a) = $b->import(['RIPE::AS12637:AS-TEST-1'], 1, 1);
is_deeply($r, [qw(2001:4:112::/48 2620:4f:8000::/48)]);
is_deeply($a, [qw(112)]);

($r, $a) = $b->import(['192.31.196.0/24']);
is_deeply($r, [qw(192.31.196.0/24)]);

done_testing();

