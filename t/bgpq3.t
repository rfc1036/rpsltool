#!/usr/bin/perl

use warnings;
use strict;

use Test::More;
use Cache::FileCache;

# manually create this directory to use a queries cache
my $cache_root = 'cache';

use BGPQ3;

my $cache;
if (-d $cache_root) {
    $cache = new Cache::FileCache({
        cache_root	=> $cache_root,
        cache_depth	=> 0,
    });
}

my $b = BGPQ3->new(
	sources => [ qw(RIPE) ],
	debug => 1,
	aspath_query => 0,
	cache => $cache,
);
isa_ok($b, 'BGPQ3');

my $r;

$b->aspath_query(0);

$r = $b->query(['AS112']);
is_deeply($r, [qw(192.31.196.0/24 192.175.48.0/24)], 'query for routes');

$b->aspath_query(1);
is($b->aspath_query, 1, 'enable aspath_query()');

$r = $b->query(['AS112']);
is_deeply($r, [qw(112)], 'query for an AS');

$r = $b->routes(['AS112']);
is_deeply($r, [qw(192.31.196.0/24 192.175.48.0/24)], 'routes() query');

$r = $b->routes(['AS12637:AS-TEST-1']);
is_deeply($r, [qw(192.31.196.0/24 192.175.48.0/24)], 'query for an as-set');

$b->aspath_query(0);
is($b->aspath_query, 0, 'disable aspath_query()');

$r = $b->aspath(['AS112']);
is_deeply($r, [qw(112)], 'aspath() query');

$b->sources('RADB,ALTDB');
$r = $b->sources;
is_deeply($r, [qw(RADB ALTDB)], 'set sources');

$r = $b->routes(['AS12637:AS-TEST-1']);
is_deeply($r, [], 'query with an empty answer');

$b->sources('RIPE');

$b->ipv6(1);
is($b->ipv6, 1, 'set ipv6');

$r = $b->routes(['AS112']);
is_deeply($r, [qw(2001:4:112::/48 2620:4f:8000::/48)], 'ipv6 routes');

done_testing();

