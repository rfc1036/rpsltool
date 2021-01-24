package BGPQ3;

use Types::Standard qw(Bool Int Str Maybe ArrayRef InstanceOf);
use IPC::System::Simple qw(capturex);

use Moo;
use namespace::clean;

##############################################################################
has path => (
	is => 'rw',
	isa => Str,
	default => 'bgpq3',
);

has host => (
	is => 'rw',
	isa => Str,
);

has port => (
	is => 'rw',
	isa => Int,
);

has asn32 => (
	is => 'rw',
	isa => Bool,
	default => 1,
);

has asdot => (
	is => 'rw',
	isa => Bool,
);

has ipv6 => (
	is => 'rw',
	isa => Bool,
);

has debug => (
	is => 'rw',
	isa => Bool,
);

has sources => (
	is => 'rw',
	isa => ArrayRef[Str],
	# from Str to ArrayRef[Str]
	coerce => sub { ref $_[0] ? $_[0] : [ split(/,/, $_[0]) ] },
	predicate => 1,
);

has aspath_query => (
	is => 'rw',
	isa => Bool,
);

has whois_show_cache_misses => (
	is => 'rw',
	isa => Bool,
	default => $ENV{WHOIS_SHOW_CACHE_MISSES} || 0,
);

has cache_root => (
	is => 'rw',
	isa => Maybe[Str],
);

has cache_depth => (
	is => 'rw',
	isa => Int,
	default => 0,
);

has cache => (
	is => 'rw',
	isa => Maybe[InstanceOf['CHI', 'Cache::BaseCache']],
);

##############################################################################
sub _bgpq3_cmdline {
	my ($self, @objects) = @_;

	my $aspath_query;

	foreach (my $i = 0; $i <= $#objects; $i++) {
		# determine is this is a query for as-paths or prefixes
		if (not defined $self->aspath_query) {
			if ($objects[$i] =~ s/^<(.+)>$/$1/) {
				$aspath_query = 1;
			} else {
				$aspath_query = 0;
			}
		} elsif ($self->aspath_query == 0) {
			die "Unsupported mixed query (@objects)!"
				if @objects > 1 and $objects[$i] =~ /^</;
			$aspath_query = 1 if $objects[$i] =~ s/^<(.+)>$/$1/;
		} elsif ($self->aspath_query == 1) {
			# <> are optional and useless if aspath_query is set
			$objects[$i] =~ s/^<(.+)>$/$1/;
		}
	}

	my @params;
	push(@params, '-3') if $self->asn32;
	push(@params, '-6') if $self->ipv6
		and not ($self->aspath_query or $aspath_query);
	push(@params, '-d') if $self->debug;
	push(@params, '-D') if $self->asdot;
	push(@params, '-S', join(',', @{$self->sources}))
		if $self->has_sources;
	push(@params, '-h', $self->host . ($self->port ? ':' . $self->port : ''))
		if $self->host;

	if ($self->aspath_query or $aspath_query) {
		push(@params, '-G', '1');		# as-path list
	} else {
		push(@params, '-F', '%n/%l\n');	# prefixes
	}

	return (@params, sort @objects)
}

sub query {
	my ($self, @objects) = @_;

	# dereference the list if needed
	@objects = @{$objects[0]} if ref $objects[0] eq 'ARRAY';

	my @cmdline = $self->_bgpq3_cmdline(@objects);

	my $cache_key = join(' ', @cmdline);

	if ($self->cache) {
		my $cached = $self->cache->get($cache_key);
		return wantarray ? @$cached : $cached if $cached;

		# some debugging code to show when an object is not in cache
		print STDERR "============> CACHE MISS: @objects\n"
			if $self->whois_show_cache_misses;
	}

	print STDERR join(' ', 'QUERY:', $self->path, @cmdline) . "\n"
		if $self->debug;

	my @output = capturex($self->path, @cmdline);
	chomp @output;

	# remove any trailing empty lines
	pop @output while @output and $output[$#output] eq '';

	# extract just the list of ASNs
	if (@output and $output[0] =~ /^no ip as-path access-list /) {
		@output =
			map { split(/\|/) }
			grep { defined $_ }
			map { /^ip as-path access-list \S+ permit \S+_\(([0-9\|]+)\)\$/; $1 }
			@output;
	}

	$self->cache->set($cache_key, \@output) if $self->cache;

	return wantarray ? @output : \@output;
}

sub routes {
	my $self = shift;

	my $saved = $self->aspath_query;
	$self->aspath_query(0);
	my $output = $self->query(@_);
	$self->aspath_query($saved);

	return wantarray ? @$output : $output;
}

sub aspath {
	my $self = shift;

	my $saved = $self->aspath_query;
	$self->aspath_query(1);
	my $output = $self->query(@_);
	$self->aspath_query($saved);

	return wantarray ? @$output : $output;
}

1;
