# This is a first attempt at coding support for automatically updating the
# value of maximum-prefix. It was originally a part of routesdiff.
# Could be used by "maxpref: auto" in the rpsltool configuration.

my %NewMaxPref = map { $_ => newmaxpref($_, $MaxPrefs{$_}) } keys %MaxPrefs;

# Try to guess a new value for the max-prefix parameter.
sub newmaxpref {
	my ($as, $routes) = @_;

	# add today's value and remove the oldest value
	push(@{$MaxPrefsHist{$as}}, $routes);
	shift @{$MaxPrefsHist{$as}} if @{$MaxPrefsHist{$as}} > 21;

	my $max = 0;
	foreach (@{$MaxPrefsHist{$as}}) {
		$max = $_ if $_ > $max;
	}

	# use the largest value in the period considered + 10%
	# if the original value is less than 20, use value + 20
	my $diff = int ($max / 10);
	$diff = 20 if $diff < 20;
	return $max + $diff;
}

# only save the new values if the file is older than one day
# sub savemaxpref {
# use Storable to dump/reload %MaxPrefsHist

