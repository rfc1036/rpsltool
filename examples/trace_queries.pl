# useful for debugging

{
	my $real_safe_query = \&Net::Whois::RIPE::safe_query;

	no warnings 'redefine';
	*Net::Whois::RIPE::safe_query = sub {
		print STDERR "========> QUERY: $_[1]\n";
		return &$real_safe_query(@_);
	}
}

1;
