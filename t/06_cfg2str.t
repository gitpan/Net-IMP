use strict;
use warnings;
use Test::More tests => 4;
use Data::Dumper;


rt(
    'Net::IMP::Pattern',
    'action=deny&adata=matched%20regex&rx=(?^:foo%25bar%20foot)&rxlen=12',
    {
	action => 'deny',
	adata  => 'matched regex',
	rx => qr/foo%bar foot/,
	rxlen => '12',
    }
);

rt(
    'Net::IMP::ProtocolPinning',
    'dir0=0&dir1=1&ignore_order=1&max_unbound0=0&max_unbound1=0&rx0=(?^:\d{4})&rx1=(?^:%20\r?\n\r?\n)&rxlen0=4&rxlen1=5',
    {
        rules => [
            { dir => '0', rxlen => '4', rx => qr/\d{4}/ },
            { dir => '1', rxlen => '5', rx => qr/ \r?\n\r?\n/ },
        ],
	max_unbound => ['0','0'],
	ignore_order => '1',
    }
);

sub rt {
    my ($class,$str,$cfg) = @_;
    eval "require $class" or BAIL_OUT("cannot load $class");

    my $str2 = $class->cfg2str(%$cfg);
    is($str2,$str,"$class cfg2str");

    my %cfg2 = $class->str2cfg($str);
    my $dp2 = Dumper(\%cfg2);
    # $rx = qr/$rx/; $rx = qr/$rx/ will put twice into (?^:...
    $dp2 =~s{qr/\Q(?^\E:(\Q(?^\E:.*?\))\)/}{qr/$1/}g;
    is($dp2,Dumper($cfg),"$class str2cfg");

}


