#!/usr/bin/perl -w

use Uniscan::Functions;
my $func = Uniscan::Functions->new();
$|++;
use strict;
use warnings;
use IO::Socket::INET;

our $report_id = $ARGV[0];
my $url = $func->pega_site($report_id);
$url =~s/https?:\/\///;
$url = substr($url, 0, index('/', $url));
$url =~s/\///;

my $dst = $url . ":443";


my $starttls = sub {1};
my $starttls_arg;
my $timeout = 15;
my $ssl_version = 'tlsv1';
my $heartbeats = 1;
$ssl_version = 
    lc($ssl_version) eq 'ssl3' ? 0x0300 :
    $ssl_version =~ m{^tlsv?1(?:_([12]))?}i ? 0x0301 + ($1||0) :
    &naovul();

#começo
my $cl = IO::Socket::INET->new(PeerAddr => $dst, Timeout => $timeout)
    or &naovul();
setsockopt($cl,6,1,pack("l",1));
$starttls->($cl,$dst);
my $hello_data = pack("nNn14Cn/a*C/a*n/a*",
    $ssl_version,
    time(),
    ( map { rand(0x10000) } (1..14)),
    0, 
    pack("H*",'c009c00ac013c01400320038002f00350013000a000500ff'), 
    "\0", 
    '',   
);
$hello_data = substr(pack("N/a*",$hello_data),1); 
print $cl pack(
    "Cnn/a*",0x16,$ssl_version,  
    pack("Ca*",1,$hello_data),   
);
my $use_version;
my $err;
while (1) {
    my ($type,$ver,@msg) = _readframe($cl,\$err) or &naovul();
    if ( $type == 22 and grep { $_->[0] == 0x0e } @msg ) {
	
	$use_version = $ver;
	last;
    }
}
my $hb = pack("Cnn/a*",0x18,$use_version,
    pack("Cn",1,0x4000));

for (1..$heartbeats) {
    print $cl substr($hb,0,1);
    print $cl substr($hb,1);
}

if ( my ($type,$ver,$buf) = _readframe($cl,\$err)) {
    if ( $type == 21 ) {
		&naovul();
	} elsif ( $type != 24 ) {
		&naovul();
    } elsif ( length($buf)>3 ) {
	print "vulneravel $report_id $url\n";
	$func->insert("UPDATE historico SET heartbleed = 1 WHERE report_id= $report_id");
	$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas,var_vuls, reqs, tipo_id) VALUES($report_id, '', 0, 1, 0, 0, 5, 33)");
	exit 1;
    } else {
    &naovul();
	}
} else {
    &naovul();
}

sub _readframe {
    my ($cl,$rerr) = @_;
    my $len = 5;
    my $buf = '';
    vec( my $rin = '',fileno($cl),1 ) = 1;
    while ( length($buf)<$len ) {
	if ( ! select( my $rout = $rin,undef,undef,$timeout )) {
	    $$rerr = 'timeout';
	    return;
	};
	if ( ! sysread($cl,$buf,$len-length($buf),length($buf))) {
	    $$rerr = "eof";
	    $$rerr .= " after ".length($buf)." bytes" if $buf ne '';
	    return;
	}
	$len = unpack("x3n",$buf) + 5 if length($buf) == 5;
    }
    (my $type, my $ver,$buf) = unpack("Cnn/a*",$buf);
    my @msg;
    if ( $type == 22 ) {
	while ( length($buf)>=4 ) {
	    my ($ht,$len) = unpack("Ca3",substr($buf,0,4,''));
	    $len = unpack("N","\0$len");
	    push @msg,[ $ht,substr($buf,0,$len,'') ];
	    
	}
    } else {
	@msg = $buf;
	
    }

    return ($type,$ver,@msg);
}

sub _readlines {
    my ($cl,$stoprx) = @_;
    my $buf = '';
    while (<$cl>) { 
	$buf .= $_;
	return $buf if ! $stoprx;
	next if ! m{\A$stoprx\Z};
	return ( m{\A$stoprx\Z},$buf );
    }
    &naovul();
}

sub naovul(){
	print "nao vul\n";
	$func->insert("UPDATE historico SET heartbleed = 0 WHERE report_id= $report_id");
	$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas,var_vuls, reqs, tipo_id) VALUES($report_id, '', 0, 0, 0, 0, 1, 33)");
	exit();
}
