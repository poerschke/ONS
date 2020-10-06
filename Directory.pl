#!/usr/bin/perl

my $report_id = $ARGV[0];

use lib "./Uniscan";
use Uniscan::Http;
use Uniscan::Functions;
use strict;
$|++;

my $func = Uniscan::Functions->new();
my $http = Uniscan::Http->new();
my $url = $func->pega_site($report_id);
my $req = $url . "uniscan" . int(rand(1000)) . "/";
my $res = $http->HEAD($req);
my $requests = 1;
my $dirs = "";
if($res->code =~/404/) {
	my @dir = $func->Check($url, "DB/Directory");
        foreach my $d (@dir){
        	$dirs .= $d . "\n";
		
	}
}
$requests = $requests + $func->pega_reqs();
$dirs =~s/'/\\'/gi;
$func->insert("UPDATE report SET diretorios='$dirs', dir_reqs = $requests WHERE report_id=$report_id");
