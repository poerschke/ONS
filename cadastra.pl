#!/usr/bin/perl
use DBI;
use strict;

open(a, "<sites.txt");
my @site = <a>;
close(a);

foreach my $s (@site){
	chomp $s;
	$s = 'http://' . $s if($s !~/https?:\/\//);
	$s .= '/' if($s !~/\/$/);
	my $dbh = DBI->connect('DBI:mysql:;host=localhost','root','naotem', {'PrintError'=>1}) or die("$@\n");
	my $query = "INSERT INTO `uniscan`.`fila` (user_id, site_id, site, enabled, checked, reports, scaner_hostname, current_report, interval_length, start_scan, end_scan, ack, scan_lock, validade, nivel )  VALUES (38, 29, '$s', '1', '0', 4, 'NULL', 0, '512400', '2000-10-10 01:01:10', '2000-10-10 01:01:10', '2000-10-10 01:01:10', 0, '2020-12-30 01:01:10', 4);";
	my $query_handle = $dbh->prepare($query);
    	$query_handle->execute();
	print "Site: $s\n";	
}
