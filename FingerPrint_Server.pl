#!/usr/bin/perl

use lib "./";
use Uniscan::Functions;
use Uniscan::Configure;
use URI;

my %conf = ( );
my $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
%conf = $cfg->loadconf();


my $func = Uniscan::Functions->new();
$report_id = $ARGV[0];
my $site = $func->pega_site($report_id);



&fingerprintServer($site);

sub fingerprintServer{
 	my $target = shift;
        my $url = &host($target);
        my $i = 0;
	my @nslookup;
	my (@nslookup2,@nslookup_result);
        my ($d,@arq,$lwp,$connect,$version);

##############################################
#  Function PING
##############################################
	my $pin = "";
	my @ping = `ping -c 4 -w 4 $url`;
	foreach $i (@ping) {
	$pin .= $i;
	}
	$pin =~s/'/\\'/gi;
	$func->insert("UPDATE report SET ping = '$pin' WHERE report_id=$report_id");


	my $trace = "";
	my @traceroute = `traceroute -n $url`;
	foreach $i (@traceroute) {
		$trace .= $i if($i !~/\d+\s+\*\s+\*\s+\*\s+/g);
	}
	$trace =~s/'/\\'/gi;
	$func->insert("UPDATE report SET traceroute = '$trace' WHERE report_id=$report_id");

	
##############################################
#  Function NSLOOKUP
##############################################

	@nslookup = `nslookup -type=MX $url`;
	push(@nslookup2,@nslookup);
	@nslookup = `nslookup -type=PX $url`;
	push(@nslookup2,@nslookup);
	@nslookup = `nslookup -type=NS $url`;
	push(@nslookup2,@nslookup);
	@nslookup = `nslookup -type=A $url`;
	push(@nslookup2,@nslookup);
	@nslookup = `nslookup -type=CNAME $url`;
	push(@nslookup2,@nslookup);
	@nslookup = `nslookup -type=HINFO $url`;
	push(@nslookup2,@nslookup);
	@nslookup = `nslookup -type=PTR $url`;
	push(@nslookup2,@nslookup);
	@nslookup = `nslookup -type=SOA $url`;
	push(@nslookup2,@nslookup);
	@nslookup = `nslookup -type=TXT $url`;
	push(@nslookup2,@nslookup);
	@nslookup = `nslookup -type=WKS $url`;
	push(@nslookup2,@nslookup);
	@nslookup = `nslookup -type=ANY $url`;
	push(@nslookup2,@nslookup);
	@nslookup = `nslookup -type=MB $url`;
	push(@nslookup2,@nslookup);
	@nslookup = `nslookup -type=MINFO $url`;
	push(@nslookup2,@nslookup);
	@nslookup = `nslookup -type=MG $url`;
	push(@nslookup2,@nslookup);
	@nslookup = `nslookup -type=MR $url`;
	push(@nslookup2,@nslookup);
	@nslookup_result = &remove(@nslookup2);
	my $ns = "";
	foreach my $i (@nslookup_result) {
		$ns .= $i;
	}
	$ns =~ s/'/\\'/g;
	$func->insert("UPDATE report SET nslookup = '$ns' WHERE report_id=$report_id");

##############################################
#  Function NMAP
##############################################

	#my @nmap = `nmap -v -A $url`;
	my @nmap = ();
	my $port = "";
	foreach my $i (@nmap) {
		if($i =~/\d+\/(tcp|udp) +open+/){
			$port .= $i;
		}
	}
	$port =~s/'/\\'/gi;
	$func->insert("UPDATE report SET nmap = '$port' WHERE report_id=$report_id");
}


sub host(){
  	my $h = shift;
  	my $url1 = URI->new( $h || return -1 );
  	return $url1->host();
}

##############################################
#  Function remove
#  this function removes repeated elements of 
#  a array
#
#  Param: @array
#  Return: @array
##############################################

sub remove{
   	my @si = @_;
   	my @novo = ();
   	my %ss;
   	foreach my $s (@si)
   	{
        	if (!$ss{$s})
        	{
            		push(@novo, $s);
            		$ss {$s} = 1;
        	}
    	}
    	return (@novo);
}


# code below taken from the project web-sorrow
sub genErrorString{
	my $errorStringGGG = "";
        my $i = 0;
	for($i = 0;$i < 20;$i++){
		$errorStringGGG .= chr((int(rand(93)) + 33)); # random 20 bytes to invoke 404 sometimes 400
	}
	
	$errorStringGGG =~ s/(#|&|\?)//g; #strip anchors and q stings
	return $errorStringGGG;
}

sub matchScan{
	my $checkMatchFromDB = shift;
	my $checkMatch = shift;
	my $matchScanMSG = shift;
	chomp $checkMatchFromDB;
	my @matchScanLineFromDB = split(';',$checkMatchFromDB);
	my $msJustString = $matchScanLineFromDB[0]; #String to find
	my $msMSG = $matchScanLineFromDB[1]; #this is the message printed if it isn't an error
	if($checkMatch =~ /$msJustString/){
		$func->write("| $matchScanMSG: $msMSG");
		$func->writeHTMLValue(" $matchScanMSG: $msMSG");
	}
}
;
