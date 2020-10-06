#!/usr/bin/perl

use lib "./Uniscan";
use Uniscan::Functions;
use Uniscan::Configure;
use Digest::MD5;
use URI;
use HTTP::Request;
use HTTP::Cookies;
use LWP::UserAgent;
use LWP::Simple;
use LWP::ConnCache;

my $func = Uniscan::Functions->new();
my $encontrou = 0;
my %existe = ();
my $wordpress = 0;
my $joomla = 0;
my $drupal = 0;

my %conf = ( );
my $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
%conf = $cfg->loadconf();
my $report_id = $ARGV[0];

&fingerprint($func->pega_site($report_id));
&bannergrabing($func->pega_site($report_id));

sub fingerprint{
 	my $target = shift;
        my $url = &host($target);
        my $i = 0;
        my ($d,@arq,$lwp,$connect,$version);
        my (@in,$left,$right);

#  Function METHOD ENABLED

	my $host = $url;
	my $path = "pdUsmmdhVC";
	my $port = 80 ; # webserver port
	my $sock = IO::Socket::INET->new(PeerAddr => $host,
					PeerPort => $port,
					Proto    => 'tcp',
					Timeout => 30) or return;
	print $sock "PUT /".$path." HTTP/1.1\r\n" ;
	print $sock "Host: ".$host."\r\n" ;
	print $sock "Connection:close\r\n" ;
	print $sock "\r\n\r\n" ;
 
        while(<$sock>){
            push (@in, $_);
        }
        close($sock) ;

	foreach my $line (@in){
		if ($line =~ /^Allow: /){
			($left,$right)=split(/\:/,$line);
			$right =~ s/ |\r|\n//g;
			$right =~s/'/\\'/gi;
			$func->insert("UPDATE report SET metodos = '". $right ."' WHERE report_id = $report_id");
		}
	}

#  SERVICES WEB

	my %existe_ = ();
	my $ua = LWP::UserAgent->new(conn_cache => 1, ssl_opts => { verify_hostname => 0});
	$ua->conn_cache(LWP::ConnCache->new); # use connection cacheing (faster)
	$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027");
	open(webServicesDB, "<", "DB/web-services.db");
	my @parsewebServicesdb = <webServicesDB>;
	my $webServicesTestPage = $ua->get("http://$url/");
	my @webServicesStringMsg;
	foreach my $lineIDK (@parsewebServicesdb){
		push(@webServicesStringMsg, $lineIDK);
	}
	my $ws = "";
	foreach my $ServiceString (@webServicesStringMsg){
	$ws .= &matchScan($ServiceString,$webServicesTestPage->content,"Web service Found");
	}
	close(webServicesDB);
	$ws =~s/'/\\'/gi;
	$func->insert("UPDATE report SET web_services = '". $ws ."' WHERE report_id = $report_id");
	
#  FAVICON

	$ua = LWP::UserAgent->new(conn_cache => 1, ssl_opts => { verify_hostname => 0});
	$ua->conn_cache(LWP::ConnCache->new); # use connection cacheing (faster)
	$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027");
	my $favicon = $ua->get("http://$url/favicon.ico");
	if($favicon->is_success){
		my $fi = "";
		my $MD5 = Digest::MD5->new;
		$MD5->add($favicon->content);
		my $checksum = $MD5->hexdigest;
		open(faviconMD5DB, "<", "DB/favicon.db");
		my @faviconMD5db = <faviconMD5DB>;
		my @faviconMD5StringMsg; # split DB by line
		foreach my $lineIDK (@faviconMD5db){
			push(@faviconMD5StringMsg, $lineIDK);
		}
		foreach my $faviconMD5String (@faviconMD5StringMsg){

			$fi .= &matchScan($faviconMD5String,$checksum,"Web service Found (favicon.ico)");
		}
		close(faviconMD5DB);
		$fi =~s/'/\\'/gi;
		$func->insert("UPDATE report SET favicon = '". $fi ."' WHERE report_id = $report_id");

	}
#  INFO ERROR BEGGING
	my $err = "";
	$ua = LWP::UserAgent->new(conn_cache => 1, ssl_opts => { verify_hostname => 0});
	$ua->conn_cache(LWP::ConnCache->new); # use connection cacheing (faster)
	$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027");
	my $getErrorString = &genErrorString();
	my $_404responseGet = $ua->get("http://$url/$getErrorString");
	$err .= &checkError($_404responseGet);
	my $postErrorString = &genErrorString();
	my $_404responsePost = $ua->post("http://$url/$postErrorString");
	$err .= &checkError($_404responsePost);
	$err =~s/'/\\'/g;
	$err =~s/\r//;
	$err =~s/^\s*\n$//;
	$func->insert("UPDATE report SET info_de_erro = '". $err ."' WHERE report_id = $report_id");

	
#  TYPE ERROR
	my $te = "";
	my %existe_E = ();
	$ua = LWP::UserAgent->new(conn_cache => 1, ssl_opts => { verify_hostname => 0});
	$ua->conn_cache(LWP::ConnCache->new); # use connection cacheing (faster)
	$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027");
	# Some servers just give you a 200 with every req. lets see
	my @webExtentions = ('.php','.html','.htm','.aspx','.asp','.jsp','.cgi');
	foreach my $Extention (@webExtentions){
		my $testErrorString = &genErrorString();
		my $check200 = $ua->get("http://$url/$testErrorString" . $Extention);
		if($check200->is_success){
			if(!$existe_E{$Extention}){
				$te .= "http://$url/$testErrorString" . $Extention . " ". $conf{'lang49'} .": " . $check200->code . " ". $conf{'lang50'} .": $Extention " . $conf{'lang51'} . "\n";
				$existe_E{$Extention} = 1;
			}
		}
	}
	$te =~s/'/\\'/gi;
	$te =~s/\r//;
	$te =~s/^\s*\n$//;
	$func->insert("UPDATE report SET tipo_de_erro = '". $te ."' WHERE report_id = $report_id");
	
#  SERVER MOBILE

	$ua = LWP::UserAgent->new(conn_cache => 1, ssl_opts => { verify_hostname => 0});
	$ua->conn_cache(LWP::ConnCache->new); # use connection cacheing (faster)
	$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027");

	#does the site have a mobile page?
	my $MobileUA = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0});
	$MobileUA->agent('Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0');
	my $mobilePage = $MobileUA->get("http://$url/");
	my $regularPage = $ua->get("http://$url/");

	unless($mobilePage->content() eq $regularPage->content()){
		$conf{'lang54'} =~s/'/\\'/gi;
		$func->insert("UPDATE report SET server_movel = '". $conf{'lang54'} ."' WHERE report_id = $report_id");
	}


#  LANGUAGE

	my %existe_L = ();
	$ua = LWP::UserAgent->new(conn_cache => 1, ssl_opts => { verify_hostname => 0});
	$ua->conn_cache(LWP::ConnCache->new); # use connection cacheing (faster)
	$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027");
	# laguage checks
	my $LangReq = $ua->get($target);
	my @langSpaceSplit = split(/ / ,$LangReq->decoded_content);
	my $langString = 'lang=';
	my @langGate;
	my $lang = "";
	foreach my $lineIDK (@langSpaceSplit){
		if($lineIDK =~ /$langString('|").*?('|")/i){
			while($lineIDK =~ "\t"){ #make pretty
				$lineIDK =~ s/\t//sg;
			}
			while($lineIDK =~ /(<|>)/i){ #prevent html from sliping in
				chop $lineIDK;
			}
			unless($lineIDK =~ /lang=('|")('|")/){ # empty?
				if(!$existe_L{$lineIDK}){
					$lang .= $lineIDK . "\n";
					$existe_L{$lineIDK} = 1;
				}
			}
		}
	}
	$lang =~ s/'/\\'/g;
	
	$func->insert("UPDATE report SET lingua = '". $lang ."' WHERE report_id = $report_id");

#  INTERESTING STRINGS IN HTML

	my %existe_I = ();
	$ua = LWP::UserAgent->new(conn_cache => 1, ssl_opts => { verify_hostname => 0});
	$ua->conn_cache(LWP::ConnCache->new); # use connection cacheing (faster)
	$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027");

	my @interestingStings = ('/cgi-bin','password','passwd','admin','database','payment','bank','account','twitter.com','facebook.com','login','@.*?(com|org|net|tv|uk|au|edu|mil|gov)','<!--#');
	my $mineIndex = $ua->get($target);
	my $istr = "";
	foreach my $checkInterestingSting (@interestingStings){
		my @IndexData = split(/</,$mineIndex->decoded_content);
		foreach my $splitIndex (@IndexData){
			if($splitIndex =~ /$checkInterestingSting/i){
				while($splitIndex =~ /(\n|\t|  )/){
					$splitIndex =~ s/\n/ /g;
					$splitIndex=~ s/\t//g;
					$splitIndex=~ s/  / /g;
				}

				if(!$existe_I{$splitIndex}){
					$splitIndex =~ s/\n/\n| /g;
					$splitIndex =~ s/\r//g;
					#$splitIndex =~ s/'/\\'/g;
					$istr .= $splitIndex ."\n" if($splitIndex);
				}
			}
			
		}
	}
	$istr =~s/'/\\'/gi;
	$istr =~s/\r//;
	$istr =~s/^\s*\n$//;
	$func->insert("UPDATE report SET strings_interessantes = '". $istr ."' WHERE report_id = $report_id");


#  Function WHOIS
	my $wr = "";
	my @connect = `whois $url`;
	foreach my $d (@connect){
		push(@arq,$d);
	}

	foreach my $d (@arq){
		$d =~s/\n//;
		if($d !~/^\n|^\r|^\s|^%/ && length($d) > 6){
			$d =~ s/\|//g;
			$wr .= $d . "\n";
		}
	}
	$wr =~ s/'/\\'/g;
	$wr =~s/\r//;
	$wr =~s/^\s*\n$//;

	$func->insert("UPDATE report SET whois = '". $wr ."' WHERE report_id = $report_id");

}

sub host(){
  	my $h = shift;
  	my $url1 = URI->new( $h);
  	return $url1->host();
}


##############################################
#  Function write
#  this function write a text in a file
#
#  Param: $file_name, @content
#  Return: nothing
##############################################

#code below taken from the project web-sorrow
sub genErrorString{
	my $errorStringGGG = "";
        my $i = 0;
	for($i = 0;$i < 20;$i++){
		$errorStringGGG .= chr((int(rand(93)) + 33)); # random 20 bytes to invoke 404 sometimes 400
	}
	$errorStringGGG =~ s/(#|&|\?)//g; #strip anchors and q stings
	return $errorStringGGG;
}
#code below taken from the project web-sorrow
sub matchScan{
	my $checkMatchFromDB = shift;
	my $checkMatch = shift;
	my $matchScanMSG = shift;
	my $ret = "";
	chomp $checkMatchFromDB;
	my @matchScanLineFromDB = split(';',$checkMatchFromDB);
	my $msJustString = $matchScanLineFromDB[0]; #String to find
	my $msMSG = $matchScanLineFromDB[1]; #this is the message printed if it isn't an error
	if($checkMatch =~ /$msJustString/){
		$matchScanMSG =~ s/\r|\n//g;
		$msMSG =~ s/\r|\n//g;
		$ret .= "$msMSG\n";
		$drupal = 1 if($msMSG =~ /drupal/i);
		$joomla = 1 if($msMSG =~ /joomla/i);
		$wordpress = 1 if($msMSG =~ /wordpress/i);
	}
	return $ret;
}
#code below taken from the project web-sorrow
sub checkError{
	my $_404response = shift;
	my $err = "";
	if($_404response->is_error) {
		my $siteHTML = $_404response->decoded_content;
		$siteHTML =~ s/<script.*?<\/script>//sgi;
		$siteHTML =~ s/<style.*?<\/style>//sgi;
		$siteHTML =~ s/<(?!--)[^'">]*"[^"]*"/</sgi;
		$siteHTML =~ s/<(?!--)[^'">]*'[^']*'/</sgi;
		$siteHTML =~ s/<(?!--)[^">]*>//sgi;
		$siteHTML =~ s/<!--.*?-->//sgi;
		$siteHTML =~ s/<.*?>//sgi;
		$siteHTML =~ s/\n/ /sg;
		while($siteHTML =~ "  "){
			$siteHTML =~ s/  / /g;
		}
		while($siteHTML =~ "\t"){
			$siteHTML =~ s/\t//sg;
		}
		my $siteNaked = $siteHTML;
		if(length($siteNaked) < 1000){
			$err .= $siteNaked . "\n";
		} 
	}
	return $err;
}
#code below taken from the project web-sorrow
##############################################
#  BANNER GRABING
##############################################

sub bannergrabing(){

	my $target = shift;
	%existe = ();
	my $ban = "";
	my $ua = LWP::UserAgent->new(conn_cache => 1);
	$ua->conn_cache(LWP::ConnCache->new); # use connection cacheing (faster)
	$ua->agent("Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027");
	my @checkHeaders = ('x-meta-generator:','x-meta-framework:','x-meta-originator:','x-aspnet-version:','www-authenticate:','x-xss.*:', 'refresh:', 'location:');
	my $resP = $ua->get($target);
	my $url = &host($target);
	my $page_content = $resP->decoded_content;
	my $headers = $resP->as_string();
	my @headersChop = split("\n\n", $headers);
	my @headers = split("\n", $headersChop[0]);
        if($HString =~ /wordpress/gi or $page_content =~/Powered by <a href="http:\/\/wordpress\.org\/"><strong>WordPress<\/strong><\/a>/gi){
		$wordpress = 1; 
		$ban .= "WordPress\n";
	}
#        $ban .= "WordPress\n" if ($page_content =~/Powered by <a href="http:\/\/wordpress\.org\/"><strong>WordPress<\/strong><\/a>/gi);

	foreach my $HString (@headers){
		foreach my $checkSingleHeader (@checkHeaders){
			if($HString =~ /$checkSingleHeader/i){
				if(!$existe{$HString}){
					$ban .= $HString;
					$existe{$HString} = 1;
					$wordpress = 1 if($HString =~ /wordpress/gi);
					$drupal = 1 if($HString =~ /drupal/gi);
					$joomla = 1 if($HString =~ /joomla/gi);
				}
			}
		}
	}
	$ban =~s/'/\\'/gi;
	$func->insert("UPDATE report SET banner_grab = '". $ban ."' WHERE report_id = $report_id");

#	my $dir = "";
#	if($joomla == 1){
#		foreach my $d ($func->Check('http://' . $url . "/", "DB/joomla_plugins.db")){
#			$dir .= $d . "\n";
#		}
#	}
#	if($wordpress == 1){ 
#		foreach my $d ($func->Check('http://' . $url . "/", "DB/wp_plugins.db")){
#			$dir .= $d . "\n";
#		}
#	}
#	if($drupal == 1){ 
#		foreach my $d ($func->Check('http://' . $url . "/", "DB/drupal_plugins.db")){
#			$dir .= $d . "\n";
#		}
#	}
#	$dir =~s/'/\\'/gi;
#	$func->insert("UPDATE report SET banner_result = '". $dir ."' WHERE report_id = $report_id");

}
