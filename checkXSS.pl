#!/usr/bin/perl -w

use lib "./Uniscan";
use Uniscan::Configure;
use Uniscan::Functions;
use Uniscan::Http;
use threads;
use threads::shared;
use Thread::Queue;
use Thread::Semaphore;

my $c = Uniscan::Configure->new(conffile => "uniscan.conf");
my $func = Uniscan::Functions->new();
my $http = Uniscan::Http->new();
my $q = new Thread::Queue;
my %xsss = ();
	
our %conf = ( );
%conf = $c->loadconf();
$|++;

#metricas
our $requests : shared = 0;
our %testado : shared = ();
our $arqs : shared = 0;
our $vuls : shared = "";
our %vtestado : shared = ();
our $varst : shared = 0;
our %varvul : shared = ();
our $vvar : shared = 0;
our %arqvul : shared = ();
our $arqv : shared = 0;

our $report_id :shared= $ARGV[0];
my @urls = $func->pega_dados_crawler($report_id);
my $semaphore = Thread::Semaphore->new();


our @XSS = (
	"\"><script>alert('XSS')</script>",
	"<script>alert('XSS')</script>",
	"<IMG SRC=\"javascript:alert('XSS');\">",
	"\"><IMG SRC=\"javascript:alert('XSS');\">",
	"<IMG SRC=javascript:alert(&quot;XSS&quot;)>",
	"\"><IMG SRC=javascript:alert(&quot;XSS&quot;)>",
	"<IMG SRC=\"javascript:alert('XSS')\"",
	"\"><IMG SRC=\"javascript:alert('XSS')\"",
	"<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">",
	"\"><LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">",
	"<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">",
	"\"><META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">",
	"<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">",
	"\"><DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">",
	"<body onload=\"javascript:alert('XSS')\"></body>",
	"\"><body onload=\"javascript:alert('XSS')\"></body>",
	"<table background=\"javascript:alert('XSS')\"></table>",
	"\"><table background=\"javascript:alert('XSS')\"></table>",
);
my $t = threads->new(\&online);
&ScanXSSCrawler(@urls);	
&ScanXSSCrawlerPost(@urls);
$vuls =~s/'/\\'/g;
$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$vuls', $arqs, $arqv, $varst, $vvar, $requests, 24)");
$func->insert("UPDATE historico SET xss = $vvar WHERE report_id= $report_id");
	        while($q->pending > 0){
	                $q->dequeue;
	        }
$t->join();




sub ScanXSSCrawler(){
	my @urls = @_;
	my @tests = &GenerateTests("XSS", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestXSS", @tests) if(scalar(@tests));
}

sub ScanXSSCrawlerPost(){
	my @urls = @_;
	my @tests = &GenerateTestsPost("XSS", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestXSSPost", @tests) if(scalar(@tests));
}


sub TestXSS(){
	while($q->pending > 0){
		$semaphore->down();
		my $test = $q->dequeue;
		$semaphore->up();
		next if(not defined $test);
		next if($test =~/\|#\|/g);
		if(!$varvul{&gera_var_vul($test)}){
			&metrica_testados($test);
			my $resp = $http->GET($test);
			$requests++;
			if($resp =~ m/<[\w|\s|\t|\n|\r|'|"|\?|\[|\]|\(|\)|\*|&|%|\$|#|@|!|\|\/|,|\.|;|:|\^|~|\}|\{|\+|\-|=|_]+>[_|=|\w|\s|\t|\n|\r|'|"|\?|\[|\]|\(|\)|\*|&|%|\$|#|@|!|\|\/|,|\.|;|:|\^|~|\}|\{|\+|\-]*(<script>alert\('XSS'\)<\/script>|<XSS>|<IMG SRC=\"javascript:alert\('XSS'\);\">|<IMG SRC=javascript:alert\(&quot;XSS&quot;\)>|<IMG SRC=javascript:alert\(String.fromCharCode\(88,83,83\)\)>|<IMG SRC=javascript:alert('XSS')>|<IMG SRC=\"javascript:alert\('XSS'\)\">|<LINK REL=\"stylesheet\" HREF=\"javascript:alert\('XSS'\);\">|<IMG SRC='vbscript:msgbox\(\"XSS\"\)'>|<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http:\/\/;URL=javascript:alert\('XSS'\);\">|<DIV STYLE=\"background-image: url\(javascript:alert\('XSS'\)\)\">|<body onload=\"javascript:alert\('XSS'\)\"><\/body>|<table background=\"javascript:alert\('XSS'\)\"><\/table>).*</i){
				$vuls .= $test . "\n";
				&metricas_vul($test);
			}
			$resp = 0;
		}
	}
	$q->enqueue(undef);
}



sub TestXSSPost(){
	while($q->pending > 0){
		$semaphore->down();
		my $test = $q->dequeue;
		$semaphore->up();
		next if(not defined $test);
		next if($test !~/\|#\|/g);
		if(!$varvul{&gera_var_vul($test)}){
			my ($url, $data) = split('\|#\|', $test);
			&metrica_testados($url ."|#|". $data);
			my $resp = $http->POST($url, $data);
			$requests++;
			if($resp =~ m/<[\w|\s|\t|\n|\r|'|"|\?|\[|\]|\(|\)|\*|&|%|\$|#|@|!|\|\/|,|\.|;|:|\^|~|\}|\{|\+|\-|=|_]+>[_|=|\w|\s|\t|\n|\r|'|"|\?|\[|\]|\(|\)|\*|&|%|\$|#|@|!|\|\/|,|\.|;|:|\^|~|\}|\{|\+|\-]*(<script>alert\('XSS'\)<\/script>|<XSS>|<IMG SRC=\"javascript:alert\('XSS'\);\">|<IMG SRC=javascript:alert\(&quot;XSS&quot;\)>|<IMG SRC=javascript:alert\(String.fromCharCode\(88,83,83\)\)>|<IMG SRC=javascript:alert('XSS')>|<IMG SRC=\"javascript:alert\('XSS'\)\">|<LINK REL=\"stylesheet\" HREF=\"javascript:alert\('XSS'\);\">|<IMG SRC='vbscript:msgbox\(\"XSS\"\)'>|<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http:\/\/;URL=javascript:alert\('XSS'\);\">|<DIV STYLE=\"background-image: url\(javascript:alert\('XSS'\)\)\">|<body onload=\"javascript:alert\('XSS'\)\"><\/body>|<table background=\"javascript:alert\('XSS'\)\"><\/table>).*</i){
				$vuls .= $url . "|#|" . $data . "\n";
				&metricas_vul($url . "|#|" . $data);
			}
			$resp = 0;
		}
	}
	$q->enqueue(undef);
}


sub GenerateTests(){
	my ($test, @list) = @_;
	my @list2 = ();
	foreach my $line (@list){
		$line =~ s/&amp;/&/g;
		$line =~ s/\[\]//g;
		if($line =~ /=/ && $line !~/\|#\|/){
			my $temp = $line;
			$temp = substr($temp,index($temp, '?')+1,length($temp));
			my @variables = split('&', $temp);
			for(my $x=0; $x< scalar(@variables); $x++){
				my $var_temp = substr($variables[$x],0,index($variables[$x], '=')+1);
				no strict 'refs';
				if($var_temp){
					foreach my $str (@{$test}){
						$temp = $line;
#						$str = urlencode($str) if($conf{'url_encode'} == 1);
						my $t = $var_temp . $str;
						$temp =~ s/\Q$variables[$x]\E//g;
						$temp .= '&' .$t;
						$temp =~s/\?&/\?/g;
						$temp =~s/&&/&/g;
						if(!$xsss{$temp}) {
							push(@list2, $temp);
							$xsss{$temp} = 1;
						}
					}
				}
			}
		@variables = ();
		}
		if($line =~/\?/){
			my $l = substr($line, 0, index($line, '?')+1);
			foreach my $f (@XSS){
				if(!$xsss{$l.$f}){
					push(@list2, $l.$f);
					$xsss{$l.$f} = 1;
				}
			}
		} 
	}
	@list = ();
	return @list2;
}

sub GenerateTestsPost(){
  	my ($test, @list) = @_;
  	my @list2 = ();
  	foreach my $line (@list){
		next if($line !~/\|#\|/);
  		my ($url, $line) = split('\|#\|', $line);
  		$line =~ s/&amp;/&/g;
  		$line =~ s/\[\]//g;
  		if($line =~ /=/){
  			my $temp = $line;
  			$temp = substr($temp,index($temp, '?')+1,length($temp));
  			my @variables = split('&', $temp);
  			for(my $x=0; $x< scalar(@variables); $x++){
  				my $var_temp = substr($variables[$x],0,index($variables[$x], '=')+1);
  				no strict 'refs';
  				if($var_temp){
  					foreach my $str (@{$test}){
  						$temp = $line;
#  						$str = urlencode($str) if($conf{'url_encode'} == 1);
  						my $t = $var_temp . $str;
						$temp =~ s/\Q$variables[$x]\E//g;
						$temp .= '&' .$t;
						$temp =~s/\?&/\?/g;
						$temp =~s/&&/&/g;
						if(!$xsss{$url . '|#|' .$temp}){
							push(@list2, $url . '|#|' .$temp);
							$xsss{$url . '|#|' .$temp} = 1;
						}
  					}
  				}
  			}
  		}
  	}
  	@list = ();
  	return @list2;
 }


 sub threadnize(){
	my ($fun, @tests) = @_;
	foreach my $test (@tests){
		$q->enqueue($test) if($test);
	}

	my $x=0;
	my @threads = ();
	while($q->pending() && $x <= $conf{'max_threads'}-1){
		no strict 'refs';
		push @threads, threads->new(\&{$fun});
		$x++;
	}

	sleep(2);
	foreach my $running (@threads) {
		$running->join();
	}
	@threads = ();
}


sub gera_var_vul(){
	my $url = shift;
	my $varl = substr($url, rindex($url, '&')+1, length($url));
	my ($var, $valor) = split('=', $varl);
	my $str = $func->get_file($url) . $var;
	return $str;
	
}

sub metricas_vul(){
	my $url = shift;
	if(!$arqvul{$func->get_file($url)}){
		$arqvul{$func->get_file($url)} = 1;
		$arqv++;
	}
	
	if(!$varvul{&gera_var_vul($url)}){
		$varvul{&gera_var_vul($url)} = 1;
		$vvar++;
	}
}

sub metrica_testados(){
	my $url = shift;
	if(!$testado{$func->get_file($url)}){
		$testado{$func->get_file($url)}=1;
		$arqs++;
	}
	if(!$vtestado{&gera_var_vul($url)}){
		$vtestado{&gera_var_vul($url)}=1;
		$varst++;
	}	
}


sub checa_online(){
        my $h = Uniscan::Http->new();
        my $x=0;
        my $site = $func->pega_site($report_id);
        while ($x<=10) {
                my $res = $h->GET1($site);
                if ($res->is_success) {
                        return 1;
                }
                else{
                        sleep(30);
                }
                $x++;
        }
        &grava_waf();
        return 0;
}

sub grava_waf(){
        $func->insert("UPDATE report SET waf=1 WHERE report_id=". $report_id);
}

sub online(){
        while(checa_online() && $q->pending > 0){
                sleep(10);
        }
	#exit();
        while($q->pending > 0){
                $q->dequeue;
        }
}

