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
my $semaphore = Thread::Semaphore->new();


our @RFI = ('http://www.on-security.com/c.txt?');
my $t = threads->new(\&online);
&ScanRFICrawler(@urls);	
&ScanRFICrawlerPost(@urls);
$vuls =~s/'/\\'/gi;
$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$vuls', $arqs, $arqv, $varst, $vvar, $requests, 22)");
$func->insert("UPDATE historico SET rfi = $vvar WHERE report_id= $report_id");
	        while($q->pending > 0){
	                $q->dequeue;
	        }
$t->join();



sub ScanRFICrawler(){
	my @urls = @_;
	my @tests = &GenerateTests("RFI", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestRFI", @tests) if(scalar(@tests));
}

sub ScanRFICrawlerPost(){
	my @urls = @_;
	my @tests = &GenerateTestsPost("RFI", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestRFIPost", @tests) if(scalar(@tests));
}

sub TestRFI(){
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
			if($resp =~/$conf{'rfi_return'}/){
				$vuls .= "$test\n";
				&metricas_vul($test);
			}
			$resp = 0;
		}
	}
	$q->enqueue(undef);
}


##############################################
#  Function TestRFIPost
#  this function test RFI Vulnerabilities 
#  on forms
#
#  Param: $test
#  Return: nothing
##############################################

sub TestRFIPost(){

	my ($resp, $test) = 0;
	while($q->pending > 0){
		$semaphore->down();
		$test = $q->dequeue;
		$semaphore->up();
		next if(not defined $test);
		next if($test !~/\|#\|/g);
		if(!$varvul{&gera_var_vul($test)}){
			my ($url, $data) = split('\|#\|', $test);
			&metrica_testados($url. "|#|" .$data);
			$resp = $http->POST($url, $data);
			$requests++;
			if($resp =~/$conf{'rfi_return'}/){
				$vuls .= $url . "|#|" . $data . "\n";
				&metricas_vul($url . "|#|" . $data);
			}
			$resp = 0;
		}
	}
	$q->enqueue(undef);
}



##############################################
#  Function GenerateTests
#  this function generate the tests
#
#
#  Param: $test, @list
#  Return: @list_of_tests
##############################################

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
  

##############################################
#  Function threadnize
#  this function threadnize any function in this
#  module
#
#  Param: $function, @tests
#  Return: nothing
##############################################


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

