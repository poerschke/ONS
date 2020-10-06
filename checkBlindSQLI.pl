#!/usr/bin/perl


use Uniscan::Configure;
use Uniscan::Functions;
use Uniscan::Http;
use threads;
use threads::shared;
use Thread::Queue;
use Thread::Semaphore;
use strict;

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
our $qv :shared = 0;



our $report_id :shared = $ARGV[0];

my @urls = $func->pega_dados_crawler($report_id);
my $t = threads->new(\&online);
&threadnize("CheckNoError", @urls) if(scalar(@urls));
$vuls =~s/'/\\'/gi;
$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$vuls', $arqs, $arqv, $varst, $vvar, $requests, 18)");
$func->insert("UPDATE historico SET blind = $vvar WHERE report_id= $report_id");
while($q->pending > 0){
        $q->dequeue;
}

$t->join();

sub CheckNoError(){
	
	while($q->pending > 0){
		$semaphore->down();
		my $url = $q->dequeue;
		$semaphore->up();
		next if(not defined $url);
		next if($url =~/\|#\|/);
		next if($url =~/\/\?S=A|\/\?N=D|\/\?S=D|\/\?D=A|\/\?N=A|\/\?M=D|\/\?M=A|\/\?D=D|\/\?D=A/g);
		if($url !~/#/){
			
			if($url =~/\?/){
				
				my ($url1, $vars) = split('\?', $url);
				if(!$testado{$url1}){
					$testado{$url1}=1;
					$arqs++;
				}
				my @var = split('&', $vars);
				foreach my $v (@var){
					my ($vv, $valor) = split('=', $v);
					if(!$vtestado{$url1.$vv}){
						$varst++;
						$vtestado{$url1.$vv} = 1;
						TestNoError($url, $v);
					}
					
				}
			}
		}
	}
	$q->enqueue(undef);
}


sub TestNoError(){
	my ($url, $var) = @_;
	$url =~s/&\Q$var\E//g;
	$url =~s/\Q$var\E//g;
	$url .= "&" . $var;
	$url =~s/\?&/\?/g;
	my ($v, $valor) = split('=', $var);
	
	# teste numérico
	if ($valor =~/^\d+$/) {
		my $url1 = $url;
		my $url2 = $url;
		my $url3 = $url;
		my $url4 = $url;
		my $rand = int(rand(10000));
		$url3 = $url;
		$url3 = s/\Q$valor\E/$rand/g;
		$url1 =~ s/\Q$var\E/$var\+AND\+1=1/g;
		$url2 =~ s/\Q$var\E/$var\+AND\+1=2/g;
		
		my $r1 = $http->GET($url);
		$requests++;

		my $r2 = $http->GET($url);
		$requests++;

		my $r4 = $http->GET($url2);
		$requests++;

		my $r5 = $http->GET($url1);
		$requests++;
		
		$r1 = &transform($r1);
		$r2 = &transform($r2);
		$r5 = &transform($r5);
		$r4 = &transform($r4);
		my $s = &get_keyword($url, $url3);
		my @w1 = split(' ', $s);
		my $keyword = "";
		my $key = 0;
		if($r4 ne "" && $r5 ne "" && $r1 ne "" && $r2 ne ""){
			foreach my $word (@w1){
				if(($r2 =~ /\Q$word\E/g) && ($r4 !~ /\Q$word\E/g) && (length($word) > 5) && ($word =~ /^\w+$/g)){
					if($key == 0){
						$key =1;
						$keyword = $word;
					}
				}
			}
		
			if(($r5 =~/\Q$keyword\E/g) && ($key == 1) && ($r5 !~/<b>Warning<\/b>/si) && ($r4 !~/\Q$keyword\E/g)){
				if(&sqlmap($url,$v)){
					$vuls .= "$url1\n";
					print "$url\n$keyword\n";
					$qv++;
				
					if(!$arqvul{$func->get_file($url1)}){
						$arqvul{$func->get_file($url1)} = 1;
						$arqv++;
					}
					my ($vv, $valor) = split('=', $var);
					if(!$varvul{$func->get_file($url1).$vv}){
						$vvar++;
					}
				}
			}
		}
		
	}
	



	# teste com valor sendo string
	if ($valor =~/^[a-z]|^\d/i) {

		my $url1 = $url;
		my $url2 = $url;
		my $url3 = $url;
		my $url4 = $url;
		my $rand = int(rand(10000));
		$url3 = $url;
		$url3 = s/\Q$valor\E/$rand/g;
		$url1 =~s/\Q$var\E/$var'\+AND\+'1'='1/g;
		$url2 =~s/\Q$var\E/$var'\+AND\+'1'='2/g;
		
		my $r1 = $http->GET($url);
		$requests++;

		my $r2 = $http->GET($url);
		$requests++;

		my $r4 = $http->GET($url2);
		$requests++;

		my $r5 = $http->GET($url1);
		$requests++;
		
		$r1 = &transform($r1);
		$r2 = &transform($r2);
		$r5 = &transform($r5);
		$r4 = &transform($r4);
	
		my @w1;
		if($valor =~/^\d+$/){
			@w1 = split(' ', &get_keyword($url, $url3));
		}
		else{
			@w1 = split(' ', $r1);
		}
		my $keyword = "";
		my $key = 0;
		if($r4 ne "" && $r5 ne "" && $r1 ne "" && $r2 ne ""){
			foreach my $word (@w1){
				if(($r2 =~ /\Q$word\E/g) && ($r4 !~ /\Q$word\E/g) && (length($word) > 5) && ($word =~ /^\w+$/g)){
					if($key == 0){
						$key =1;
						$keyword = $word;
					}
				}
			}
		
			if(($r5 =~/\Q$keyword\E/g) && ($key == 1) && ($r5 !~/<b>Warning<\/b>/si) && ($r4 !~/\Q$keyword\E/g)){
				if(&sqlmap($url,$v)){
					$vuls .= "$url1\n";
					print "$url\n$keyword\n";
					$qv++;
				
					if(!$arqvul{$func->get_file($url1)}){
						$arqvul{$func->get_file($url1)} = 1;
						$arqv++;
					}
					my ($vv, $valor) = split('=', $var);
					if(!$varvul{$func->get_file($url1).$vv}){
						$vvar++;
					}
				}
			}

		}
	}
	



	# teste com valor como string usando "
	if ($valor =~/^[a-z]|^\d/i) {
		my $url1 = $url;
		my $url2 = $url;
		my $url3 = $url;
		my $url4 = $url;
		my $rand = int(rand(10000));
		$url3 = $url;
		$url3 = s/\Q$valor\E/$rand/g;
		$url1 =~s/\Q$var\E/$var"\+AND\+"1"="1/g;
		$url2 =~s/\Q$var\E/$var"\+AND\+"1"="2/g;
		
		my $r1 = $http->GET($url);
		$requests++;

		my $r2 = $http->GET($url);
		$requests++;

		my $r4 = $http->GET($url2);
		$requests++;

		my $r5 = $http->GET($url1);
		$requests++;
		
		$r1 = &transform($r1);
		$r2 = &transform($r2);
		$r5 = &transform($r5);
		$r4 = &transform($r4);
		my @w1;
		if($valor =~/^\d+$/){
			@w1 = split(' ', &get_keyword($url, $url3));
		}
		else{
			@w1 = split(' ', $r1);
		}
		my $keyword = "";
		my $key = 0;
		if($r4 ne "" && $r5 ne "" && $r1 ne "" && $r2 ne ""){
			foreach my $word (@w1){
				if(($r2 =~ /\Q$word\E/g) && ($r4 !~ /\Q$word\E/g) && (length($word) > 5) && ($word =~ /^\w+$/g)){
					if($key == 0){
						$key =1;
						$keyword = $word;
					}
				}
			}
		
			if(($r5 =~/\Q$keyword\E/g) && ($key == 1) && ($r5 !~/<b>Warning<\/b>/si) && ($r4 !~/\Q$keyword\E/g)){
				if(&sqlmap($url,$v)){
					$vuls .= "$url1\n";
					print "$url\n$keyword\n";
					$qv++;
				
					if(!$arqvul{$func->get_file($url1)}){
						$arqvul{$func->get_file($url1)} = 1;
						$arqv++;
					}
					my ($vv, $valor) = split('=', $var);
					if(!$varvul{$func->get_file($url1).$vv}){
						$vvar++;
					}
				}
			}
		}

	}
}


 sub threadnize(){
	my ($fun, @tests) = @_;
	foreach my $test (@tests){
		$q->enqueue($test) if($test && $test =~/=/);
	}

	my $x=0;
	my @threads = ();
	while($q->pending() && $x <=  $conf{'max_threads'}-1){
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



sub transform(){
	my $r1 = shift;
	$r1 =~s/<.+?>//g;
	my @re = split("\n", $r1);
	my $r1 = "";
	foreach my $r (@re){
		chomp($r);
		$r1 .= " " . $r;
	}
	$r1 =~ s/<script.+?<\/script>//gi;
	$r1 =~s/<!DOCTYPE HTML PUBLIC ".+?">//gi;
	return $r1;
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

sub get_keyword(){
	my $ori = shift;
	my $mod = shift;
	my $h = Uniscan::Http->new();
	my $r1 = $h->GET($ori);
	my $r2 = $h->GET($mod);
	$r1 = &transform($r1);
	$r2 = &transform($r2);
	my @w = split(' ', $r1);
	my $string = "";
	foreach my $word (@w){
		$string .= $word . " " if($r2 !~/\Q$word\E/);
	}
	return $string;
}



sub sqlmap($$){
	my $url = shift;
	my $param = shift;
	my $sqlmap = "/opt/ONS/sqlmap/sqlmap.py -u '". $url ."' -p ". $param ." --batch --purge-output";
	my $ret = `$sqlmap`;
	if($ret =~/sqlmap identified the following injection/gi){
		print "SQLMAP: 1\n";
		return 1;
	}
	else{
		print "SQLMAP: 0\n";
		return 0;
	}
}
