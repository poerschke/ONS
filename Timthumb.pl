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
our %arqvul : shared = ();
our $arqv : shared = 0;



our $report_id :shared = $ARGV[0];
my @urls = $func->pega_dados_crawler($report_id);


	my %checks = ();
	my $protocol;
	my @check;
	my @files = (
		"timthumb.php",
"thumb.php",
"check.php",
"uploadify.php"
	);
my $t = threads->new(\&online);

	foreach my $d (@urls){
		$protocol = 'http://' if($d =~/^http:\/\//);
		$protocol = 'https://' if($d =~/^https:\/\//);
		$d =~s/https?:\/\///g;
		$d = substr($d, 0, rindex($d, '/'));
		while($d =~/\//){
			$d = substr($d, 0, rindex($d, '/'));
			foreach my $f (@files){
				my $u = $protocol . $d . '/' . $f;
				if(!$checks{$u}){
					$checks{$u} = 1;
					push(@check, $u);
				 }
			}
		}
	}


	&threadnize(@check);
$vuls =~s/'/\\'/gi;
$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$vuls', $arqs, $arqv, 0, 0, $requests, 26)");
$func->insert("UPDATE historico SET timthumb = $arqv WHERE report_id= $report_id");
	        while($q->pending > 0){
	                $q->dequeue;
	        }
$t->join();


sub findtimthumb(){
	my @matches = (
		"TimThumb version : (.+)<\/pre>",
	);

	while($q->pending() > 0){
		$semaphore->down();
		my $url1 = $q->dequeue;
		$semaphore->up();
		next if(not defined $url1);
		next if($url1 =~/\|#\|/g);
		
		my $result = $http->GET($url1);
		&metrica_testados($url1);
		$requests++;
		foreach my $mat (@matches){
			if($result =~ m/$mat/gi){
				$vuls .= "$url1\n" if($1 < 1.33);
				&metricas_vul($url1);
			}
		}
	}
	$q->enqueue(undef);
}

sub threadnize(){
	my @tests = @_;
	foreach my $test (@tests){
		$q->enqueue($test) if($test);
	} 
	my $x=0;
	my @threads = ();
	while($q->pending() && $x <= $conf{'max_threads'}-1){
		push @threads, threads->new(\&findtimthumb);
		$x++;
	}

	sleep(2);
	foreach my $running (@threads) {
		$running->join();
		
	}
	@threads = ();
}




sub metricas_vul(){
	my $url = shift;
	if(!$arqvul{$func->get_file($url)}){
		$arqvul{$func->get_file($url)} = 1;
		$arqv++;
	}
}

sub metrica_testados(){
	my $url = shift;
	if(!$testado{$func->get_file($url)}){
		$testado{$func->get_file($url)}=1;
		$arqs++;
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

