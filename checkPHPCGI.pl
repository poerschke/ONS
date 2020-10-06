#!/usr/bin/perl


use Uniscan::Configure;
use Uniscan::Functions;
use Uniscan::Http;
use threads;
use threads::shared;
use Thread::Queue;
use Thread::Semaphore;

my $c = Uniscan::Configure->new(conffile => "uniscan.conf");
my $func = Uniscan::Functions->new();
my $q = new Thread::Queue;
my @vulns = ();
my $semaphore = Thread::Semaphore->new();
our $qv : shared = 0;
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

our $report_id :shared= $ARGV[0];
my @urls = $func->pega_dados_crawler($report_id);

my $t = threads->new(\&online);
@urls = &generate(@urls);
&CheckVulns(@urls);
$vuls =~s/'/\\'/gi;
$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$vuls', $arqs, $arqv, 0, 0, $requests, 20)");
$func->insert("UPDATE historico SET phpcgi = $arqv WHERE report_id= $report_id");
	        while($q->pending > 0){
	                $q->dequeue;
	        }
$t->join();


sub generate(){
	my @urls = @_;
	my @ret = ();
	foreach $url (@urls){
		chomp $url;
		substr($url, index($url, '?'), length($url)) = "" if($url =~ /\?/);
		$url = substr($url, 0, index($url, '|#|')-1) if($url =~/\|#\|/);
		push(@ret, $url) if($url =~/\.php$/i);
	}
	return @ret;
}

sub CheckVulns(){
	my @files = @_;
	my @xpl = ('?-s');
	my %bkp = ();
	my @file = ();
	my $url = "";
	foreach my $f (@files){
		chomp($f);
		next if($f =~/\|#\|/);
		foreach my $b (@xpl){
			if(!$bkp{$f.$b}){
				push(@file, $f.$b);
				$bkp{$f.$b} = 1;
			}			
		}
	}
	&threadnize("GetResponse", @file) if(scalar(@file));
}


sub GetResponse(){
	my $http = Uniscan::Http->new();
	while($q->pending() > 0){
		$semaphore->down();
		my $url1 = $q->dequeue;
		$semaphore->up();
		next if(not defined $url1);
		next if($url1 =~/#/);
		my $response = $http->GET($url1);
		$requests++;
		&metrica_testados($url1);
		if($response =~ /<code>.+\n<span style="color: #0000BB">/gi && $response =~ /&lt;\?/gi){
			$vuls .= $url1."\n";
			$qv++;
			&metricas_vul($url1);
		}
	}
	$q->enqueue(undef);
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

