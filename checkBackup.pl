#!/usr/bin/perl -w

use Uniscan::Configure;
use Uniscan::Functions;
use Uniscan::Http;
use threads;
use threads::shared;
use Thread::Queue;
use Thread::Semaphore;
use LWP::Protocol::https;


my $c = Uniscan::Configure->new(conffile => "uniscan.conf");
my $func = Uniscan::Functions->new();
my $http = Uniscan::Http->new();
my $q = new Thread::Queue;
my @bkpf :shared = ();
my $semaphore = Thread::Semaphore->new();
our %conf = ( );
%conf = $c->loadconf();
$|++;

#metricas
our $requests : shared = 0;
our %testado : shared = ();
our $arqs : shared = 0;
our $vuls : shared = "";
our $qv :shared =0;

our $report_id :shared = $ARGV[0];

my @urls = $func->pega_dados_crawler($report_id);


	my $u = "";
	foreach (@urls){
		if(/^https?:\/\//){
			$u = $_;
			last;
		}
	}
	substr($u, index($u, '?'), length($u)) = "" if($u =~/\?/g);
	$u = substr($u, 0, rindex($u, '/'));
	my $req = $u . '/testing123/';
	my $r = $http->HEAD($req);
	$requests++;

	if($r->code =~/404/){
		my $t = threads->new(\&online);
		&threadnize("checkNoExist", @urls);
		&CheckBackupFiles(@bkpf);
		$vuls =~s/'/\\'/gi;
		$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$vuls', $arqs, 0, 0, 0, $requests, 17)");
		$func->insert("UPDATE historico SET backup = $qv WHERE report_id= $report_id");
	        while($q->pending > 0){
	                $q->dequeue;
	        }
		$t->join();
	}
	else{
                $func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '', 0, 0, 0, 0, 0, 17)");
                $func->insert("UPDATE historico SET backup = 0 WHERE report_id= $report_id");
	}
	



sub CheckBackupFiles(){
	my @files = @_;
	
	my @backup = (	'.bkp',
			'~',
		    );
	my %bkp = ();
	my @file = ();
	my $url = "";
	foreach my $f (@files){
		chomp($f);
		next if($f =~/#/);
		$url = $func->get_url($f);
		my $fi = $func->get_file($f);
		if(!$testado{$fi}){
			$arqs++;
			$testado{$fi} =1;
		}
		substr($fi, length($fi)-1, length($fi)) = "" if(substr($fi, length($fi)-1, length($fi)) eq "/");
		foreach my $b (@backup){
			my $fil = $fi . $b;
			if(!$bkp{$fil}){
				push(@file, $url.$fil) if($fil =~/\//);
				$bkp{$fil} = 1;
			}
			
		}
	}
	checkBackup(@file);
}




sub checkBackup(){
	my @bkp = @_;
	&threadnize("GetResponse", @bkp) if(scalar(@bkp));
}


sub GetResponse(){
	my $h = Uniscan::Http->new();
	while($q->pending() > 0){
		$semaphore->down();
		my $url1 = $q->dequeue;
		$semaphore->up();
		next if(not defined $url1);
		next if($url1 !~/^https?:\/\//);
		next if($url1 =~/#/);
		my $response=$h->HEAD($url1);
		$requests++;
		if($response){
			if($response->code =~ /200/){
				$vuls .= "$url1\n";
				$qv++;
			}
		}
	}
	$q->enqueue(undef);
}


sub threadnize(){
	my ($fun, @tests) = @_;
	$tests[0] = 0;
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


sub checkFile(){
	my $url1 = shift;
	
	if($url1 =~/^https?:\/\//){
		my $h = Uniscan::Http->new();
                my $response=$h->HEAD($url1);
		$requests++;
                return 1 if($response->code =~ /200/);
	}
	return 0;
}

sub checkNoExist(){
	while($q->pending() > 0){
		$semaphore->down();
		my $url1 = $q->dequeue;
		$semaphore->up();
		next if(not defined $url1);
		$url1 = substr($url1, 0, index($url1, '|#|')) if($url1 =~/\|#\|/);
		my $fil = $func->get_file($url1);
		my $ext = $func->get_extension($fil);

		if($ext) {
			if(&checkFile($url1."adad") != 1){
				$semaphore->down();
				push(@bkpf, $url1);
				$semaphore->up();
			}
		}
	}
	$q->enqueue(undef);
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
