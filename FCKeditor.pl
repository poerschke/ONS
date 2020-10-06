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
my @dirs = (	"/FCKeditor/editor/",
		"/fckeditor/editor/");
our @fck : shared = ();
my $q = Thread::Queue->new();
my %check = ();
my $semaphore = Thread::Semaphore->new();
our %has : shared = ( );
our %conf = ( );
%conf = $c->loadconf();	

$|++;

#metricas
our $requests : shared = 0;
our %testado : shared = ();
our $arqs : shared = 0;
our %arqvul : shared = ();
our $arqv : shared = 0;
our $vuls : shared = "";

our $report_id :shared = $ARGV[0];
my @urls = $func->pega_dados_crawler($report_id);

my $t = threads->new(\&online);

my $u = "";
foreach (@urls){
	if(/^https?:\/\//){
		$u = $_;
		last;
	}
}
substr($u, index($u, '?'), length($u)) = "" if($u =~/\?/g);
$u = substr($u, 0, rindex($u, '/'));
my $req = $u . '/testing123';
my $res = $http->HEAD($u . '/testing123');
$requests++;
if($res->code !~ /404/){
}
else {
	foreach my $url (@urls){
		next if($url !~/^https?:\/\/.+/);
		$url = substr($url, 0, index($url, '?'));
		my $u = $func->host($url);
		my $temp = $url;
		my $ub = 2000;
		while($ub > 11){
			$ub = rindex($temp, '/');
			$temp = substr($temp, 0, $ub);
			foreach my $dir (@dirs){
				if($temp =~ /$u/){
					$temp =~s/\r|\n//g;
					$check{$temp.$dir} =  1 if(!$check{$temp.$dir});
				}
			}
			$ub = rindex($temp, '/');
		}
	}
	my @urls = ();
	foreach my $url	(keys %check){
		push(@urls, $url);
	}
	&threadnize("checkNoExist", @urls);
	&CheckUpload(@fck) if(scalar(@fck));
}
	        while($q->pending > 0){
	                $q->dequeue;
	        }

$t->join();

$vuls =~s/'/\\'/g;

$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$vuls', $arqs, $arqv, 0, 0, $requests, 25)");
$func->insert("UPDATE historico SET fckeditor = $arqv WHERE report_id= $report_id");





sub CheckUpload(){
	my @files = @_;
	my @forms = ();
	my @connectors = (	"filemanager/upload/cfm/upload.cfm",
				"filemanager/upload/php/upload.php",
				"filemanager/upload/asp/upload.asp",
				"filemanager/upload/aspx/upload.aspx",
				"filemanager/upload/perl/upload.cgi",
				"filemanager/upload/py/upload.py");
	foreach my $f (@files){
		foreach my $con (@connectors){
			push(@forms, $f. $con);
		}
	}
	@files = ();
	&threadnize("Upload", @forms) if(scalar(@forms));
	
}







 sub threadnize(){
	my ($fun, @tests) = @_;
	@_=();
	foreach my $test (@tests){
		$q->enqueue($test) if($test);
	}
	my $x=0;
	my @threads = ();
	while($q->pending() > 0 && $x <= $conf{'max_threads'}-1){
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
		$h = Uniscan::Http->new();
                my $response=$h->GET1($url1);
		$requests++;
                if(defined $response){
                	if($response->code =~ /200|403/ && $response->content =~/<title>Index of/){
						return 1;
					}
					else{ return 0; }
				}
				else{
					return 0;
				}
	}
	return 0;
}

sub checkNoExist(){
	while($q->pending() > 0){
		$semaphore->down();
		my $url1 = $q->dequeue;
		$semaphore->up();
		next if(not defined $url1);
		next if($url1 =~/\|#\|/g);
		print $q->pending() . " Verificando: $url1\n";
		if(&checkFile($url1) == 1){
			$semaphore->down();
			if(!$has{$url1}){
				$has{$url1} = 1;
				push(@fck, $url1);
			}
			$semaphore->up();
		}
	}
	$q->enqueue(undef);
}


sub Upload(){
	while($q->pending() > 0){
		$semaphore->down();
		my $url = $q->dequeue;
		$semaphore->up();
		next if(not defined $url);
		next if(!$url);
		next if($url =~/\|#\|/g);
		next if($url !~/^https?:\/\//);
		print "Testando: $url\n";		
		my $host = $func->host($url);
		my $temp = $url;
		$temp =~ s/https?:\/\///g;
		$temp =~ s/$host//g;
		my $path = $temp;
		print "Path: $path\n";
		print "host: $host\n";
		&metrica_testados('http://'.$host.$path);
		my $sock = IO::Socket::INET->new (PeerAddr => $host,PeerPort => 80, Proto    => 'tcp') || next;
		print $sock "POST ". $path ." HTTP/1.1\r\n" ;
		print $sock "Host: ".$host."\r\n" ;
		print $sock "User-Agent:Mozilla/5.0 (X11; U; Linux i686; pt-BR; rv:1.9.2.24) Gecko/20111107 Ubuntu/10.10 (maverick) Firefox/3.6.24\r\n" ;
		print $sock 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'."\r\n" ;
		print $sock 'Accept-Language: pt-br,pt;q=0.8,en-us;q=0.5,en;q=0.3'."\r\n" ;
		print $sock 'Accept-Encoding: gzip,deflate'."\r\n" ;
		print $sock 'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7'."\r\n" ;
		print $sock 'Keep-Alive: 115'."\r\n" ;
		print $sock 'Connection: keep-alive'."\r\n" ;
		print $sock 'Referer: http://'. $host .'/FCKeditor/editor/filemanager/upload/test.html'."\r\n" ;
		print $sock 'Content-Type: multipart/form-data; boundary=---------------------------3404088951808214906347034904'."\r\n" ;
		print $sock 'Content-Length: 236'."\r\n\r\n" ;
		print $sock '-----------------------------3404088951808214906347034904'."\r\n" ;
		print $sock 'Content-Disposition: form-data; name="NewFile"; filename="uniscan.txt"'."\r\n" ;
		print $sock 'Content-Type: text/plain'."\r\n" ;
		print $sock "\r\n" ;
		print $sock 'teste uniscan'."\n" ;
		print $sock "\r\n" ;
		print $sock '-----------------------------3404088951808214906347034904--'."\r\n" ;
		my $result;
		while(<$sock>){
			$result .= $_;
		}
		$requests++;
		if(defined $result){
			if($result =~/OnUploadCompleted\((\d+)\,"(.*)"\,"(.*)"\, ""\)/){
				my $code = $1;
				my $path_file = $2;
				my $file_name = $3;
				if($code =~ /201/ && $path_file =~/uniscan/ && $file_name=~/uniscan/){
					$vuls .= "http://" . $host . $path . " ".$conf{'lang136'}." http://" . $host. $path_file . "\n";
					&metricas_vul("http://" . $host . $path);
				}
			}
		}
	}
	$q->enqueue(undef);
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
						print "Erro, nao sucesso\n";
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

