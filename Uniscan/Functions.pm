package Uniscan::Functions;

use Moose;
use Uniscan::Http;
use HTTP::Response;
use Socket;
use threads;
use threads::shared;
use Thread::Queue;
use Thread::Semaphore;
use HTTP::Request;
use LWP::UserAgent;
use Uniscan::Configure;
use strict;
use URI;
use POSIX qw(strftime);

use Uniscan::MySQL;

our %conf = ( );
our $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
%conf = $cfg->loadconf();
our $pattern;
my $q = new Thread::Queue;
my $semaphore = Thread::Semaphore->new();
our @list :shared= ( );
my $atual;
my $sql = Uniscan::MySQL->new();
our $requests : shared = 0;



sub GetServerInfo(){
	my ($self, $url) = @_;
	my $http = Uniscan::Http->new();
	my $response = $http->HEAD($url);
	$requests++;
	return $response->server;
	
}






sub GetServerIp(){
	my ($self, $url) = @_;
	$url =~ s/https?:\/\///g if($url =~/https?:\/\//);
	$url = substr($url, 0, index($url, '/'));
	$url = substr($url, 0, index($url, ':')) if($url =~/:/); 
	return(join(".", unpack("C4", (gethostbyname($url))[4])));
}






sub Check(){
	my ($self, $url, $txtfile) = @_;
	$semaphore->down();
	@list = ( );
	$semaphore->up();
	open(my $file, "<", $txtfile) or die "$!\n";
	my @directory = <$file>;
	close($file);
	
	
	foreach my $dir (@directory){
		chomp($dir);
		$q->enqueue($url.$dir);
	}
	my $x =0;
	my @threads = ();
	while($q->pending() && $x <  $conf{'max_threads'}){
		$x++;
		push @threads, threads->create(\&GetResponse);
	}

	
	sleep(2);
	
	foreach my $running (@threads) {
		$running->join();
	}
return @list;
}




sub GetResponse(){
	my $http = Uniscan::Http->new();
	while($q->pending()){
		$semaphore->down();
		my $url1 = $q->dequeue;
		$semaphore->up();
		next if(not defined $url1);
		
			my $response=$http->HEAD($url1);
			$requests++;
			if($response){
				if($response->code =~ $conf{'code'}){
					$semaphore->down();
					push(@list, $url1);
					$semaphore->up();
				}
			}
			$response = 0;
	}
	$q->enqueue(undef);
}




sub INotPage(){
	my ($self, $url) = @_;
	$url .= "/uniscan". int(rand(10000)) ."uniscan/";
	my $h = Uniscan::Http->new();
	my $content = $h->GET($url);
	$requests++;
	if($content =~ /404/){
		$pattern = substr($content, 0, index($content, "404")+3);
	}
	else{
		$content =~/<title>(.+)<\/title>/i;
		$pattern = $1;
	}
	$pattern = "not found|não encontrada|página solicitada não existe|could not be found" if(!$pattern);
	$h = "";
	return $pattern;
}


sub get_file(){
	my ($self, $url1) = @_;
	substr($url1,0,7) = "" if($url1 =~/http:\/\//);
	substr($url1,0,8) = "" if($url1 =~/https:\/\//);
	substr($url1, index($url1, '?'), length($url1)) = "" if($url1 =~/\?/);
	substr($url1, index($url1, '|#|'), length($url1)) = "" if($url1 =~/\|#\|/);
	if($url1 =~ /\//){
		$url1 = substr($url1, index($url1, '/'), length($url1)) if(length($url1) != index($url1, '/'));
		if($url1 =~ /\?/){
			$url1 = substr($url1, 0, index($url1, '?'));
		}
		return $url1;
	}
	elsif($url1=~/\?/){
		$url1 = substr($url1, 0, index($url1, '?'));
		return $url1;
	}
	else {
		return $url1;
	}
}



sub get_url(){
	my ($self, $url) = @_;
	if($url =~/http:\/\//){
		$url =~s/http:\/\///g;
		$url = "http://" . substr($url, 0, index($url, '/'));
		return $url;
	}
	if($url =~/https:\/\//){
		$url =~s/https:\/\///g;
		$url = "https://" . substr($url, 0, index($url, '/'));
		return $url;
	}
}





sub remove{
	
   	my @si = @_;
   	my @novo = ();
   	my %ss;
  	foreach my $s (@si)
   	{
        	if (!$ss{$s})
        	{
            		push(@novo, $s);
            		$ss{$s} = 1;
        	}
    	}
    	return @novo;
}



sub CheckRedirect(){
	my ($self, $url) = @_;
	use LWP::UserAgent;
	use HTTP::Headers;
	my $ua = LWP::UserAgent->new;
	my $request  = HTTP::Request->new( HEAD => $url);
	my $response = $ua->request($request);
	$requests++;
	if ( $response->is_success and $response->previous ){
		$url = $response->request->uri;
	}
	return $url;
}



sub host(){
  	my ($self, $h )= @_;
  	my $url1 = URI->new( $h || return -1 );
  	return $url1->host();
}




sub pega_reportid(){
	my $self = shift;

	$sql->conecta();
	my $rep = $sql->select('select max(report_id) from report');
	my $report;
	while(my $data = $rep->fetch){
	    $report = $data->[0];
	}
	$sql->disconecta();


	return $report;
}

sub verifica_reportid($){
        my $self= shift;
        $sql->conecta();
        my $rep = $sql->select('select count(report_id) from report where report_id = '. $self);
        my $report;
        while(my $data = $rep->fetch){
            $report = $data->[0];
        }
        $sql->disconecta();
        return $report;
}

sub gera_report(){
	my $self= shift;

	my $id = &pega_reportid();
	while(&verifica_reportid($id) > 0){
		$id +=1;
	}
	&insert('', "INSERT INTO report(report_id) VALUES(". $id .")");
	&insert('', "INSERT INTO historico(report_id) VALUES(". $id .")");
	$sql->disconecta();
	
	return $id;
}

sub pega_site(){
	my ($self, $report_id) =  @_;
	$sql->conecta();
	my $rep = $sql->select('SELECT site FROM report WHERE report_id='. $report_id);
	my $site;
	while(my $data = $rep->fetch){
	    $site = $data->[0];
	}
	$sql->disconecta();
	return $site;
}

sub pega_ip(){
	my ($self, $report_id) =  @_;
	$sql->conecta();
	my $rep = $sql->select('SELECT ip FROM report WHERE report_id='. $report_id);
	my $ip;
	while(my $data = $rep->fetch){
	    $ip = $data->[0];
	}
	$sql->disconecta();
	return $ip;
}

sub pega_dados(){
	my ($self, $report_id, $coluna) = @_;
	$sql->conecta();
	my $rep = $sql->select("SELECT $coluna FROM report WHERE report_id=$report_id");
	my $dados;
	while(my $data = $rep->fetch){
	    $dados = $data->[0];
	}
	my @lista = split('\n', $dados);
	$sql->disconecta();
	return @lista;
}

sub pega_dados_crawler(){
	my ($self, $report_id) = @_;
	$sql->conecta();
	my $rep = $sql->select("SELECT urls FROM report WHERE report_id=$report_id");
	my $dados = "";
	while(my $data = $rep->fetch){
	    $dados = $data->[0];
	}
	my @lista = split('\n', $dados);
	$sql->disconecta();
	return @lista;
}



sub pega_vulid(){
	my $self = shift;
	$sql->conecta();
	my $rep = $sql->select('select max(vulnid) from vulnerabilidades');
	my $report;
	while(my $data = $rep->fetch){
	    $report = $data->[0];
	}
	$sql->disconecta();
	return $report;
}


sub insert(){
	my ($self, $sql1) = @_;
	$sql->conecta();
	my $res;
	do{
		$res  = $sql->insert($sql1);
		if(!defined($res)){
			open(my $a,'>>errosql.txt');
			print $a "$sql1\n";
			close($a);
		}
	}while(!defined($res));
	$sql->disconecta();
	return $res;
}


sub pega_reqs(){
	my $self = shift;
	return $requests;
}

sub logAdd($$){
        my $now = strftime "[%Y-%m-%d %H:%M:%S]", localtime;
        my ($self, $logfile, $str) = @_;
        system("/usr/bin/touch $logfile") if (! -e $logfile);
        open (FILE, '>>', $logfile);
        print FILE "$now - $str\n";
        close (FILE);
}

sub checa_online(){
	my $h = Uniscan::Http->new();
	my ($self, $report_id) = @_;
	my $x=0;
	$sql->conecta();
	my $rep = $sql->select('SELECT waf FROM report WHERE report_id='. $report_id);
	my $waf;
	while(my $data = $rep->fetch){
	    $waf = $data->[0];
	}
	$sql->disconecta();
	return 0 if($waf == 1);
	my $site = &pega_site("", $report_id);
	$site =  &CheckRedirect('', $site);
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
	&grava_waf($report_id);
	return 0;
}


sub get_extension(){
	my  ($self, $file) = @_;
	if($file =~/\./){
		my $ext = substr($file, rindex($file, '.'), length($file));
		$ext =~ s/ //g;
		if($ext !~/\(|\)|\-|\//){
			return $ext;
		}
		else {
			return 0;
		}
	}
	else{
		return 0;
	}
}

sub grava_waf(){
	my $report_id = shift;
	&insert('', "UPDATE report SET waf=1 WHERE report_id=". $report_id);
}

sub check_waf(){
	my ($self, $id) = @_;
	$sql->conecta();
	my $rep = $sql->select("SELECT waf FROM report WHERE report_id = ". $id);
	my $dados = "";
	while(my $data = $rep->fetch){
		$dados = $data->[0];
	}
	$sql->disconecta();
	return $dados;
}



sub wordpress_vuln_by_version(){
	my ($self, $versao) = @_;
	$sql->conecta();
	my $rep = $sql->select("SELECT COUNT(word_id) FROM wordpress WHERE versao = '$versao'");
	my $data = $rep->fetch;
	my $vuls = $data->[0];
	#$sql->disconecta();
	return $vuls;
}

sub wordpress_vuls(){
	my ($self, $versao) = @_;
	$sql->conecta();
	my %vuls = ();
	my $rep = $sql->select("SELECT * FROM wordpress WHERE versao = '$versao'");
	while(my $data = $rep->fetch){
		$vuls{$data->[0]}{'versao'} 	= $data->[1];
		$vuls{$data->[0]}{'titulo'} 	= $data->[2];
		$vuls{$data->[0]}{'urls'} 	= $data->[3];
		$vuls{$data->[0]}{'secunia'} 	= $data->[4];
		$vuls{$data->[0]}{'cve'} 	= $data->[5];
		$vuls{$data->[0]}{'osvdb'} 	= $data->[6];
		$vuls{$data->[0]}{'exploitdb'} 	= $data->[7];
	}
	return %vuls;
	
}

1;
