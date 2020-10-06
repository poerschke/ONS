#!/usr/bin/perl

use Uniscan::Functions;
use Thread::Queue;
use threads;
use Uniscan::Http;
use Uniscan::Configure;
use Time::HiRes qw(gettimeofday tv_interval);
use HTTP::Headers;
use HTTP::Request;
use HTTP::Response;
use LWP::UserAgent;
use LWP::Protocol::https;
use strict;
use warnings;

my $report_id = $ARGV[0];	
my %conf = ( );
my $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
%conf = $cfg->loadconf();


my $func = Uniscan::Functions->new();
my $q = new Thread::Queue;
my $max_threads  = 50;
our $time : shared = 0;
my $minuts = 2; 
my %hash = ();
my @url = $func->pega_dados_crawler($report_id);
our $custo_real : shared = 0;
our $caiu : shared = 0;
our $requests : shared = 0;
our $soma_custo : shared = 0;
our $url_alvo_final :shared = "";
my $custo_ref = 0;

$|++;

open(my $arq, ">custo.csv");
print $arq "Custo normal;Maior custo durante ataque;Custo médio durante ataque;Requisições;Requisições nao atendidas;Percentual de requisições perdidas;Máquinas necessárias para negar o serviço;Requisições/segundo;URL alvo\n";
close($arq);


#aqui busca url mais custosa e retorna pra $url
my %url = &cost(@url);
my $x=0;
&grava("---------------------------------\n");
my $custos = "";
foreach my $key (sort ordena (keys(%hash))){
	$x++;
	$custo_ref = $hash{$key} if(!$custo_ref);
	&grava("[$x] Custo: $hash{$key} URL: $key\n");
	$custos .= $key .";;;". $hash{$key}."\n";
	
}

$func->insert("UPDATE report SET custo_stress = '$custos' WHERE report_id = $report_id");





foreach my $ur (sort ordena (keys(%url))){
	print "Aperte enter para proximo teste ou n para pular\n";
	my $tec = <stdin>;
	chomp($tec);
	next if($tec eq "n");
	$requests=0;
	$custo_ref = $url{$ur};
	$custo_real = 0;
	&grava("---------------------------------\n");
	&grava("Alvo: $ur Custo inicial: $url{$ur}\n");
	&grava("---------------------------------\n");
	&grava("Iniciando testes com duracao de ". ($minuts * 60) . " segundos usando $max_threads threads\n");
	$time = time() + ($minuts * 60);
	&threadnize("miniStress", $ur);
	$requests = $caiu if($caiu > $requests); 
	my $percentual=0;
	$percentual = sprintf("%.2f", ($custo_real*100)/$custo_ref) if(($custo_real > 0) && ($custo_ref >0));
	$percentual = 0 if(($custo_real == 0) or ($custo_ref == 0));

	my $custo_medio=0;
	$custo_medio = sprintf("%.6f", $soma_custo /($requests - $caiu)) if(($soma_custo > 0) && (($requests - $caiu) > 0));
	$custo_medio = 0 if(($soma_custo == 0) or (($requests - $caiu) == 0));

	my $percentual_cm=0;
	$percentual_cm = sprintf("%.2f", ($custo_medio*100)/$custo_ref) if(($custo_medio > 0) && ($custo_ref > 0));
	$percentual_cm = 0 if(($custo_medio == 0) or ($custo_ref == 0));

	my $req_s=0;
	$req_s = sprintf("%.2f", $requests/($minuts * 60)) if($requests > 0);
	$req_s = 0 if($requests == 0);

	my $perda_reqs=0;
	$perda_reqs = sprintf("%.2f", ($caiu/$requests)*100) if(($caiu > 0) && ($requests > 0));
	$perda_reqs =0 if(($caiu == 0) or ($requests == 0));

	my $maquinas=0;
	$maquinas =  int((100/(($caiu/$requests)*100))*$max_threads) if(($caiu > 0) && ($requests > 0) && ($max_threads > 0));
	$maquinas = 0 if(($caiu == 0) or ($requests == 0) or ($max_threads == 0));

	# salva em formato csv
	open(my $arq, ">>custo.csv");
	print $arq "$custo_ref;$custo_real;$custo_medio;$requests;$caiu;$perda_reqs%;$maquinas;$req_s;$ur\n";
	close($arq);

	&grava("\n\n---------------------------------\n");
	&grava("Custo antes do ataque: \t[$custo_ref]\n");
	&grava("Maior custo durante ataque: \t[$custo_real]\n");
	&grava("Custo medio durante o ataque:\t[$custo_medio]\n");
	&grava("Requisicoes efetuadas: [$requests]\n");
	&grava("Servidor nao respondeu a [$caiu] requisicoes\n");
	&grava("Percentual de perdas de requisicoes: [$perda_reqs%]\n");
	&grava("Maquinas necessarias para derrubar o host: [$maquinas]\n") if($maquinas > 0);
	&grava("Maquinas necessarias para derrubar o host: [incalculavel]\n") if($maquinas == 0);
	&grava("Requisicoes/segundo: [$req_s]\n");
	&grava("---------------------------------\n");
	

}

#########
# funcs #
#########

sub threadnize(){
	my ($fun, $test) = @_;
	$url_alvo_final = $test;
	my $x=0;
	my @threads = ();
	while( $x < $max_threads){
		no strict 'refs';
		$threads[$x] = threads->new(\&miniStress);
		$x++;
	}
	
	sleep(($minuts * 60)*2 );
	foreach my $running (@threads) {
		$running->join() if($running->joinable());
	}
}



sub miniStress(){
	
	my $url = $url_alvo_final;
	while(($time  - time()) > -1 ){
		my $c = &GET2($url);
		$requests++;
		if($c == 0){
			$caiu++;
		}
		$custo_real = $c if($c > $custo_real);
		print "Custo: $custo_real Tempo: ". ($time  - time()) . " segundos  \r" if(($time  - time())>-1);
	}
	return 0;
}


sub cost(){
    my @urls = @_;
    my $target = "a";
    my $cost = 0;
    my $x = 0 ;
    my $y = scalar(@urls);
    my %target = ();
    foreach my $url (@urls){
	$x++;
	chomp $url;
	
	my $c = &GET($url);

	$hash{$url} = $c;
	if($c > $cost){
		print "Maior custo $c $url\n";
		$cost = $c;
		
		$target{$url} = $c;
	        
	}
	print "[$x - $y] \r";
    }
	# retornar o tamanho da resposta
    return %target;
    
    
}

sub GET(){
	my $url1 = shift;
	return 0 if(!$url1);
	chomp $url1;
	my $req;
	if($url1 =~/\|#\|/){
		my ($action, $data) = split('\|#\|', $url1);
		$req = HTTP::Request->new("POST", $action);
	        $req->content($data);
	        $req->content_type('application/x-www-form-urlencoded');
	}
	else {
		$req = HTTP::Request->new(GET=>$url1);
	}
	my $ua	= LWP::UserAgent->new(ssl_opts => { verify_hostname => 0});
	$ua->protocols_allowed( [ 'http', 'https'] );
	$ua->timeout(20);
	my $time1 = [gettimeofday];
	my $resp = $ua->request($req);
	my $time2 = tv_interval($time1);
	my $ret = length($resp->content);
#	print "Codigo: " . $resp->code . " $url1\n";
	return 0 if($ret == 0);
	return 0 if(!$resp->is_success);
	my $c = sprintf("%.6f", $time2/$ret);
	return $c;
}


sub GET2(){
	my $url1 = shift;
	return 0 if(!$url1);
	my $req;
	if($url1 =~/\|#\|/){
		my ($action, $data) = split('\|#\|', $url1);
		$req = HTTP::Request->new("POST", $action);
	        $req->content($data);
	        $req->content_type('application/x-www-form-urlencoded');
	}
	else {
		$req = HTTP::Request->new(GET=>$url1);
	}
	my $ua	= LWP::UserAgent->new(sl_opts => { verify_hostname => 0});
	$ua->protocols_allowed( [ 'http', 'https'] );
	$ua->timeout(10);
	my $time1 = [gettimeofday];
	my $resp = $ua->request($req);
	my $time2 = tv_interval($time1);
	#return 0 if(!$resp->is_success);

	my $ret = length($resp->content);
	#return 0 if($ret == 0);
	$ret = 100000000 if($ret == 0);
	my $c = sprintf("%.6f", $time2/$ret);
	if($resp->is_success){
		$soma_custo += $c;
	}
	return 0 if(!$resp->is_success);
	return $c;
}


sub ordena{
   $hash{$b} <=> $hash{$a};
}

sub grava{
	my $s = shift;
	open(my $arq, ">>custos.txt");
	print $arq $s;
	print $s;
	close($arq);
}
