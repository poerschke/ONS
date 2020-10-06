package Plugins::Crawler::sqldis;

use Uniscan::Functions;
use Thread::Semaphore;
use Uniscan::Configure;
use Uniscan::Http;

my %conf = ( );
my $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
%conf = $cfg->loadconf();
my $func = Uniscan::Functions->new();
my $semaphore = Thread::Semaphore->new();
our %pages : shared = ();
our %info : shared  = ();

sub new {
	my $class    = shift;
	my $self     = {name => "SQL Query Disclosure", version => 1.0};
	our $enabled = 1;
	return bless $self, $class;
}

sub execute {
	my $self = shift;
	my $url = shift;
	my $content = shift;

	while($content =~m/(select\s[\*\s,\w\._]+\sfrom\s[\*\s,\w\._]+\swhere)/gi){
		my $r = $1;
		$semaphore->down();
		$pages{$r."|".$url} = 1;
		$semaphore->up();
	}
	while($content =~m/(insert\s+into\s[\*\s,\w\._]+\s*\(.+\)\s+values)/gi){
		my $r = $1;
		$semaphore->down();
		$pages{$r."|".$url} = 1;
		$semaphore->up();
	}
	while($content =~m/(update\s[\*\s,\w\._]+\s+set)/gi){
		my $r = $1;
		$semaphore->down();
		$pages{$r."|".$url} = 1;
		$semaphore->up();
	}
}


sub showResults(){
	my ($self, $report_id) = @_;
	my $cp = "";
	my $qv=0;
	foreach my $w (keys %pages){
		if($pages{$w}){
			$cp .= $w . "\n";
			$qv++;
		}
	}
	$cp =~s/'/\\'/g;
	$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$cp', 0, 0, 0, 0, 0, 14)");
	$func->insert("UPDATE historico SET sqldisc = $qv WHERE report_id= $report_id");
}

sub getResults(){
	my $self = shift;
	return %pages;
}

sub clean(){
	my $self = shift;
	%pages = ();
	%info = ();
}


sub status(){
	my $self = shift;
	return $enabled;
}



1;

