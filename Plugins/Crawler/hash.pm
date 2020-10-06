package Plugins::Crawler::hash;

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
our $requests : shared = 0;

sub new {
	my $class    = shift;
	my $self     = {name => "MD5 and SHA1 hash Disclosure", version => 1.0};
	our $enabled = 1;
	return bless $self, $class;
}

sub execute {
	my $self = shift;
	my $url = shift;
	my $content = shift;

	while($content =~m/([0-9a-f]{32,40})/gi){
		my $hash = $1;
		$hash = uc($hash);
		$semaphore->down();
		$pages{"MD5|". $hash."|".$url} = 1 if(length($hash) == 32);
		$pages{"SHA1|". $hash."|".$url} = 1 if(length($hash) == 40);
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
	$cp =~s/'/\\'/gi;
	$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$cp', 0, 0, 0, 0, $requests, 9)");
	$func->insert("UPDATE historico SET hash = $qv WHERE report_id= $report_id");

}

sub getResults(){
	my $self = shift;
	return %pages;
}

sub clean(){
	my $self = shift;
	%pages = ();
}


sub status(){
	my $self = shift;
	return $enabled;
}



1;

