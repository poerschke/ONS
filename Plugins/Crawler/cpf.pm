package Plugins::Crawler::cpf;

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
my $qv =0;

sub new {
	my $class    = shift;
	my $self     = {name => "CPF Disclosure", version => 1.0};
	our $enabled = 1;
	return bless $self, $class;
}

sub execute {
	my $self = shift;
	my $url = shift;
	my $content = shift;

	while($content =~m/([0-9]{3}\.[0-9]{3}\.[0-9]{3}\-[0-9]{2})/gi){
		my $cpf = $1;
		chomp $cpf;
		$semaphore->down();
		if(!$pages{$cpf} && length($cpf)>11){
			$pages{$cpf .'|'. $url} = 1;
			
		}
		$semaphore->up();
	}
}


sub showResults(){
	my ($self, $report_id) = @_;
	my $cp = "";
	foreach my $w (keys %pages){
		$cp .=  $w . "\n" if($pages{$w});
		$qv++;
	}
	$cp =~s/'/\\'/gi;
        $func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$cp', 0, 0, 0, 0, 0, 4)");
		$func->insert("UPDATE historico SET cpf = $qv WHERE report_id= $report_id");
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

