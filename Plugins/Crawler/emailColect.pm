package Plugins::Crawler::emailColect;

use Uniscan::Functions;
use Thread::Semaphore;
use Uniscan::Configure;
	
my %conf = ( );
my $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
%conf = $cfg->loadconf();
my $semaphore = Thread::Semaphore->new();
my $func = Uniscan::Functions->new();
our %email : shared = ();

sub new {
	my $class    = shift;
	my $self     = {name => "E-mail Detection", version => 1.1};
	our $enabled = 1;
	return bless $self, $class;
}

sub execute {
    my $self = shift;
	my $url = shift;
	my $content = shift;

	while($content =~m/([a-z\-\_\.\d]+\@[a-z\d\-\.]+\.[a-z{2,4}]+)/g){
		$semaphore->down();
		$email{$1."|".$url}++;
		$semaphore->up();
	}
}


sub showResults(){
	my ($self, $report_id) = @_;
	my $cp = "";
	my $qv=0;
	foreach my $mail (keys %email){
		if($email{$mail}){
			$cp.= $mail."\n";
			$qv++;
		}
	}
	$cp =~s/'/\\'/gi;
        $func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$cp', 0, 0, 0, 0, 0, 6)");
		$func->insert("UPDATE historico SET email = $qv WHERE report_id= $report_id");

}

sub getResults(){
	my $self = shift;
	return %email;
}

sub clean(){
	my $self = shift;
	%email = ();
}


sub status(){
	my $self = shift;
	return $enabled;
}

1;
