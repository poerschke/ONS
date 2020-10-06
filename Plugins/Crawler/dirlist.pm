package Plugins::Crawler::dirlist;

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
	my $self     = {name => "Directory listing", version => 1.0};
	our $enabled = 1;
	return bless $self, $class;
}

sub execute {
	my $self = shift;
	my $url = shift;
	my $content = shift;

	while($content =~m/<TITLE>Index of \/.+<\/TITLE>/gi && $url !~/&|\?/){
		$semaphore->down();
		$pages{$url}++;
		$semaphore->up();
	}
}


sub showResults(){
	my ($self, $report_id) = @_;
	my $co = "";
	my $qv=0;
	foreach my $w (keys %pages){
		if($pages{$w}){
			$co .= $w . "\n";
			$qv++;
		}
	}
	$co =~s/'/\\'/gi;
        $func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$co', 0, 0, 0, 0, 0, 5)");
		$func->insert("UPDATE historico SET dirlist = $qv WHERE report_id= $report_id");

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

