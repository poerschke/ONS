package Plugins::Crawler::checkUploadForm;

use Uniscan::Functions;
use Thread::Semaphore;
use Uniscan::Configure;
	
my %conf = ( );
my $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
%conf = $cfg->loadconf();


my $func = Uniscan::Functions->new();
our %upload : shared = ();
my $semaphore = Thread::Semaphore->new();
my $qv=0;

sub new {
    my $class    = shift;
    my $self     = {name => "Upload Form Detect", version => 1.1 };
    our $enabled = 1;
    return bless $self, $class;
}

sub execute {
    my ($self, $url, $content) = @_;
	while($content =~ m/<input(.+?)>/gi){
		my $params = $1;
		if($params =~ /type *= *"file"/i){
			$semaphore->down();
			$upload{$url}++;
			$semaphore->up();
		}
	}
	

}


sub showResults(){
	my ($self, $report_id) = @_;
	my $up = "";
	foreach my $url (keys %upload){
		if($upload{$url}){
			$up.= $url ."\n";
			$qv++;
		}
	}
	$up =~s/'/\\'/g;
	$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$up', 0, 0, 0, 0, 0, 1)");
	$func->insert("UPDATE historico SET uploadform = $qv WHERE report_id= $report_id");
}

sub getResults(){
	my $self = shift;
	return %upload;
}

sub clean(){
	my $self = shift;
	%upload = ();
}

sub status(){
	my $self = shift;
	return $enabled;
}

1;
