package Plugins::Crawler::phpinfo;

use Uniscan::Functions;
use Thread::Semaphore;
use Uniscan::Configure;
	
my %conf = ( );
my $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
%conf = $cfg->loadconf();
my $func = Uniscan::Functions->new();
my $semaphore = Thread::Semaphore->new();
our %pages : shared = ();
our %info : shared  = ();

sub new {
	my $class    = shift;
	my $self     = {name => "phpinfo() Disclosure", version => 1.0};
	our $enabled = 1;
	return bless $self, $class;
}

sub execute {
	my $self = shift;
	my $url = shift;
	my $content = shift;

	if($content =~m/<title>phpinfo\(\)<\/title>/gi){
		$semaphore->down();
		$pages{$url}++;
		$semaphore->up();
		while($content =~m/<tr><td class="e">(.+?) <\/td><td class="v">(.+?)<\/td><\/tr>/g){
			$semaphore->down();
			$info{$1} = $2;
			$semaphore->up();
		}

		while($content =~m/<tr><td class="e">(.+?)<\/td><td class="v">(.+?)<\/td><td class="v">(.+?)<\/td><\/tr>/g){
			$semaphore->down();
			$info{$1} = $2;
			$semaphore->up();
		}
	}
}


sub showResults(){
	my ($self, $report_id) = @_;
	my $cp = "";
	my $qv =0;
	foreach my $w (keys %pages){
		$cp .= "phpinfo() encontrada em: $w\n";
		$qv++;
	}
	
	$cp .= "System: ". $info{'System'} ."\n" if($info{'System'});
	$cp .= "PHP version: ". $info{'PHP Version'}."\n" if($info{'PHP Version'});
	$cp .= "Apache Version: ". $info{'Apache Version'}."\n" if($info{'Apache Version'});
	$cp .= "Server Administrator: ". $info{'Server Administrator'}."\n" if($info{'Server Administrator'});
	$cp .= "User/Group: ". $info{'User/Group'}."\n" if($info{'User/Group'});
	$cp .= "Server Root: ". $info{'Server Root'}."\n" if($info{'Server Root'});
	$cp .= "DOCUMENT_ROOT: ". $info{'DOCUMENT_ROOT'}."\n" if($info{'DOCUMENT_ROOT'});
	$cp .= "SCRIPT_FILENAME: ". $info{'SCRIPT_FILENAME'}."\n" if($info{'SCRIPT_FILENAME'});
	$cp .= "allow_url_fopen: ". $info{'allow_url_fopen'}."\n" if($info{'allow_url_fopen'});
	$cp .= "allow_url_include: ". $info{'allow_url_include'}."\n" if($info{'allow_url_include'});
	$cp .= "disable_functions: ". $info{'disable_functions'}."\n" if($info{'disable_functions'});
	$cp .= "safe_mode: ". $info{'safe_mode'} . "\n" if($info{'safe_mode'});
	$cp .= "safe_mode_exec_dir: ". $info{'safe_mode_exec_dir'}. "\n" if($info{'safe_mode_exec_dir'});
	$cp .= "OpenSSL Library Version: ". $info{'OpenSSL Library Version'}. "\n" if($info{'OpenSSL Library Version'});
	$cp =~s/'/\\'/gi;
	$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$cp', 0, 0, 0, 0, 0, 12)");
	$func->insert("UPDATE historico SET phpinfo = $qv WHERE report_id= $report_id");
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

