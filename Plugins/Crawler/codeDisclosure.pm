package Plugins::Crawler::codeDisclosure;

use Uniscan::Functions;
use Thread::Semaphore;
use Uniscan::Configure;
	
my %conf = ( );
my $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
%conf = $cfg->loadconf();
my $func = Uniscan::Functions->new();
our %source : shared = ();
my $semaphore = Thread::Semaphore->new();
my $qv=0;
sub new {
    my $class    = shift;
    my $self     = {name => "Code Disclosure", version => 1.1};
	our $enabled = 1;
    return bless $self, $class;
}

sub execute {
	my $self = shift;
	my $url = shift;
	my $content = shift;
	my @codes = ('<\?php', '#include <', '#!\/usr', '#!\/bin', 'import java\.', 'public class .+\{', '<\%.+\%>', '<asp:', 'package\s\w+\;');

	
	foreach my $code (@codes){
		if($content =~ /$code/i){
			my $matched = $code;
			$semaphore->down();
			$source{$url."|". $matched}++;
			$semaphore->up();
		}
	}
}


sub showResults(){
	my ($self, $report_id) = @_;
	my $co = "";
	foreach my $url (keys %source){
	    if($source{$url}){
			$co .= $url . "\n";
			$qv++;
		}
	}
	$co =~s/'/\\'/gi;
    $func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$co', 0, 0, 0, 0, 0, 3)");
	$func->insert("UPDATE historico SET sourcecode = $qv WHERE report_id= $report_id");

}

sub getResults(){
	my $self = shift;
	return %source;
}

sub clean(){
	my $self = shift;
	%source = ();
}

sub status(){
	my $self = shift;
	return $enabled;
}

1;
