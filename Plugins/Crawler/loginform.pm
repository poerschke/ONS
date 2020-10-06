package Plugins::Crawler::loginform;

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
	my $self     = {name => "Login Form", version => 1.0};
	our $enabled = 0;
	return bless $self, $class;
}

sub execute {
	my $self = shift;
	my $url = shift;
	my $content = shift;
	$content =~s/\n//;
	$content =~s/\r//;
	
	while($content =~m/<form(.+?)<\/form/gsi){
		my $r = $1;
		my $login = 0;
		$r =~ m/action\s*=\s*["'](.+?)["']/gi;
		my $action = $1;
		$action = $site if(!$action);
		if($action =~ /^\//){
			$action = $func->get_url($url) . $action;
		}
		$r =~ m/method *= *["'](.+?)["']/gi;
		my $method = $1;
		$method = "post" if(!$method or $method !~/^get$/i);
		my @inputs = &get_input($r);
		next if(scalar(@inputs) < 2);
		$semaphore->down();
		if(!$pages{$action}){
			$pages{'Action: ' .$action} .= "\n   Method: $method\n";
			foreach my $inp (@inputs){
				$pages{'Action: ' .$action} .= " ". $inp;
				$x++;
			}
		}
		$semaphore->up();
	}
}


sub showResults(){
	my ($self, $report_id) = @_;
	my $cp = "";
	my $qv=0;
	foreach my $w (keys %pages){
		if($pages{$w} =~/password/i){
			$cp .= $w . ':' . $pages{$w} . "\n";
			$qv++;
		}
	}
	$cp =~s/'/\\'/gi;
	$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$cp', 0, 0, 0, 0, 0, 10)");
	$func->insert("UPDATE historico SET loginform = $qv WHERE report_id= $report_id");

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

sub get_input(){
		my $content = shift;
		my @input = ();
		my $pw = 0;
		while ($content =~  m/<input(.+?)>/gi){
			my $inp = $1;
			my $name = "";
			my $value = "";
			my $type = "";
			#print "inp: $inp\n";
			while($inp =~ m/(\w+) *= *['"](.+?)['"]/gi){
				${$1} = $2;
				$pw = 1 if(${'type'} == "password")
			}
			#print "input type: ". ${'type'} . " input name: " . ${'name'}. " input value: ". ${'value'} . "\n";
			push(@input, "  Nome do input: " .${'name'} . " Tipo:". ${'type'} . " Valor: ". ${'value'}."\n");
			${'name'} = "";
			${'type'} = "";
			${'value'} = "";
			
		}
		return @input if($pw);
		my @a = ("");
		return @a;
	}

1;

