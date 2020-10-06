package Plugins::Crawler::externalHost;

use Uniscan::Functions;
use URI;
use  Thread::Semaphore;
use Uniscan::Configure;
	
my %conf = ( );
my $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
%conf = $cfg->loadconf();
my $func = Uniscan::Functions->new();
our %external : shared = ();
my $semaphore = Thread::Semaphore->new();

sub new {
    my $class    = shift;
    my $self     = {name => "External Host Detect", version => 1.2};
	our $enabled = 1;
    return bless $self, $class;
}

sub execute {
    my $self = shift;
    my $url = shift;
    my $content = shift;
    my $url_uri = &host($url);
    $url = $func->get_url($url);
    my @ERs = (	"href=\"(.+)\"", 
		"href='(.+)'", 
		"href=(.+?)>", 
		"location.href='(.+)'",
		"src='(.+)'",
		"src=\"(.+)\"",
		"location.href=\"(.+)\"", 
		"<meta.*content=\"?.*;URL=(.+)\"?.*?>"
    );
			
	foreach my $er (@ERs){
		while ($content =~  m/$er/gi){
			my $link = $1;
			next if($link =~/[\s"']/);
			$link = &get_url($link);
			if($url ne $link){
	                    if($link !~ /$url_uri/){
					$semaphore->down();
					$external{$link}++ if($link);
					$semaphore->up();
 			    }
			}
		}
	}
	

}


sub showResults(){
	my ($self, $report_id) = @_;
	my $cp = "";
	my $qv=0;
	foreach my $url (keys %external){
		if($external{$url}){
			$cp.= $url ."\n";
			$qv++;
		}
	}
	$cp =~s/'/\\'/gi;
        $func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$cp', 0, 0, 0, 0, 0, 7)");
		$func->insert("UPDATE historico SET links = $qv WHERE report_id= $report_id");
}

sub getResults(){
	my $self = shift;
	return %external;
}

sub clean(){
	my $self = shift;
	%external = ();
}

sub status(){
	my $self = shift;
	return $enabled;
}

sub get_url(){
	my $url = shift;
	if($url =~/http:\/\//){
		$url =~s/http:\/\///g;
		$url = substr($url, 0, index($url, '/')) if($url =~/\//);
		return "http://" . $url;
	}
	if($url =~/https:\/\//){
		$url =~s/https:\/\///g;
		$url =  substr($url, 0, index($url, '/')) if($url =~/\//);
		return "https://" . $url;
	}
}


##############################################
#  Function host
#  this function return the domain of a url
#
#  Param: a $url
#  Return: $domain of url
##############################################

sub host(){
  	my $h = shift;
  	my $url1 = URI->new( $h || return -1 );
  	return $url1->host();
}



1;
