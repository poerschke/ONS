package Uniscan::MySQL;

use Moose;
use Uniscan::Configure;
use DBI;

my %conf = ( );
my $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
%conf = $cfg->loadconf();
our $con;
	
sub conecta(){
	my $self = shift;
	$con = DBI->connect('DBI:mysql:'. $conf{'database'} .';host=' . $conf{'database_host'}, $conf{'database_user'}, $conf{'database_pass'},{ RaiseError => 0 }) or &conecta();
	
}


sub insert(){
	my ($self, $sql) = @_;
	#print "sql: $sql\n";
	return $con->do($sql);
}

sub select(){
	my ($self, $sql) = @_;
	my $res = $con->prepare($sql);
	$res->execute();
	return $res;
}


sub disconecta(){
	my $self = shift;
	$con->disconnect();
}

1;
