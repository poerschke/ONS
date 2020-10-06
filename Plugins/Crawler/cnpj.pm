package Plugins::Crawler::cnpj;

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
	my $self     = {name => "CNPJ Disclosure", version => 1.0};
	our $enabled = 1;
	return bless $self, $class;
}

sub execute {
	my $self = shift;
	my $url = shift;
	my $content = shift;

	while($content =~m/([0-9]{2}\.[0-9]{3}\.[0-9]{3}\/[0-9]{4}\-[0-9]{2})/gi){
		my $cnpj = $1;
		#$cnpj =~s/\.|\-|\///g;
		$semaphore->down();
		if(!$pages{$cnpj . "|" . $url}){
			$pages{$cnpj . "|" . $url} = 1;
			
		}
		$semaphore->up();
		
	}
}


sub showResults(){
	my ($self, $report_id)= @_;
        my $cn = "";
	foreach my $w (keys %pages){
		$cn .= $w . "\n" if($pages{$w});
		$qv++;
	}
	$cn =~s/'/\\'/gi;
	$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$cn', 0, 0, 0, 0, 0, 2)");
	$func->insert("UPDATE historico SET cnpj = $qv WHERE report_id= $report_id");
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

sub formata(){
	my $cnpj = shift;
	my $ret = sprintf("%d%d.%d%d%d.%d%d%d/%d%d%d%d-%d%d", split('', $cnpj));
	return $ret;
}

use Scalar::Util qw(looks_like_number);
sub _canon_id {
  my $piece = shift;
  my %options = @_;
  if (looks_like_number($piece) && int($piece)==$piece) {
      return sprintf('%0*s', $options{size}, $piece)
  } else {
      $piece =~ s/[\W_]//g;
      return $piece;
  }
}


sub _dot {
  my $a = shift;
  my $b = shift;
  warn "arguments a and b should have the same length"
    unless (@$a==@$b);
  my $s = 0;
  for ( my $i=0; $i<@$a; $i++ ) {
    my ($x, $y) = ($a->[$i], $b->[$i]);
    if ($x && $y) {
       $s += $x*$y;
    }
  }
  return $s;
}

sub canon_cnpj {
  return _canon_id(shift, size => 14);
}  

sub verifica {
  my $cnpj = canon_cnpj shift;
  return undef if length $cnpj != 14;
  my @cnpj = split '', $cnpj;
  my $s1 = _dot([5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0], \@cnpj) % 11;
  my $s2 = _dot([6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2, 1], \@cnpj) % 11;
  unless ($s1==0 || $s1==1 && $cnpj[12]==0) {
    return 0;
  }
  return ($s2==0 || $s2==1 && $cnpj[13]==0) ? 1 : 0;
}

1;

