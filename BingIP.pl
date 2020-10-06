#!/usr/bin/perl
	
	use lib "./Uniscan";
	use Uniscan::Http;
	use Uniscan::Functions;
	use Uniscan::Configure;
	
	my %conf = ( );
	my $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
	%conf = $cfg->loadconf();
	my $func = Uniscan::Functions->new();
        my $report_id = $ARGV[0];
	my $ip = $func->pega_ip($report_id);
	
	&search($ip);
	
	sub search(){
		my $search = shift;
		
		my $http = Uniscan::Http->new();
		my $x = 0;
		my $y = 701;
		my ($bing, $response) = "";
		my %sites = ();
		for($x=0; $x <= $y; $x+=10){
			$bing = 'http://www.bing.com/search?q=ip:'.$search.'&first='.$x.'&FORM=PORE';
			$response = $http->GET($bing);
			while ($response =~  m/<cite>(.*?)<\/cite>/g){
				my $site = $1;
				$site =~s/<strong>|<\/strong>//g;
				$site = substr($site, 0, index($site, '/')) if($site =~/\//);
				if(!$sites{$site}){
					$sites{$site} = 1;
				}
			}
			$y = 10 * &getmax($response) + 1;
		}
		my $si = "";
		foreach my $key (keys %sites){
			$si .= $key . "\n";
		}
		$si =~s/'/\\'/gi;
		$func->insert("UPDATE report SET sites_hospedados = '$si' WHERE report_id=$report_id");
	}
	
	
	sub getmax(){
		my $content = shift;
		my $max = 0;
		while($content =~m/<li><a href="\/search\?q=.+">(\d+)<\/a><\/li>/g){
			$max = $1;
		}
		return $max;
	}
