#!/usr/bin/perl -w

use lib "./Uniscan";
use Uniscan::Configure;
use Uniscan::Functions;
use Uniscan::Http;
use threads;
use threads::shared;
use Thread::Queue;
use Thread::Semaphore;

my $c = Uniscan::Configure->new(conffile => "uniscan.conf");
my $func = Uniscan::Functions->new();
my $http = Uniscan::Http->new();
my $q = new Thread::Queue;

our %conf = ( );
%conf = $c->loadconf();
$|++;

#metricas
our $requests : shared = 0;
our %testado : shared = ();
our $arqs : shared = 0;
our $vuls : shared = "";
our %vtestado : shared = ();
our $varst : shared = 0;
our %varvul : shared = ();
our $vvar : shared = 0;
our %arqvul : shared = ();
our $arqv : shared = 0;

our $report_id :shared= $ARGV[0];
my @urls = $func->pega_dados_crawler($report_id);
my $semaphore = Thread::Semaphore->new();

our @SQL = (
	"'",
	"\"",
	";"
);
my $t = threads->new(\&online);
&ScanSQLCrawler(@urls);	
&ScanSQLCrawlerPost(@urls);

$vuls =~s/'/\\'/g;
$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '$vuls', $arqs, $arqv, $varst, $vvar, $requests, 23)");
$func->insert("UPDATE historico SET sqli = $vvar WHERE report_id= $report_id");
	        while($q->pending > 0){
	                $q->dequeue;
	        }
$t->join();


sub ScanSQLCrawler(){
	my @urls = @_;
	my @tests = &GenerateTestsSql("SQL", @urls) if(scalar(@urls));
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestSQL", @tests) if(scalar(@tests));
}

sub ScanSQLCrawlerPost(){
	my  @urls = @_;
	my @tests = &GenerateTestsPostSql("SQL", @urls);
	@tests = $func->remove(@tests) if(scalar(@tests));
	&threadnize("TestSQLPost", @tests) if(scalar(@tests));
}

sub TestSQL(){
	while($q->pending > 0){
		$semaphore->down();
		my $test = $q->dequeue;
		$semaphore->up();
		next if(not defined $test);
		if($test !~/\|#\|/){
			if(!$varvul{&gera_var_vul($test)}){
				&metrica_testados($test);
				my $resp = $http->GET($test);
				$requests++;
				if($resp =~/Microsoft OLE DB Provider for ODBC Drivers|Microsoft OLE DB Provider for SQL Server|Microsoft OLE DB Provider for Oracle|error '80040e14'|Syntax error in string in query expression|Microsoft JET Database Engine|You have an error in your SQL syntax|Microsoft OLE DB Provider for ODBC Drivers|Supplied argument is not a valid .* result|Unclosed quotation mark after the character string|Query failed: ERROR:  syntax error at or near|ORA\-00933: SQL command not properly ended/i){
					my $var;
					#print "url: $test\n";
					$var = substr($test, rindex($test, '&')+1, length($test)-1) if($test =~/&/);
					$var = substr($test, rindex($test, '?')+1, length($test)-1) if($test !~/&/);
					#print "var: $var\n";
					my ($v, $valor) = split('=', $var);
					#print "v: $v\n";
					my $temp = $test;
					$temp =~ s/'|"|;//g;
					#print "$temp";
					if(&sqlmap($temp, $v)){
						$vuls .= $test . "\n";
						&metricas_vul($test);
					}
				}
				$resp = 0;
			}
		}
	}
	$q->enqueue(undef);
}


sub TestSQLPost(){
	while($q->pending > 0){
		$semaphore->down();
		my $test = $q->dequeue;
		$semaphore->up();
		next if(not defined $test);
		next if(!$test =~/\|#\|/);
		if($test =~/\|#\|/){
			if(!$varvul{&gera_var_vul($test)}){
				my ($url, $data) = split('\|#\|', $test);
				&metrica_testados($url."|#|".$data);
				my $resp = $http->POST($url, $data);
				$requests++;
				if($resp =~/You have an error in your SQL syntax|Microsoft OLE DB Provider for ODBC Drivers|Supplied argument is not a valid .* result|Unclosed quotation mark after the character string/i){

					my $temp = $data;
					$temp =~s/'|"|;//g;
					my $var;
					$var = substr($temp, rindex($temp, '&')+1, length($temp)) if($temp =~/&/);
					($var, undef) = split('=', $temp) if($temp !~/&/);
					my $v;
					if($var =~ /=/){
						($v, undef) = split('=', $var);
					}
					else{
						$v = $var;
					}
					if(&sqlmap_post($url, $temp, $v)){
						$vuls .= $url."|#|".$data."\n";
						&metricas_vul($url."|#|".$data);
					}
				}
				$resp = 0;
			}
		}
	}
	$q->enqueue(undef);
}



sub GenerateTestsSql(){
	my ($test, @list) = @_;
	my @list2 = ();
	foreach my $line (@list){
		$line =~ s/&amp;/&/g;
		$line =~ s/\[\]//g;
		if($line =~ /=/){
			my $temp = $line;
			$temp = substr($temp,index($temp, '?')+1,length($temp));
			my @variables = split('&', $temp);
			for(my $x=0; $x< scalar(@variables); $x++){
				no strict 'refs';
				if($variables[$x]){
					foreach my $str (@{$test}){
						$temp = $line;
#						$str = urlencode($str) if($conf{'url_encode'} == 1);
						my $t = $variables[$x] . $str;
						$temp =~ s/\Q$variables[$x]\E//g;
						$temp .= '&' .$t;
						$temp =~s/\?&/\?/g;
						$temp =~s/&&/&/g;
						push(@list2, $temp);
					}
				}
			}
		}
	}
	@list = ();
	return @list2;
}


sub GenerateTestsPostSql(){
	my ($test, @list) = @_;
	my @list2 = ();
	foreach my $linha (@list){
		if($linha =~/\|#\|/g){
			my ($url, $line) = split('\|#\|', $linha);
			$line =~ s/&amp;/&/g;
			$line =~ s/\[\]//g;
			if($line =~ /=/){
				my $temp = $line;
				$temp = substr($temp,index($temp, '?')+1,length($temp));
				my @variables = split('&', $temp);
				for(my $x=0; $x< scalar(@variables); $x++){
					no strict 'refs';
					if($variables[$x]){
						foreach my $str (@{$test}){
							$temp = $line;
#							$str = urlencode($str) if($conf{'url_encode'} == 1);
							my $t = $variables[$x] . $str;
							$temp =~ s/\Q$variables[$x]\E//g;
							$temp .= '&' .$t;
							$temp =~s/\?&/\?/g;
							$temp =~s/&&/&/g;
							push(@list2, $url . '|#|' .$temp);
						}
					}
				}
			}
		}
	}
	@list = ();
	return @list2;
}



 sub threadnize(){
	my ($fun, @tests) = @_;
	foreach my $test (@tests){
		$q->enqueue($test) if($test);
	}

	my $x=0;
	my @threads = ();
	while($q->pending() && $x <= $conf{'max_threads'}-1){
		no strict 'refs';
		push @threads, threads->new(\&{$fun});
		$x++;
	}

	sleep(2);
	foreach my $running (@threads) {
		$running->join();
	}
	@threads = ();
}


sub gera_var_vul(){
	my $url = shift;
	my $varl = substr($url, rindex($url, '&')+1, length($url));
	my ($var, $valor) = split('=', $varl);
	my $str = $func->get_file($url) . $var;
	return $str;
	
}

sub metricas_vul(){
	my $url = shift;
	if(!$arqvul{$func->get_file($url)}){
		$arqvul{$func->get_file($url)} = 1;
		$arqv++;
	}
	
	if(!$varvul{&gera_var_vul($url)}){
		$varvul{&gera_var_vul($url)} = 1;
		$vvar++;
	}
}

sub metrica_testados(){
	my $url = shift;
	if(!$testado{$func->get_file($url)}){
		$testado{$func->get_file($url)}=1;
		$arqs++;
	}
	if(!$vtestado{&gera_var_vul($url)}){
		$vtestado{&gera_var_vul($url)}=1;
		$varst++;
	}	
}


sub checa_online(){
        my $h = Uniscan::Http->new();
        my $x=0;
        my $site = $func->pega_site($report_id);
        while ($x<=10) {
                my $res = $h->GET1($site);
                if ($res->is_success) {
                        return 1;
                }
                else{
                        sleep(30);
                }
                $x++;
        }
        &grava_waf();
        return 0;
}

sub grava_waf(){
        $func->insert("UPDATE report SET waf=1 WHERE report_id=". $report_id);
}

sub online(){
        while(checa_online() && $q->pending > 0){
                sleep(10);
        }
	#exit();
        while($q->pending > 0){
                $q->dequeue;
        }
}


sub sqlmap($$){
        my $url = shift;
        my $param = shift;
        my $sqlmap = "/opt/ONS/sqlmap/sqlmap.py -u '". $url ."' -p ". $param ." --batch --purge-output";
        my $ret = `$sqlmap`;
        if($ret =~/sqlmap identified the following injection/gi){
                print "SQLMAP: 1\n";
                return 1;
        }
        else{
                print "SQLMAP: 0\n";
                return 0;
        }
}



sub sqlmap_post($$$){
        my $url = shift;
	my $post = shift;
        my $param = shift;
        my $sqlmap = "/opt/ONS/sqlmap/sqlmap.py -u '". $url ."' -p ". $param ." --batch --purge-output --data='".$post."'";
        my $ret = `$sqlmap`;
        if($ret =~/sqlmap identified the following injection/gi){
                print "SQLMAP POST: 1\n";
                return 1;
        }
        else{
                print "SQLMAP POST: 0\n";
                return 0;
        }
}

