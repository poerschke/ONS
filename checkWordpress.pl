#!/usr/bin/perl -w

use Uniscan::Configure;
use Uniscan::Functions;
use Uniscan::Http;
use threads;
use threads::shared;
use Thread::Queue;
use Thread::Semaphore;
use Digest::MD5;

my $c = Uniscan::Configure->new(conffile => "uniscan.conf");
my $func = Uniscan::Functions->new();
my $http = Uniscan::Http->new();
my $q = new Thread::Queue;
my $semaphore = Thread::Semaphore->new();

our %conf = ( );
%conf = $c->loadconf();
$|++;

#metricas
our $requests : shared = 0;
our %testado : shared = ();
our $arqs : shared = 0;
our $vuls : shared = 0;
our %vtestado : shared = ();
our $varst : shared = 0;
our %varvul : shared = ();
our $vvar : shared = 0;
our %arqvul : shared = ();
our $arqv : shared = 0;



our $report_id :shared = $ARGV[0];
my $url = $func->pega_site($report_id);
my $t = threads->new(\&online);
$res = $http->GET($url);
$requests++;
my $versao;

if ($res =~/name="generator" content="WordPress (.+?)[",]/ig) {
	$versao = $1;
}
else{
	$res = $http->GET($url.'readme.html');
	$requests++;
	if ($res =~/<br \/> Version (.+?)\n/ig) {
		$versao = $1;
	}
	else{
		$versao = &md5_versao($url, $http);
		print "Versao $versao com md5\n" if(defined($versao));
	}
}
if (defined($versao)) {
		my $atual = &versao_atual($http);
		my $vuls = $func->wordpress_vuln_by_version($versao);
		$vuls = 0 if(!defined($vuls));
		my %v = $func->wordpress_vuls($versao);
		foreach my $key (keys %v){
			print $v{$key}{'titulo'} . "\n";
		}
		$func->insert("UPDATE report SET wordpress = 1, versaowordpress = '$versao', worpressatual='$atual' WHERE report_id= $report_id");
		$func->insert("UPDATE historico SET wordpress = $vuls WHERE report_id= $report_id");
		
		$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '', 0, $vuls, 0, 0, $requests, 32)");
}
else {
		$func->insert("UPDATE historico SET wordpress = $vuls WHERE report_id= $report_id");
		$func->insert("INSERT INTO vulnerabilidade(report_id, dados, arq_testados, arq_vuls, var_testadas, var_vuls, reqs, tipo_id) VALUES($report_id, '', 0, $vuls, 0, 0, $requests, 32)");
}

$t->join();

	
sub md5_versao(){
	my ($site, $h) = @_; 
	my %ver = ();
	$ver{'3.7.1'}{'arquivo'} = "wp-includes/js/tinymce/plugins/wpeditimage/editor_plugin_src.js";
	$ver{'3.7.1'}{'md5'} = "5d01c0e812cdcd6356b78ee0cb4e5426";
	$ver{'3.7'}{'arquivo'} = "wp-includes/js/jquery/jquery.form.js";	
	$ver{'3.7'}{'md5'} = "e5afd8e41d2ec22c19932b068cd90a71";
	$ver{'3.6.1'}{'arquivo'} = "wp-admin/js/common.js";
	$ver{'3.6.1'}{'md5'} = "03eaffeef39119f0523a49c7f9767f3b";
	$ver{'3.3'}{'arquivo'} = "wp-admin/js/common.js";
	$ver{'3.3'}{'md5'} = "4516252d47a73630280869994d510180";
	$ver{'3.6'}{'arquivo'} = "wp-includes/js/jquery/jquery.js";
	$ver{'3.6'}{'md5'} = "9dcde2d5e8aeda556a0c52239fa2f44c";
	$ver{'3.5.2'}{'arquivo'} = "wp-includes/js/tinymce/tiny_mce.js";
	$ver{'3.5.2'}{'md5'} = "eddb5fda74d41dbdac018167536d8d53";	
	$ver{'3.5.1'}{'arquivo'} = "wp-includes/js/tinymce/tiny_mce.js";	
	$ver{'3.5.1'}{'md5'} = "6e79ab6d786c5c95920064add33ee599";
	$ver{'3.5'}{'arquivo'} = "wp-includes/js/tinymce/tiny_mce.js";
	$ver{'3.5'}{'md5'} = "55cd8e5ceca9c1763b1401164d70df50";
	$ver{'3.4.2'}{'arquivo'} = "wp-includes/js/wp-lists.js";
	$ver{'3.4.2'}{'md5'} = "46e1341cd4ea49f31046f7d7962adc7f";
	$ver{'3.4.1'}{'arquivo'} = "wp-includes/js/customize-preview.js";
	$ver{'3.4.1'}{'md5'} = "617d9fd858e117c7d1d087be168b5643";	
	$ver{'3.4'}{'arquivo'} = "wp-includes/js/customize-preview.js";
	$ver{'3.4'}{'md5'} = "da36bc2dfcb13350c799b62de68dfa4b";
	$ver{'3.4-beta4'}{'arquivo'} = "wp-includes/js/customize-preview.js";
	$ver{'3.4-beta4'}{'md5'} = "a8a259fc5197a78ffe62d6be38dc52f8";
	$ver{'3.3.2'}{'arquivo'} = "wp-includes/js/plupload/plupload.js";
	$ver{'3.3.2'}{'md5'} = "85199c05db63fcb5880de4af8be7b571";
	$ver{'3.3.1'}{'arquivo'} = "wp-content/themes/twentyeleven/style.css";
	$ver{'3.3.1'}{'md5'} = "030d3bac906ba69e9fbc99c5bac54a8e";
	$ver{'3.2.1'}{'arquivo'} = "wp-admin/js/wp-fullscreen.js";
	$ver{'3.2.1'}{'md5'} = "5675f7793f171b6424bf72f9d7bf4d9a";
	$ver{'3.2'}{'arquivo'} = "wp-admin/js/wp-fullscreen.js";
	$ver{'3.2'}{'md5'} = "7b423e0b7c9221092737ad5271d09863";
	$ver{'3.8'}{'arquivo'} = "wp-includes/css/admin-bar.css";
	$ver{'3.8'}{'md5'} = "4077bbaddd5b0afec30d0465dfee9a1f";
	$ver{'3.1'}{'arquivo'} = "wp-includes/css/admin-bar.css";
	$ver{'3.1'}{'md5'} = "181250fab3a7e2549a7e7fa21c2e6079";
	$ver{'3.0'}{'arquivo'} = "wp-content/themes/twentyten/style.css";
	$ver{'3.0'}{'md5'} = "6211e2ac1463bf99e98f28ab63e47c54";
	$ver{'2.8.6'}{'arquivo'} = "wp-plugins/akismet/readme.txt";
	$ver{'2.8.6'}{'md5'} = "4d5e52da417aa0101054bd41e6243389";
	$ver{'2.8.5'}{'arquivo'} = "wp-plugins/akismet/readme.txt";
	$ver{'2.8.5'}{'md5'} = "58e086dea9d24ed074fe84ba87386c69";
	$ver{'2.8.2'}{'arquivo'} = "wp-plugins/akismet/readme.txt";
	$ver{'2.8.2'}{'md5'} = "48c52025b5f28731e9a0c864c189c2e7";
	$ver{'2.7.1'}{'arquivo'} = "wp-includes/js/wp-ajax-response.js";
	$ver{'2.7.1'}{'md5'} = "0289d1c13821599764774d55516ab81a";
	$ver{'2.7'}{'arquivo'} = "wp-includes/js/thickbox/thickbox.css";
	$ver{'2.7'}{'md5'} = "9c2bd2be0893adbe02a0f864526734c2";
	$ver{'2.6'}{'arquivo'} = "wp-includes/js/tinymce/plugins/wpeditimage/editor_plugin.js";
	$ver{'2.6'}{'md5'} = "5b140ddf0f08034402ae78b31d8a1a28";
	$ver{'2.5.1'}{'arquivo'} = "wp-includes/js/tinymce/themes/advanced/js/image.js";
	$ver{'2.5.1'}{'md5'} = "088245408531c58bb52cc092294cc384";
	$ver{'2.5'}{'arquivo'} = "wp-includes/js/tinymce/themes/advanced/js/link.js";
	$ver{'2.5'}{'md5'} = "19c6f3118728c38eb7779aab4847d2d9";
	$ver{'2.2'}{'arquivo'} = "wp-includes/js/wp-ajax.js";
	$ver{'2.2'}{'md5'} = "c5dbce0c3232c477033e0ce486c62755";
	$ver{'2.0.1'}{'arquivo'} = "wp-content/themes/default/style.css";
	$ver{'2.0.1'}{'md5'} = "e44545f529a54de88209ce588676231c";
	$ver{'2.0'}{'arquivo'} = "wp-content/themes/default/style.css";
	$ver{'2.0'}{'md5'} = "f786f66d3a40846aa22dcdfeb44fa562";
	$ver{'1.2.1'}{'arquivo'} = "wp-layout.css";
	$ver{'1.2.1'}{'md5'} = "7140e06c00ed03d2bb3dad7672557510";
	$ver{'1.2-delta'}{'arquivo'} = "wp-layout.css";
	$ver{'1.2-delta'}{'md5'} = "1bcc9253506c067eb130c9fc4f211a2f";
	$ver{'0.71'}{'arquivo'} = "layout2b.css";
	$ver{'0.71'}{'md5'} = "baec6b6ccbf71d8dced9f1bf67c751e1";

        my $MD5 = Digest::MD5->new;
	my $x = 0;
	foreach my $key (keys %ver){
		print "\rDeterminando versao[$x] ";
		$res = $h->GET1($site . $ver{$key}{'arquivo'});
		$requests++;
	        $MD5->add($res->content);
	        my $checksum = $MD5->hexdigest;
		return $key if($checksum eq $ver{$key}{'md5'});
		$x++;
	}
	return undef;
}



sub versao_atual(){
	my $h = shift;
	my $res = $h->GET('http://wordpress.org/download/counter/');
	if($res =~m/<h2>WordPress (.+?) has/ig){
		my $versao = $1;
		return $versao;
	}
	return undef;
}







sub checa_online(){
        my $h = Uniscan::Http->new();
        my $x=0;
        my $site = $func->pega_site($report_id);
	print "site: $site\n";
        while ($x<=10) {
                my $res = $h->GET1($site);
                if ($res->is_success) {
                        return 1;
                }
                else{
			print "sleep de 30\n";
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
                print "sleep de 10\n";
		sleep(10);
        }
	#exit();
}

