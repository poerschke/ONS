#!/usr/bin/perl
	
	use threads;
	use threads::shared;
	use Thread::Queue;
	use strict;
	use URI;
	use lib "./Uniscan";
	use Uniscan::Http;
	use Uniscan::Configure;
	use Uniscan::Functions;
	use Uniscan::Factory;
	use Thread::Semaphore;
	
	$|++;
	
	
	our $pri 	: shared 	= 1;
	our $tempo 	: shared	= 20;
	our $last_req	: shared	= -1;
	our $requests 	: shared 	= 0;
	our $u		: shared 	= 0;
	our $reqs	: shared 	= 0;

	our @list	: shared 	= ( );
	my  @threads			= ( );

	our %forms	: shared 	= ( );
	our %checado	: shared	= ( );
	our %checado2	: shared	= ( );
	our %urls	: shared	= ( );
	our %ignored  	: shared	= ( );
	our %files 	: shared	= ( );
	
	our %conf = ( );
	our @url_list = ( );
	our @plugins = ();

	my $p = 0;
	my $pat = 0;

	our $func = Uniscan::Functions->new();
	my $q = new Thread::Queue;
	our $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
	my $semaphore = Thread::Semaphore->new();
	%conf = $cfg->loadconf();
	

	our $report_id :shared = $ARGV[0];
	our $urlsite :shared = $func->pega_site($report_id);
	print "site: $urlsite\n";	
	
	&AddUrl($urlsite);
	$urlsite =~ s/\/$//gi;


	my @robots = &CheckRobots($urlsite);
	my $rob = "";
	foreach my $r (@robots){
		&AddUrl($r);
		$rob .= $r."\n";
	}

	my @sitemap = &CheckSitemap($urlsite);
	my $simap = "";
	foreach my $r (@sitemap){
		&AddUrl($r);
		$simap .= $r . "\n";
	}
	&AddUrl($urlsite."/");
	
	foreach my $dir ($func->pega_dados($report_id, "diretorios")){
		&AddUrl($dir);
	}

	foreach my $dir ($func->pega_dados($report_id, "arquivos")){
		&AddUrl($dir);
	}

	foreach my $dir ($func->pega_dados($report_id, "banner_result")){
		&AddUrl($dir);
	}

        my $url = $func->CheckRedirect($urlsite);
        my $url_temp = $url;
        my $proto = "";
        if($url_temp =~ /http:\/\//){
        	$proto = "http://";
        }
        else{ $proto = "https://"; }
        $url_temp =~s/https?:\/\///g;
        if(rindex($url_temp, '/') != index($url_temp, '/')){
                $url_temp = $proto . substr($url_temp, 0, index($url_temp, '/')+1);
                &AddUrl($url_temp);
        }


		
	$urlsite .= '/';
	my $t = threads->new(\&online);
	&loadPlugins();
	&start();
	$t->join();






	sub get_input(){
		my $content = shift;
		my @input = ();
		while ($content =~  m/<input(.+?)>/gi){
			my $inp = $1;
			if($inp =~ /name/i){
				$inp =~ m/name *= *"(.+?)"/gi;
				push(@input, $1);
			}
		}
	
		while ($content =~  m/<select(.+?)>/gi){
			my $inp = $1;
			if($inp =~ /name/i){
				$inp =~ m/name *= *"(.+?)"/gi;
				push(@input, $1);
			}
		}
	
		while ($content =~  m/<textarea(.+?)>/gi){
			my $inp = $1;
			if($inp =~ /name/i){
				$inp =~ m/name *= *"(.+?)"/gi;
				push(@input, $1);
			}
		}
		return @input;
	}
	
	
	
	sub get_extension(){
		my  $file = shift;
		if($file =~/\./){
			my $ext = substr($file, rindex($file, '.'), length($file));
			$ext =~ s/ //g;
			if($ext !~/\(|\)|\-|\//){
				return $ext;
			}
			else {
				return 0;
			}
		}
		else{
			return 0;
		}
	}
	
	
	
sub pega_action(){
	my ($url, $conteudo) = @_;
	my $protocolo;
	$protocolo = "http://" if($url =~/^http:\/\//i);
	$protocolo = "https://" if($url =~/^https:\/\//i);
	my $diretorio = &diretorio_atual($url);
	my $dom = $func->host($url);
	
	while($conteudo =~ m/action\s*=\s*['"](.+?)['"]/gsi){
		my $action = $1;
		if($action =~m/^https?:\/\/\Q$dom\E/gi){
			return $action;
		}
		if($action =~ m/^\//){
			$action = $protocolo . $dom . $action;
			return $action;
		}
		if($action !~/^\/|^https?:\/\//i){
			$action = $protocolo . $dom . $diretorio . $action;
			return $action;
		}
		return $action if($action =~/^https?:\/\//);
		return $url;
	}
}	







	sub add_form(){
		my ($url, $conteudo) = @_;
		my @form = ();
		while($conteudo =~m/<form(.+?)<\/form>/gsi){
			my $f_cont = $1;
			my $action = &pega_action($url, $f_cont);
			my $dominio = &host($url);
			next if($action !~/$dominio/);
			my $method;
			while($f_cont =~m/method *= *["'](.+?)["']/gsi){
				$method = $1;
			}
			$method = "post" if(!$method);
			my @inputs = &get_input($f_cont);
			
			if($method =~ /get/i ){
				my $url2 = $action . '?';
				foreach my $var (@inputs){
					$url2 .= '&'.$var .'=123' if($var && $url2 !~/\Q$var\E/);
				}
				push(@form, $url2);
			}
			else{
				my $data = "";
				foreach my $var (@inputs){
					$data .='&'.$var.'=123' if($var && $data !~/\Q$var\E/);
				}
				push(@form, $action . "|#|" . $data);
			}
		}
	return(@form);
	}	
	
	
	
	
	
	
	sub get_urls(){
		my $url = shift; 
		
		return if($url !~/^$urlsite/i);
		my $h = Uniscan::Http->new();
		my $resultado = "";
		my $response;
		
		if($url =~ /\|#\|/g){
			#print "url: $url\n";
			my ($action, $data) = split('\|#\|', $url);
			#print "POST: $action\n$data\n";
			$response = $h->POST1($action, $data);
			$requests++;
		}
		else{
			$response = $h->GET1($url);
			$requests++;
		}
		return if(!$response);
		return if(!$response->is_success);
		
		$url = $response->request->uri;
		return if($url !~/^$urlsite/i);

		$resultado = $response->decoded_content;
		foreach my $p (@plugins){
			$p->execute($url, $resultado) if($p->status() == 1);
		}

		my $dominio = &host($url);
		my $diretorio = &diretorio_atual($url);
		my $protocolo = "";
		$protocolo = "http://" if($url =~/^http:\/\//i);
		$protocolo = "https://" if($url =~/^https:\/\//i);
		
		my @uurls = &parser($resultado);
 		if($resultado =~ m/<form/gi){
			my @posts = &add_form($url, $resultado);
			foreach my $post (@posts){
				push(@uurls, $post);
			}
		}
		@uurls = &classifica_urls($protocolo, $dominio, $diretorio, @uurls);
		#@uurls = &adiciona_diretorios(@uurls);
		@uurls = &verifica_variacao(@uurls);
		@uurls = &verifica_ignorados(@uurls);
		@uurls = &checa_head(@uurls);	
		return(@uurls);
	}
	
	
	
	
	sub crawling(){
		
		while($reqs <= $conf{'max_reqs'}){
			sleep(5) if($q->pending < 1);
			$semaphore->down();
			my $l = $q->dequeue if($q->pending);
			
			$semaphore->up();
			next if(not defined $l);
			next if($l !~/https?:\/\//i);
			$reqs++;
			my @tmp = &get_urls($l);
			foreach my $t (@tmp){
				if(!$urls{$t}){
					push(@list, $t);
					$q->enqueue($t);
					$u++;
					$urls{$t} = 1;
					
				}
			}
			#printf("\r| [*] ". $conf{'lang28'} ." Pages: [%d - %d %2.1f%%] Requests: [%d]\r", $reqs, $u, (($reqs*100)/$u), $requests);
			$pri = 0;
		}
		
		$q->enqueue(undef);
	}
	
	
	
	
	
	sub start(){
		$reqs = 0;
		$pat = $func->INotPage($url_list[1]);
		foreach my $ur (@url_list){
			$q->enqueue($ur);
		}
		$semaphore->down();
		$u = scalar(@url_list);
		$semaphore->up();
		$url = $url_list[0];
		my $controlador = threads->new(\&baixa_threads);	
		my $x =0;
		while($x < $conf{'max_threads'}){
			$x++;
			push @threads, threads->new(\&crawling);
			
			while($pri == 1){
				sleep(1);
			}
		}
		
		
		foreach my $running (@threads) {
			$running->join();
			
		}
	
		while($q->pending()){
			$q->dequeue;
		}
		
		$controlador->join;
	
		
		foreach my $plug (@plugins){
			$plug->showResults($report_id)  if($plug->status() == 1);
			$plug->clean()  if($plug->status() == 1);
		}
		if($list[0]){
			while($list[0] !~ /^https?:\/\//i && $list[0]){
				shift @list;
			}
		}
		my $ign = "";
		foreach my $key (keys %ignored){
			$ign .= $key . "\n";
		}
		
		my $lst = "";
		foreach my $key (@list){
			$lst .= $key . "\n" if($key =~/^$urlsite/i);
		}
		$lst =~s/'/\\'/gi;
		$ign =~s/'/\\'/gi;
		$rob =~s/'/\\'/gi;
		$simap =~s/'/\\'/gi;
		$func->insert("UPDATE report SET urls = '$lst', ignorados =  '$ign', robots ='$rob', sitemap='$simap', reqs= $requests WHERE report_id = $report_id");
		return @list;
		
	}
	

	
	sub AddUrl(){
	my $ur = shift;
		push(@url_list, $ur) if($ur =~/^https?:\/\//i);
	}
	
	
		
	sub CheckRobots(){
		my  $url = shift;
		my $h = Uniscan::Http->new();
		my @found = ();
		my $content = $h->GET($url."/robots.txt");
		$requests++;
		if($content =~/Allow:|Disallow:/){
		    
			my @file = split("\n", $content);
			foreach my $f (@file){
				my ($tag, $dir) = split(' ', $f);
				if($dir){  
				push(@found, $url.$dir) if($dir =~/^\//);
				}
			}
		}
	return @found;
	}
	
	
	sub CheckSitemap(){
		my $url = shift;
		my $h = Uniscan::Http->new();
		my @found = ();
		my $content = $h->GET($url."/sitemap.xml");
		$requests++;
		$content =~s/\n//g;
		$content =~s/\r//g;
		while($content =~ m/<loc>(.+?)<\/loc>/gi){
			my $file = $1;
			if($file =~ /^https?:\/\//i){
				my $ho = &host($url);
				if($file =~ /$ho/i){
					push @found, $file;
				}
			}
			else{
				$file = $url . $file;
				push @found, $file;
			}
		}
		return @found;
	}
	
	
	
	sub GetForms(){
		my @f = ();
		foreach my $key (keys %forms){	
			push(@f, $key.'|#|'.$forms{$key});
		}
		return @f;
	}
	
	
	
	sub loadPlugins(){
		@plugins = ();
		opendir(my $dh, "./Plugins/Crawler/") || die "$!\n";
		my @plug = grep {/\.pm$/} readdir($dh);
		closedir $dh;
		my $x=0;
		foreach my $d (@plug){
			$d =~ s/\.pm//g;
			push(@plugins, Uniscan::Factory->create($d, "Crawler"));
			
			$x++;
		}
		
	
	}
	
	sub corta(){
		my $str = shift;
		if($str =~/\?/){
			$str = substr($str, 0, index($str, '?'));
		}
		if($str =~/\|#\|/){
			$str = substr($str, 0, index($str, '|#|'));
		}
		return $str;
	}
	sub host(){
		my $h = shift;
		my $url1 = URI->new( $h || return -1 );
		return $url1->host();
	}

	sub diretorio_atual(){
		my $url = shift;
		
		$url =~s/https?:\/\///;
		my $dir = substr($url, index($url, '/'), length($url));
		$dir = substr($dir, 0, rindex($dir, '/')+1);
		$dir = '/' if($dir !~/^\//);
		return $dir;
		
	}
	
sub parser(){
	my $content = shift;	
	my @ERs = (	'href\s*=\s*"(.+?)"',
			'href\s*=\s*\'(.+?)\'',
			"location.href='(.+?)'",
			"window\.open\('(.+?)'(,'')*\)",
			'src\s*=\s*["\'](.+?)["\']',
			'location.href\s*=\s*"(.+?)"', 
			'<meta.+content=\"\d+;\s*URL=(.+?)\".*\/?>',
			);
	my @result = ();
	
	foreach my $er (@ERs){
		while($content =~ m/$er/gi){
			push(@result, $1);
		}
	} 

	return @result;
}

sub classifica_urls(){
	my ($protocolo, $dominio, $diretorio, @uurls) = @_;
	my @ret = ();
	$diretorio =~ s/\/\//\//g;
	$protocolo = 'http://' if($protocolo =~/^http:\// && $protocolo !~/http:\/\//);
	$protocolo = 'https://' if($protocolo =~/^https:\// && $protocolo !~/https:\/\//);
	
	foreach my $url (@uurls){
		next if($url =~/^htp:\//);
		next if($url =~/file:\/\//gi);
		next if($url =~/ \+ /gi);
		next if($url =~/connect\.facebook\.net/i);
		next if($url =~/ajax\.googleapis\.com/i);
		next if($url =~/www\.facebook\.com/i);
		next if($url =~/^ [A-Za-z]+=/i);
		next if($url =~/mms:\/\//gi);
		
		
		
		$url =~s/^ // if($url =~/^ https?:/);
		
		if($url =~/^http:\// && $url !~/http:\/\//){
			$url =~ s/^http:\//http:\/\//;
		}

		if($url =~/^https:\// && $url !~/https:\/\//){
			$url =~ s/^https:\//https:\/\//;
		}

		$url = &trata_url($url);
		next if($url =~ m/javascript:|mailto:/gi);
		# retira os n ../ e volta n diretorios
		my $temp_dir = $diretorio;
		while($url =~/^\.\.\//){
			$url = substr($url, 3, length($url));
			$temp_dir =~s/\/$//;
			$temp_dir = substr($temp_dir, 0, rindex($temp_dir, '/')+1);
		}
		
		while($url =~/\.\.\//){
			$url = &volta_dir($url);
		}
		$url =~s/^\.\///g;
		
		#limpezas:
		my $flag = 0;
		$flag = 1 if($url =~/\|#\|/);
		#print "$url\n" if($flag);
		my $tmp = substr($url, index($url, '|#|'), length($url)) if($url =~/\|#\|/);
		#print "tmp $tmp\n" if($flag);
		$url = substr($url, 0, index($url, '|#|')) if($url =~/\|#\|/);
		#print "$url\n" if($flag);
		$url =~s/'//g;
		$url =~s/"//g;
		if($url =~ /^\.\//){
			$url = substr($url, 2, length($url));
		}
		#se come\E7a com https?:\/\/ e contem o dominio entao adiciona ao retorno
		$url .= $tmp if($flag == 1);
		#print "$url\n" if($flag);
		
		push(@ret, $url) if($url =~ m/^https?:\/\/\Q$dominio\E/i && $url =~/^$urlsite/);
		
		#se come\E7a com /, adiciona https?:// + dominio + url ao retorno
		push(@ret, $protocolo . $dominio . $url) if($url =~/^\//);
		
		#se n\E3o come\E7a com https:// e n\E3o come\E7a com /: add ao ret : https:// $dominio $diretorio $url
		push(@ret, $protocolo . $dominio . $temp_dir . $url) if($url !~/^https?:\/\//i && $url !~ /^\//);
		
	}
	
	return @ret;
}

sub verifica_variacao(){
	my @uurls = @_;
	my @ret = ();
	
	foreach my $url (@uurls){
		$url = &trata_url($url);
		my $fil = $func->get_file($url);
			
		if($files{$fil} <= $conf{'variation'} && !$files{$url}){
			$files{$fil}++;
			$files{$url}=1;
			push(@ret, $url)if($url =~ /^$urlsite/i);
		}
	}
	return(@ret);
}

sub verifica_ignorados(){
	my @uurls = @_;
	my @ret = ();
	my $h = Uniscan::Http->new();
	foreach my $url (@uurls){
		$url = &trata_url($url);
		my $fil = $func->get_file($url);
		my $ext = &get_extension($fil);
		if($conf{'extensions'} !~/$ext/i){
			if (!$checado{$url}) {
				$checado{$url} = 1;
				my $temp = $url;
				$url = substr($url, 0, index($url, '|#|')) if($url =~/\|#\|/);
				my $res = $h->HEAD($url);
				$url = $temp;
				$requests++;
				if($res->code !~ m/401|403|404/g && $res->code && $url =~ /^$urlsite/i){
					push(@ret, $url);
				}
				else{
					#open(a, ">>error.txt");
					#print a __LINE__ . " code: " .$res->code . " $url \n";
					#close(a);
				}
			}
		}
		else{
			if(!$ignored{$url}){
				if (!$checado{$url}) {
					$checado{$url} = 1;
					my $res = $h->HEAD($url);
					$requests++;
					if($res->code !~ m/401|403|404/g && $res->code && $url =~ /^$urlsite/i){
						$ignored{$url} = 1;
					}
					else{
						#open(a, ">>error.txt");
						#print a __LINE__ . " code: " .$res->code . " $url \n";
						#close(a);
					}

				}
			}
		}
	}
	return(@ret);
	
}

sub checa_head(){
	my @uurls = @_;
	my @ret = ();
	my $h = Uniscan::Http->new();
	foreach my $url (@uurls){
		$url = &trata_url($url);
		if (!$checado2{$url}) {
			$checado2{$url} = 1;
			my $temp = $url;
			$url = substr($url, 0, index($url, '|#|')) if($url =~/\|#\|/);
			my $response = $h->HEAD($url);
			$url = $temp;
			$requests++;
			if($response->code !~ /401|403|404/ && $response->code){
				push(@ret, $url) if($url =~ /^$urlsite/i);
			}
			else{
#				open(a, ">>error.txt");
#				print a __LINE__ . " code: " .$response->code . " $url \n";
#				close(a);
			}
		}
	}
	return(@ret);
	
}

sub adiciona_diretorios(){
	my @uurls = @_;
	my @ret = ();
	my %controle;
	
	foreach my $url (@uurls){
		$url = &trata_url($url);
		$controle{$url}=1 if($url =~/^$urlsite/);
		while(length($url)>13){
			$url = substr($url, 0, rindex($url, '/'));
			$controle{$url."/"} = 1 if(length($url)>13 && $url =~ /^$urlsite/i);
		}
	}
	foreach my $key (keys %controle){
		push(@ret, $key) if($key =~/^$urlsite/i);
	}
	return(@ret);
}


#termina termina os threads se nao fizer requests por mais de 2 minuto (controlador de threads baseado nas requests)
sub baixa_threads(){
	while ($requests != $last_req) {
		$last_req = $requests;
		sleep($tempo);
	}
	$reqs += $conf{'max_reqs'};
	return 1;
}



sub checa_online(){
        my $h = Uniscan::Http->new();
        my $x=0;
        my $site = $func->pega_site($report_id);
		print "on: $site\n";
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
        $func->insert("UPDATE report SET waf = 1 WHERE report_id=". $report_id);
}


sub online(){
	while(checa_online() && $q->pending > 0){
		sleep(60);
	}
 	#exit();		
	while($q->pending > 0){
		$q->dequeue;
	}
	
}


sub trata_url(){
	my $url = shift;

	$url =~s/&quot;/%22/gi;
	$url =~s/&amp;/&/gi;
	$url =~s/&lt;/%3C/gi;
	$url =~s/&gt;/%3E/gi;
	$url =~s/&Aacute;/%C3%81/gi;
	$url =~s/&nbsp;/%20/gi;
	$url =~s/&Acirc;/%C3%82/gi;
	$url =~s/&Agrave;/%C3%80/gi;
	$url =~s/&Atilde;/%C3%83/gi;
	$url =~s/&aacute;/%C3%A1/gi;
	$url =~s/&acirc;/%C3%A2/gi;
	$url =~s/&agrave;/%C3%A0/gi;
	$url =~s/&atilde;/%C3%A3/gi;
	$url =~s/&Eacute;/%C3%89/gi;
	$url =~s/&Ecirc;/%C3%8A/gi;
	$url =~s/&Egrave;/%C3%88/gi;
	$url =~s/&eacute;/%C3%A9/gi;
	$url =~s/&ecirc;/%C3%AA/gi;
	$url =~s/&egrave;/%C3%A8/gi;
	$url =~s/&Iacute;/%C3%8D/gi;
	$url =~s/&Icirc;/%C3%8E/gi;
	$url =~s/&Igrave;/%C3%8C/gi;
	$url =~s/&iacute;/%C3%AD/gi;
	$url =~s/&icirc;/%C3%AE/gi;
	$url =~s/&igrave;/%C3%AC/gi;
	$url =~s/&Oacute;/%C3%93/gi;
	$url =~s/&Ocirc;/%C3%94/gi;
	$url =~s/&Ograve;/%C3%92/gi;
	$url =~s/&Otilde;/%C3%95/gi;
	$url =~s/&oacute;/%C3%B3/gi;
	$url =~s/&ocirc;/%C3%B4/gi;
	$url =~s/&ograve;/%C3%B2/gi;
	$url =~s/&otilde;/%C3%B5/gi;
	$url =~s/&Uacute;/%C3%9A/gi;
	$url =~s/&Ucirc;/%C3%9B/gi;
	$url =~s/&Ugrave;/%C3%99/gi;
	$url =~s/&uacute;/%C3%BA/gi;
	$url =~s/&ucirc;/%C3%BB/gi;
	$url =~s/&ugrave;/%C3%B9/gi;
	$url =~s/ /%20/gi;
	$url =~s/\+/%2B/gi;
	$url =~s/&Ccedil;/%C3%87/gi;
	$url =~s/&ccedil;/%C3%A7/gi;
	return $url;
}


sub volta_dir(){
	my $url = shift;
	my $pos = index($url, '../');
	#print "pos: $pos\n";
	my $str1 = substr($url, 0, $pos-1);
	$str1 = substr($url, 0, rindex($str1, '/'));
	my $str2 = substr($url, $pos+2, length($url));
	#print "1 $str1\n2 $str2\n";
	return $str1.$str2;
}
