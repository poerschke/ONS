#!/usr/bin/perl

use DBI;
use URI;
use HTTP::Cookies;
use HTTP::Headers;
use HTTP::Request;
use LWP::UserAgent;


%uu 		= ();
%files 		= ();
$urlsite 	= $ARGV[0];

my $dbh = DBI->connect('DBI:mysql:;host=localhost','root','', {'PrintError'=>1}) or die("");
$query = "UPDATE `uniscan`.`fila` SET checked = 1 WHERE uniscan.fila.site = '$urlsite'";
$dbh->do($query);


@urls = verifica_ignorados(get_urls($urlsite));

foreach $url (@urls){
	if($url !~/^http/){
		push(@urls2, $urlsite . $url);	
	}
	elsif($url =~/^$urlsite/){
		push(@urls2, $url);		
	}
}


foreach $url (@urls2){
	
	$uu{$url} = 1;
	@urls = verifica_ignorados(get_urls($url));
	foreach $url3 (@urls){
		if($url3 !~/^http/){
			push(@urls3, $urlsite . $url3);	
		}
		elsif($url3 =~/^$urlsite/){
			push(@urls3, $url3);		
		}
	
	foreach $url4 (@urls3){
		$uu{$url4} = 1;
	}
}

}

foreach $key (keys %uu){
	#print "$key\n";
	next if($key =~/\.uol|'|"|javascript/);
	$query = "INSERT INTO `paginas`.`pagina` SET url = '$key'";
	$dbh->do($query);
}

















############ funcs ###########

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


sub get_urls(){
	my $url = shift; 
	return if($url !~/^$urlsite/i);
	my $resultado = "";
	my $response;
	if($url =~ /\|#\|/g){
		my ($action, $data) = split('\|#\|', $url);
		$response = POST1($action, $data);
		$requests++;
		}
		else{
			$response = GET1($url);
			$requests++;
		}
		return if(!$response);
		return if(!$response->is_success);		
		$url = $response->request->uri;
		return if($url !~/^$urlsite/i);
		$resultado = $response->decoded_content;
		my $dominio = &host($url);
		my $diretorio = &diretorio_atual($url);
		my $protocolo = "";
		$protocolo = "http://" if($url =~/^http:\/\//i);
		$protocolo = "https://" if($url =~/^https:\/\//i);
		
		my @uurls = &parser($resultado);
		return(@uurls);
}
	




sub verifica_variacao(){
	my @uurls = @_;
	my @ret = ();
	
	foreach my $url (@uurls){
		$url = &trata_url($url);
		my $fil = get_file($url);
			
		if($files{$fil} <= 2 && !$files{$url}){
			$files{$fil}++;
			$files{$url}=1;
			push(@ret, $url)if($url =~ /^$urlsite/i);
		}
	}
	return(@ret);
}








sub GET1(){
    	my $url1 = shift;
	#print "$url1\n";
	return 0 if(!$url1);
	return 0 if($url1 !~/^https?:\/\//);
	my $headers = HTTP::Headers->new();
	$headers->header(
			'Accept-Language' 	=> "en-US,en",
			 'Accept-Encoding' 	=> "deflate",
			 'Connection' 		=> "Keep-alive",
			 'Keep-Alive'		=> 30);
	$headers->referer($referer);
	my $req = HTTP::Request->new('GET',$url1, $headers);
    	my $ua	= LWP::UserAgent->new(agent => 'Uniscan Crawler', ssl_opts => { verify_hostname => 0} );
    	$ua->timeout(5);
    	$ua->max_size(1024*1024);
	$ua->protocols_allowed( [ 'http', 'https'] );
    	my $response=$ua->request($req);
	return $response;	
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


sub verifica_ignorados(){
	my @uurls = @_;
	my @ret = ();
	my $exten = ".wmv.exe.pdf.xls.csv.mdb.rpm.deb.doc.odt.pptx.docx.db.xps.cdr.jpg.jpeg.png.gif.bmp.css.tgz.gz.bz2.mp4.zip.rar.tar.asf.avi.bin.dll.js.fla.mp3.mpg.mov.ogg.ppt.rtf.scr.wav.msi.swf.sql.xml.flv.ogv.ico.asp.aspx";
	foreach my $url (@uurls){
		$url = &trata_url($url);
		my $fil = get_file($url);
		my $ext = &get_extension($fil);
		if($exten !~/$ext/i){
			if (!$checado{$url}) {
				$checado{$url} = 1;
				my $temp = $url;
				$url = $temp;
				push(@ret, $url);
			}
		}
		else{
		}
	}
	return(@ret);
	
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


sub get_file(){
	my $url1 = shift;
	substr($url1,0,7) = "" if($url1 =~/http:\/\//);
	substr($url1,0,8) = "" if($url1 =~/https:\/\//);
	substr($url1, index($url1, '?'), length($url1)) = "" if($url1 =~/\?/);
	substr($url1, index($url1, '\#'), length($url1)) = "" if($url1 =~/\|#\|/);
	if($url1 =~ /\//){
		$url1 = substr($url1, index($url1, '/'), length($url1)) if(length($url1) != index($url1, '/'));
		if($url1 =~ /\?/){
			$url1 = substr($url1, 0, index($url1, '?'));
		}
		return $url1;
	}
	elsif($url1=~/\?/){
		$url1 = substr($url1, 0, index($url1, '?'));
		return $url1;
	}
	else {
		return $url1;
	}
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

