package Uniscan::Http;

use Moose;
use HTTP::Headers;
use HTTP::Request;
use HTTP::Response;
use LWP::UserAgent;
use Uniscan::Configure;
use HTTP::Cookies;
use LWP::Protocol::https;




our $agente = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.77 Safari/535.7";
our %conf = ( );
our $c = Uniscan::Configure->new(conffile => "uniscan.conf");
%conf = $c->loadconf();
our $cookie_jar = HTTP::Cookies->new(file => "/opt/ONS/cookies.lwp", autosave => 1);

sub HEAD(){
	my ($self, $url1) = @_;
	my $headers = HTTP::Headers->new();
	$headers->remove_header('Connection');
	$headers->header('Accept' 		=> "text/html, application/xhtml+xml, application/xml",
			'Accept-Language' 	=> "en-US,en",
			 'Accept-Encoding' 	=> "deflate",
			 'Connection' 		=> "Keep-alive",
			 'Keep-Alive'		=> 30);
	my $req=HTTP::Request->new('HEAD', $url1, $headers);
	#my $cookie_jar = HTTP::Cookies->new(file => "/opt/ONS/cookies.lwp", autosave => 1);
	my $ua=LWP::UserAgent->new(agent => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.77 Safari/535.7", ssl_opts => { verify_hostname => 0} );
	$ua->timeout($conf{'timeout'});
	$ua->max_size($conf{'max_size'});
	$ua->protocols_allowed( [ 'http', 'https'] );
	$ua->cookie_jar($cookie_jar);
	
	my $response=$ua->request($req);
	#$cookie_jar->extract_cookies($response) if($response->as_string =~/Set\-Cookie:/);
        #$cookie_jar->save() if($response->as_string =~/Set\-Cookie:/);
	return $response;

}


sub GET(){
        my ($self, $url1 )= @_;
	return 0 if(!$url1);
	return 0 if($url1 !~/^https?:\/\//);
	my $headers = HTTP::Headers->new();
	$headers->remove_header('Connection');
	$headers->header('Accept' 		=> "text/html, application/xhtml+xml, application/xml",
			'Accept-Language' 	=> "en-US,en",
			 'Accept-Encoding' 	=> "deflate",
			 'Connection' 		=> "Keep-alive",
			 'Keep-Alive'		=> 30);

	my $req = HTTP::Request->new('GET', $url1, $headers);
	my $cookie_jar = HTTP::Cookies->new(file => "/opt/ONS/cookies.lwp",autosave => 1);
        my $ua	= LWP::UserAgent->new(agent => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.77 Safari/535.7", ssl_opts => { verify_hostname => 0} );

	$ua->cookie_jar($cookie_jar);
        $ua->timeout($conf{'timeout'});
        $ua->max_size($conf{'max_size'});
	$ua->protocols_allowed( [ 'http', 'https'] );
        my $response=$ua->request($req);
        #$cookie_jar->extract_cookies($response) if($response->as_string =~/Set\-Cookie:/);
        #$cookie_jar->save() if($response->as_string =~/Set\-Cookie:/);
	my $code = $response->code;
	if($response->is_success){
	        return $response->decoded_content;
	}
	elsif($code == 404){
		return "error";
	}
	else{
		return $code;
	}

}



sub POST(){
        my ($self, $url1, $data) = @_;
	return if(!$url1);
	return 0 if($url1 !~/^https?:\/\//);
	
        $data =~ s/\r//g;


	my $headers = HTTP::Headers->new();
	$headers->remove_header('Connection');
	$headers->header('Accept' 		=> "text/html, application/xhtml+xml, application/xml",
			'Accept-Language' 	=> "en-US,en",
			 'Accept-Encoding' 	=> "deflate",
			 'Connection' 		=> "Keep-alive",
			 'Keep-Alive'		=> 30);
        my $request= HTTP::Request->new("POST", $url1, $headers);
        $request->content($data);
        $request->content_type('application/x-www-form-urlencoded');
	#my $cookie_jar = HTTP::Cookies->new(file => "/opt/ONS/cookies.lwp",autosave => 1);
        my $ua=LWP::UserAgent->new(agent => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.77 Safari/535.7", ssl_opts => { verify_hostname => 0} );
	
	$ua->cookie_jar($cookie_jar);

        $ua->timeout($conf{'timeout'});
        $ua->max_size($conf{'max_size'});
	$ua->protocols_allowed( [ 'http', 'https'] );
        my $response=$ua->request($request);
       	#$cookie_jar->extract_cookies($response) if($response->as_string =~/Set\-Cookie:/);
        #$cookie_jar->save() if($response->as_string =~/Set\-Cookie:/);
        return $response->decoded_content;
        }



sub POST1(){
        my ($self, $url1, $data) = @_;
	return if(!$url1);
	return 0 if($url1 !~/^https?:\/\//);
	
        $data =~ s/\r//g;
	my $headers = HTTP::Headers->new();
	$headers->remove_header('Connection');
	$headers->header('Accept' 		=> "text/html, application/xhtml+xml, application/xml",
			'Accept-Language' 	=> "en-US,en",
			 'Accept-Encoding' 	=> "deflate",
			 'Connection' 		=> "Keep-alive",
			 'Keep-Alive'		=> 30);
        my $request= HTTP::Request->new("POST", $url1, $headers);
        $request->content($data);
        $request->content_type('application/x-www-form-urlencoded');
	#my $cookie_jar = HTTP::Cookies->new(file => "/opt/ONS/cookies.lwp",autosave => 1);
        my $ua=LWP::UserAgent->new(agent => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.77 Safari/535.7", ssl_opts => { verify_hostname => 0} );
	
	$ua->cookie_jar($cookie_jar);

        $ua->timeout($conf{'timeout'});
        $ua->max_size($conf{'max_size'});
	$ua->protocols_allowed( [ 'http', 'https'] );
        my $response=$ua->request($request);
        #$cookie_jar->extract_cookies($response)  if($response->as_string =~/Set\-Cookie:/);
        #$cookie_jar->save()  if($response->as_string =~/Set\-Cookie:/);
        return $response;
        }


sub PUT(){
	my($self, $url, $data) = @_;
	return if(!$url);
	return 0 if($url !~/^https?:\/\//);
	
	my $headers = HTTP::Headers->new();
	$headers->remove_header('Connection');
	$headers->header('Accept' 		=> "text/html, application/xhtml+xml, application/xml",
			'Accept-Language' 	=> "en-US,en",
			 'Accept-Encoding' 	=> "deflate",
			 'Connection' 		=> "Keep-alive",
			 'Keep-Alive'		=> 30);
        my $req=HTTP::Request->new(PUT=>$url, $headers, $data);
	#my $cookie_jar = HTTP::Cookies->new(file => "/opt/ONS/cookies.lwp",autosave => 1);
        my $ua=LWP::UserAgent->new(agent => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.77 Safari/535.7");
        $ua->timeout($conf{'timeout'});
        $ua->max_size($conf{'max_size'});
	$ua->protocols_allowed( [ 'http', 'https'] );
	$ua->cookie_jar($cookie_jar);
        my $response=$ua->request($req);
        #$cookie_jar->extract_cookies($response) if($response->as_string =~/Set\-Cookie:/);
        #$cookie_jar->save() if($response->as_string =~/Set\-Cookie:/);
        return $response->content;
}




sub GET1(){
    my ($self, $url1 )= @_;
	
	return 0 if(!$url1);
	return 0 if($url1 !~/^https?:\/\//);
	my $headers = HTTP::Headers->new();
	#$headers->remove_header('Connection');
	$headers->header('Accept' 		=> "text/html, application/xhtml+xml, application/xml",
			'Accept-Language' 	=> "en-US,en",
			 'Accept-Encoding' 	=> "deflate",
			 'Connection' 		=> "Keep-alive",
			 'Keep-Alive'		=> 30);
	
	my $req = HTTP::Request->new('GET',$url1, $headers);
	#my $cookie_jar = HTTP::Cookies->new(file => "/opt/ONS/cookies.lwp",autosave => 1);
    	my $ua	= LWP::UserAgent->new(agent => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.77 Safari/535.7", ssl_opts => { verify_hostname => 0} );
	$ua->cookie_jar($cookie_jar);
    	$ua->timeout($conf{'timeout'});
    	$ua->max_size($conf{'max_size'});
	$ua->protocols_allowed( [ 'http', 'https'] );
    	my $response=$ua->request($req);
        #$cookie_jar->extract_cookies($response) if($response->as_string =~/Set\-Cookie:/);
	#$cookie_jar->save() if($response->as_string =~/Set\-Cookie:/);
	return $response;	
}
 
1;
