#!/usr/bin/perl

use threads;
use threads::shared;
use Thread::Queue;
use Thread::Semaphore;

use POSIX qw(setsid);
use strict;
use warnings;
use File::Pid;
use IPC::Open3;

use lib "./Uniscan";
use Uniscan::Functions;
use Uniscan::Queue;
use Uniscan::Configure;

my $CHILD_PID;
my $UNISCAN_DIR = "/opt/ONS";
my $nome        = "uniscan";
my $pidlocation = "/var/run/$nome.pid";
my $MAX_INSTANCES;
my $semaphore = Thread::Semaphore->new();
our @lock : shared = ();

$SIG{"INT"} = "IGNORE";
$SIG{"HUP"} = "IGNORE";
$SIG{"TERM"} = "IGNORE";
$SIG{"CHLD"} = "IGNORE";
#auto flush
$| = 1;

&setMaxInstances();

open STDIN,  '<', '/dev/null' or die $!;
open STDOUT, '>>', '/var/log/ons.txt' or die $!;
open STDERR, '>>', '/var/log/ons.txt' or die $!;  
  
setsid;
chdir "$UNISCAN_DIR/";
umask 0;

our $pid = fork;
exit(0) if ($pid != 0);
die "Fork problem: $!\n" unless defined($pid);

&writePid();

my $queue = Uniscan::Queue->new();
my %report;
my @instaces_pid;
my $active_instances;

# inicia $MAX_INSTANCES do scanner

my $ins = 0;
my @thr = ();
$MAX_INSTANCES = 2;
while($ins < $MAX_INSTANCES){
    push(@thr, threads->new(\&scan, $ins));
    sleep(1);
    $ins++;
    print "Thread: $ins\n";
}

while(1){
    sleep(30);
}






sub setMaxInstances(){ 
    my($wtr, $rdr, $err, @ret_command);
  
    open3($wtr, $rdr, $err, "/bin/grep processor /proc/cpuinfo | /usr/bin/tail -1");

    while (<$rdr>) {
        chomp;
        push(@ret_command, $_);
    }

    $ret_command[@ret_command - 1] =~ s/.*: ?//;

    $MAX_INSTANCES = ($ret_command[@ret_command - 1] + 1) - 2;
    $MAX_INSTANCES = 1 if ($MAX_INSTANCES < 1);
}


sub scan(){
    my $ins = shift;
    my $func = Uniscan::Functions->new();
    my $c = Uniscan::Configure->new(conffile => "uniscan.conf");
    my %conf = ( );


    while(1){
        $lock[$ins] = 0;
        my $waitTime = 15;
	$semaphore->down();
        my %report = $queue->getNext();
        my ($thread, $ip, $banner);
	$semaphore->up();

	if(defined($report{site})){
        	my $site = $func->pega_site($report{report_id});
        	%conf = $c->loadconf();
	
        	# para o thread do ack, thread vai rodar enquanto $lock=1 
        	$lock[$ins] = 1;
        	# cria o thread do ack
        	$thread = threads->new(\&ack, $waitTime, $ins, $report{report_id}) if(!$thread);
	
        	$func->insert("UPDATE report SET data_inicio=now() WHERE report_id = ".$report{report_id});
        	$ip = $func->GetServerIp($report{site});
        	$banner = "";
        	$banner = $func->GetServerInfo($report{site});
        	$banner =~s/'/\\'/g if(defined($banner));
        	$func->insert("UPDATE report SET ip='$ip', server_banner='$banner' WHERE report_id = ". $report{report_id});
		#next if($banner =~/iis/gi);
        	#$func->logAdd($conf{'queue_log'}, "Iniciando Bing.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/BingIP.pl $report{report_id}") if($func->checa_online($report{report_id}));

        	#$func->logAdd($conf{'queue_log'}, "Iniciando FingerPrint.pl em ". $report{site});
       		#system("perl $UNISCAN_DIR/FingerPrint.pl $report{report_id}")  if($func->checa_online($report{report_id}));
	
        	#$func->logAdd($conf{'queue_log'}, "Iniciando FingerPrint_server.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/FingerPrint_Server.pl $report{report_id}")  if($func->checa_online($report{report_id}));

		#$func->logAdd($conf{'queue_log'}, "Iniciando checkHeartbleed.pl em ". $report{site});
            	#system("perl $UNISCAN_DIR/checkHeartbleed.pl $report{report_id}")  if($func->checa_online($report{report_id}));

        	#$func->logAdd($conf{'queue_log'}, "Iniciando Files.pl em ". $report{site});
	        #system("perl $UNISCAN_DIR/Files.pl $report{report_id}")  if($func->checa_online($report{report_id}));
	
        	#$func->logAdd($conf{'queue_log'}, "Iniciando Directory.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/Directory.pl $report{report_id}")  if($func->checa_online($report{report_id}));
        	
		#$func->logAdd($conf{'queue_log'}, "Iniciando checkWordpress.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/checkWordpress.pl $report{report_id}")  if($func->checa_online($report{report_id}));

        	$func->logAdd($conf{'queue_log'}, "Iniciando Crawler.pl em ". $report{site});
        	system("perl $UNISCAN_DIR/Crawler.pl $report{report_id}")  if($func->checa_online($report{report_id}));
        	
        	#$func->logAdd($conf{'queue_log'}, "Iniciando checkBlindSQLI.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/checkBlindSQLI.pl $report{report_id}")  if($func->checa_online($report{report_id}));
        	
        	#$func->logAdd($conf{'queue_log'}, "Iniciando checkLFI.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/checkLFI.pl $report{report_id}")  if($func->checa_online($report{report_id}));
        	
        	#$func->logAdd($conf{'queue_log'}, "Iniciando checkPHPCGI.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/checkPHPCGI.pl $report{report_id}") if($func->checa_online($report{report_id}));
        	
        	#$func->logAdd($conf{'queue_log'}, "Iniciando checkRCE.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/checkRCE.pl $report{report_id}") if($func->checa_online($report{report_id}));
        	
        	#$func->logAdd($conf{'queue_log'}, "Iniciando checkRFI.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/checkRFI.pl $report{report_id}") if($func->checa_online($report{report_id}));
        	
        	#$func->logAdd($conf{'queue_log'}, "Iniciando checkSQLI.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/checkSQLI.pl $report{report_id}") if($func->checa_online($report{report_id}));

		#$func->logAdd($conf{'queue_log'}, "Iniciando checkSQLiFriendlyURL.pl em ". $report{site});
		#system("perl $UNISCAN_DIR/checkSQLiFriendlyURL.pl $report{report_id}") if($func->checa_online($report{report_id}));

        	#$func->logAdd($conf{'queue_log'}, "Iniciando checkXSS.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/checkXSS.pl $report{report_id}") if($func->checa_online($report{report_id}));
       
		#if(int($report{nivel}) == 4){ 
        	#	$func->logAdd($conf{'queue_log'}, "Iniciando stress.pl em ". $report{site});
        	#	system("perl $UNISCAN_DIR/stress.pl $report{report_id}") if($func->checa_online($report{report_id}));
		#}
        	#$func->logAdd($conf{'queue_log'}, "Iniciando FCKeditor.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/FCKeditor.pl $report{report_id}") if($func->checa_online($report{report_id}));

        	#$func->logAdd($conf{'queue_log'}, "Iniciando Timthumb.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/Timthumb.pl $report{report_id}") if($func->checa_online($report{report_id}));

        	#$func->logAdd($conf{'queue_log'}, "Iniciando webShell.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/webShell.pl $report{report_id}") if($func->checa_online($report{report_id}));

        	#$func->logAdd($conf{'queue_log'}, "Iniciando checkRCEarq.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/checkRCEarq.pl $report{report_id}") if($func->checa_online($report{report_id}));

        	#$func->logAdd($conf{'queue_log'}, "Iniciando checkRFIarq.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/checkRFIarq.pl $report{report_id}") if($func->checa_online($report{report_id}));

        	#$func->logAdd($conf{'queue_log'}, "Iniciando checkLFIarq.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/checkLFIarq.pl $report{report_id}") if($func->checa_online($report{report_id}));

        	#$func->logAdd($conf{'queue_log'}, "Iniciando checkBackup.pl em ". $report{site});
        	#system("perl $UNISCAN_DIR/checkBackup.pl $report{report_id}")  if($func->checa_online($report{report_id}));
        	$func->logAdd($conf{'queue_log'}, "o scan de ". $report{site} . " terminou");
		

    
        	$func->insert("UPDATE report SET data_fim=now() WHERE report_id = $report{report_id}");
    
        	Uniscan::Queue->endScan(%report);
        
        	$lock[$ins] = 0;
#		$thread->join();
#		$thread = undef;
	}
	else{ sleep(30); }
        #$thread->join;
        #$thread = undef;
    }
}



sub ack($$$){
    my ($waitTime, $ins, $report_id) = @_;
    while($lock[$ins]){
        sleep(30);
        Uniscan::Queue->sendAck($report_id) if($lock[$ins] == 1);
    }
    
}


sub writePid(){
  system("rm -f $pidlocation") if(-e "$pidlocation");

  my $pidfile = File::Pid->new( { file => $pidlocation, } );
  $pidfile->write or die "Erro ao criar o arquivo de PID, /dev/null: $!";
}
