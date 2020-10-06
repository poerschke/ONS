#!/usr/bin/perl
use strict;
use warnings;

chdir '/opt/ONS/';
umask 0;

use lib "Uniscan";
use Uniscan::Functions;
my $func = Uniscan::Functions->new();

my $ret = `ps --no-header aux | grep ONS |grep -v grep |grep -v killa`;

my $linha = "iniciando em: " . `date`;
my $a;
open($a, ">>/var/log/killons.log");
print $a $linha;
close($a);

while($ret =~m/(.+?)\s+(.+?)\s+(.+?)\s+(.+?)\s+(.+?)\s+(.+?)\s+(.+?)\s+(.+?)\s+(.+?)\s+(.+?)\s+(.+?)\n/g){
	my $pid = $2;
	my $proc = $11;
	my $inicio = $9;
	if($inicio =~/[A-Za-z]/){
	        my $hora = `date "+%H"`;
        	chomp $hora;
		my $id = 0; 
		(undef, undef, $id) = split(' ', $proc) if($proc =~/perl/);
		if($id != 0){
			&killpid($pid) if($hora > 3 && $func->check_waf($id) == 1);
		}
		&killpid($pid) if($hora > 0 && $proc =~/^python/);
		if($proc =~/^python/){
			if(&existe($pid) == 1){
				&killpid($pid);
				&deletapid($pid);
				}
			else{
				&addpid($pid);
			}
		}
	}
	else{
		my ($inicio, undef) = split(':', $9);
		my $hora = `date "+%H"`;
		chomp $hora;
		$hora += 23 if($hora < $inicio);
		my $id = 0;
		(undef, undef, $id) = split(' ', $proc) if($proc =~/perl/);
#	print "id: $id\n$ret\n";
		if($id != 0){ 
			if(($hora - $inicio) > 3 && $func->check_waf($id) == 1 ){
				&killpid($pid);
			}
		}
		if(($hora - $inicio) > 0 && $proc =~/^python/){
                        &killpid($pid);
                }
		if($proc =~/^python/){
		if(&existe($pid) == 1){
           &killpid($pid);
           &deletapid($pid);
        }
   		else{
           &addpid($pid);
        }
		}

	}

}

exit(0);

sub killpid(){
	my $pid = shift;
	my $cmd = `ps aux |grep $pid |grep -v grep`;
	$cmd .= " Morto em: ". `date`;
	$cmd =~s/\n//g;
	my $a;
	open($a, ">>/var/log/killons.log");
	print $a "$cmd\n";
	close($a);
	system("kill -9 $pid");
	print "$cmd\n";
}


sub addpid(){
	my $pid = shift;
	open(my $arq, ">>/opt/ONS/killa.pids");
	print $arq "$pid\n";
	close($arq);
}


sub deletapid(){
	my $pid = shift;
	my @pids = ();
	open(my $arq, "</opt/ONS/killa.pids");
	while(<$arq>){
		my $pidd = $_;
		chomp $pidd;
		push(@pids, $pidd) if($pid != $pidd);
	}
	close($arq);

	open($arq, ">/opt/ONS/killa.pids");
	foreach $pid (@pids){
		print $arq "$pid\n";
	}
	close($arq);
}



sub existe(){
																						
	my $pid = shift;
	open(my $arq, "</opt/ONS/killa.pids");
	my @pids = <$arq>;
	close($arq);
													
	foreach my $pidd (@pids){
		chomp $pidd;
		return 1 if($pid == $pidd);
	}
	return 0;
	}
