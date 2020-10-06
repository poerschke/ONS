#!/usr/bin/env perl 

use strict;
use warnings;
use utf8;
use DBI;
use Moose;
use Uniscan::Functions;
chdir("/opt/ONS/");
use lib "./Uniscan";

sub _execute_query($$){
    my ($dbh, $query) = @_;
    my $query_handle;

    $query_handle = $dbh->prepare($query);
    $query_handle->execute();

    return $query_handle;
}

sub _connect(%){
    my %glob_cfg = @_;
    my $dbh;

	$dbh = DBI->connect('DBI:mysql:;mysql_connect_timeout=15;host=' . $glob_cfg{database_host}, $glob_cfg{database_user}, $glob_cfg{database_pass}, {'PrintError'=>0});

    exit(0) if (not $dbh);

    return $dbh;
}

sub _read_conf(){
    my $func = Uniscan::Functions->new();
    my $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");
    my %glob_conf = $cfg->loadconf();

    if ((not defined($glob_conf{database}))
        or (not defined($glob_conf{database_host}))
        or (not defined($glob_conf{database_user}))
        or (not defined($glob_conf{database_pass}))){
            exit(0);
    }

    return %glob_conf;
}

sub sendmail($) {
    my $dbh = shift;
	my %h = ();

	my 	$query_ret = _execute_query($dbh, "select  uniscan.usuarios.nome, uniscan.slots.user_id, uniscan.usuarios.email, uniscan.slots.slot_id FROM uniscan.slots, uniscan.usuarios WHERE uniscan.slots.validade < ". (int( time()) + 604800) ." and uniscan.slots.user_id = uniscan.usuarios.user_id AND uniscan.slots.notificado=0");

	while (my $contact = $query_ret->fetchrow_hashref()) {
		print "enviando email para:" . $contact->{email} . "\n";
		if(!$h{$contact->{email}}){
			system('/bin/echo -e "Prezado(a) senhor(a) '. $contact->{nome} . ',\n\n\tInformamos que você tem créditos que ainda não foram usados e que irão expirar em até 7 dias.\n\n\nON-Security Segurança da informação\ne-mail: contato@on-security.com" | /usr/bin/mail -s "[ON-S Info] Validade do monitoramento" -a "From:ON-Security <contato@on-security.com>" ' . $contact->{email});
			$h{$contact->{email}} = 1;
		}
		_execute_query($dbh, 'UPDATE uniscan.slots SET notificado=1 WHERE uniscan.slots.slot_id=' . $contact->{slot_id});
	}
}

sub main () {
    my %glob_cfg=_read_conf();
    my $dbh = _connect(%glob_cfg);

	sendmail($dbh);
	_execute_query($dbh, "DELETE FROM $glob_cfg{database}.slots WHERE validade < ". int(time()));

    $dbh->disconnect;
} &main

