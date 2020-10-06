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
	my $query_ret = _execute_query($dbh, 'SELECT uniscan.fila.site,uniscan.usuarios.nome,uniscan.usuarios.email FROM uniscan.fila,uniscan.usuarios WHERE uniscan.fila.user_id=uniscan.usuarios.user_id AND uniscan.fila.validade < NOW()');

	while (my $contact = $query_ret->fetchrow_hashref()) {
        system('/bin/echo -e "Prezado(a) senhor(a) ' . $contact->{nome} . ',\n\n\tInformamos que a validade do monitoramento para o site \"' . $contact->{site} . '\" expirou e o mesmo será removido do sistema.\n\n\nON-Security Segurança da informação\ne-mail: contato@on-security.com" | /usr/bin/mail -s "[ON-S Info] Site removido do monitoramento" ' . $contact->{email});
	}

	$query_ret = _execute_query($dbh, 'SELECT uniscan.fila.fila_id,uniscan.fila.site,uniscan.usuarios.nome,uniscan.usuarios.email FROM uniscan.fila,uniscan.usuarios WHERE uniscan.fila.user_id=uniscan.usuarios.user_id AND uniscan.fila.validade BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 7 DAY) AND uniscan.fila.notificado_7=0');

	while (my $contact = $query_ret->fetchrow_hashref()) {
        system('/bin/echo -e "Prezado(a) senhor(a) ' . $contact->{nome} . ',\n\n\tInformamos que a validade do monitoramento para o site \"' . $contact->{site} . '\" irá terminar em 7 dias.\n\n\nON-Security Segurança da informação\ne-mail: contato@on-security.com" | /usr/bin/mail -s "[ON-S Info] Validade do monitoramento" -a "From:ON-Security <contato@on-security.com>" ' . $contact->{email});
		_execute_query($dbh, 'UPDATE uniscan.fila SET notificado_7=1 WHERE uniscan.fila.fila_id=' . $contact->{fila_id});
	}
}

sub main () {
    my %glob_cfg=_read_conf();
    my $dbh = _connect(%glob_cfg);

	sendmail($dbh);
	_execute_query($dbh, "DELETE FROM $glob_cfg{database}.fila WHERE validade < NOW()");

    $dbh->disconnect;
} &main

