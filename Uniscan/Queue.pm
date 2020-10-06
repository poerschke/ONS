package Uniscan::Queue;

use Uniscan::Functions;
use Uniscan::Configure;
use Moose;
use DBI;
use strict;
use POSIX qw(strftime);
use Time::Local;
use IPC::Open3;

my $func = Uniscan::Functions->new();
my $cfg = Uniscan::Configure->new(conffile => "uniscan.conf");

sub _execute_query($$){
    my ($dbh, $query) = @_;
    my $query_handle;

    $query_handle = $dbh->prepare($query);
    $query_handle->execute();

    return $query_handle;
}

sub _read_conf(){
    my %glob_conf = $cfg->loadconf();

    if ((not defined($glob_conf{database}))
        or (not defined($glob_conf{database_host}))
        or (not defined($glob_conf{database_user}))
        or (not defined($glob_conf{database_pass}))
        or (not defined($glob_conf{queue_log}))) {
            $func->logAdd($glob_conf{queue_log}, "Erro no arquivo de configuracao. Encerrando execucao.");
            exit(1);
    }

    return %glob_conf;
}

sub _check_database($$){
    my ($dbh,$database) = @_;
    my ($rows);

    $rows = _execute_query($dbh, "SHOW DATABASES");

    while (my $line = $rows->fetchrow_array()) {
        if ($line =~ /^$database$/) {
            $rows->finish();
            return 0;
        }
    }

    $rows->finish();
    return 1;
}

sub timediff($) {
    my $sql_time = shift;
    my @sql_time_aux;
    my @now = split(" ", strftime "%S %M %H %e %m %Y", localtime);
    my $diff;

    $sql_time =~ s/-|:/ /g;
    @sql_time_aux = split(" ",$sql_time);

    $diff = timelocal($now[0], $now[1], $now[2], $now[3], $now[4] - 1, $now[5]) 
            - timelocal($sql_time_aux[5], $sql_time_aux[4], $sql_time_aux[3], $sql_time_aux[2], $sql_time_aux[1] - 1, $sql_time_aux[0]);
    return $diff;;
}

sub _check_queue($$){
    my ($dbh,$database) = @_;
    my $query_ret;

    $query_ret = _execute_query($dbh, "SELECT site, ack, fila_id, start_scan, interval_length, scan_lock, checked, current_report, nivel FROM $database.fila WHERE enabled=1 and validade > NOW()");

    while (my $line = $query_ret->fetchrow_hashref()) {
        if (($line->{scan_lock} == 0) && ($line->{checked} == 1) && (timediff($line->{start_scan}) > $line->{interval_length})) {
            _execute_query($dbh, "UPDATE $database.fila set checked=0 WHERE fila_id='" . $line->{fila_id} . "' and site='" . $line->{site} . "'");
        } elsif (($line->{scan_lock} == 1) && (timediff($line->{ack}) > 3600)) {
            _execute_query($dbh, "UPDATE $database.fila set checked=0, scan_lock=0 WHERE fila_id='" . $line->{fila_id} . "' and site='" . $line->{site} . "'");
            _execute_query($dbh, "DELETE FROM $database.report WHERE report_id='" . $line->{current_report} . "'");
        }
    }
}

sub _check_reports($$%){
    my ($dbh, $database, %next_client) = @_;
    my $query_ret = _execute_query($dbh, "SELECT reports FROM $database.fila WHERE fila_id='" . $next_client{fila_id} . "' and site='" . $next_client{site} . "'");
    my $client = $query_ret->fetchrow_hashref();
    $query_ret = _execute_query($dbh, "SELECT (SELECT COUNT(*) FROM $database.report WHERE site='" . $next_client{site} . "') count");
    my $reports = $query_ret->fetchrow_hashref();

    if ($client->{reports} <= $reports->{count}) {
        $query_ret = _execute_query($dbh, "SELECT report_id, data_fim FROM $database.report WHERE site='" . $next_client{site} . "' ORDER BY data_fim ASC");

        while (my $line = $query_ret->fetchrow_hashref()) {
            _execute_query($dbh, "DELETE FROM $database.report WHERE report_id='" . $line->{report_id} . "'");
            $reports->{count} -= 1;
            last if ($client->{reports} > $reports->{count});
        }
    }
}

sub _get_hostname(){
    my $ret_command;
    $ret_command = `hostname`;
    chomp $ret_command;
    return $ret_command;
}

sub _getNext($$){
    my ($dbh,$database) = @_;
    my $query_ret;
    my ($max, $diff, %next_client);
    $max=0;

    $query_ret = _execute_query($dbh, "SELECT site_id, user_id, end_scan, site, fila_id, interval_length, scan_lock, nivel FROM $database.fila WHERE enabled=1 and checked=0 and scan_lock=0");
    while (my $line = $query_ret->fetchrow_hashref()) {
        $diff = (timediff($line->{end_scan}) - $line->{interval_length});
        if (($diff > $max) && ($line->{scan_lock} == 0)) {
            $max = $diff;
            $next_client{fila_id} = $line->{fila_id};
            $next_client{user_id} = $line->{user_id};
            $next_client{site_id} = $line->{site_id};
            $next_client{site} = $line->{site};
	    $next_client{nivel} = $line->{nivel};
        }
    }

    $query_ret->finish();

    return %next_client;
}

sub _genNewReport($$%){
    my ($dbh,$database,%next_client) = @_;
    my $report_id = $func->gera_report();
    my $hostname = _get_hostname();

    _execute_query($dbh, "UPDATE $database.fila set nivel = ". $next_client{nivel} .", scan_lock=1, ack=NOW(), start_scan=NOW(), scaner_hostname='" . $hostname . "', current_report='" . $report_id . "' WHERE fila_id='" . $next_client{fila_id} . "' and site='" . $next_client{site} . "'");
    _execute_query($dbh, "UPDATE $database.report set site='" . $next_client{site} . "' WHERE report_id='" . $report_id . "'");
    _execute_query($dbh, "UPDATE $database.historico set site='" . $next_client{site} . "' WHERE report_id='" . $report_id . "'");

    return $report_id;
}

sub getNext(){
    my $self = shift;
    my %glob_cfg=_read_conf();
    my $dbh = _connect(%glob_cfg);
    my (%next_client, %client_conf, %ret, $hash_ref);
    my $report_id;

    _check_queue($dbh,$glob_cfg{database});

    %next_client = _getNext($dbh, $glob_cfg{database});

    if (defined($next_client{fila_id})) {
        _check_reports($dbh, $glob_cfg{database}, %next_client);
        $report_id =_genNewReport($dbh, $glob_cfg{database},%next_client);
        _execute_query($dbh, "UPDATE " . $glob_cfg{database} . ".report SET nivel = ". $next_client{nivel}.", user_id=" . $next_client{user_id} . ", site_id=" . $next_client{site_id} . " WHERE report_id=$report_id") if ($report_id);
    }

    $dbh->disconnect;

    $ret{report_id} = $report_id if ($report_id);
    $ret{site} = $next_client{site} if ($next_client{site});
    $ret{nivel} = $next_client{nivel} if($next_client{nivel});

    if (defined($ret{site})) {
    	$func->logAdd($glob_cfg{queue_log}, "Iniciando scan no site '" . $ret{site} . "' com report_id '" . $ret{report_id} . "'");
    } else {
    	$func->logAdd($glob_cfg{queue_log}, "Nenhum site disponivel para o scan...");
    }

    return %ret;
}

sub endScan(%){
    my %glob_cfg=_read_conf();
    my $dbh = _connect(%glob_cfg);
    my ($self,%client) = @_;

    _execute_query($dbh, "UPDATE " . $glob_cfg{database} . ".fila set end_scan=NOW(), scan_lock='0', ack=NOW(), checked='1' WHERE current_report='" . $client{report_id} . "' and site='" .$client{site} . "'");
    #sendmail($dbh,$client{report_id});
    $dbh->disconnect;
}

sub _connect(%){
    my %glob_cfg = @_;
    my $dbh;

	do {
		$dbh = DBI->connect('DBI:mysql:' . $glob_cfg{database} . ';mysql_connect_timeout=15;host=' . $glob_cfg{database_host}, $glob_cfg{database_user}, $glob_cfg{database_pass}, {'PrintError'=>0});
      	$func->logAdd($glob_cfg{queue_log}, "Nao foi possivel conectar ao banco: " . DBI->errstr) if (not $dbh);
	} while (not $dbh);

    if (_check_database($dbh,$glob_cfg{database}) == 1) {
        $func->logAdd($glob_cfg{queue_log}, "Base de dados " . $glob_cfg{database} . " nao encontrada.");
        exit(1);
    }

    return $dbh;
}

sub sendAck(){
    my %glob_cfg=_read_conf();
    my $dbh = _connect(%glob_cfg);
    my ($self,$report_id) = @_;
    _execute_query($dbh, "UPDATE $glob_cfg{database}.fila set ack=NOW() WHERE current_report='" . $report_id . "'");

    $dbh->disconnect;
}

sub sendmail($$) {
        my ($dbh,$report_id) = @_;
	my $query_ret = _execute_query($dbh, 'SELECT report.site,usuarios.nome,usuarios.email FROM report,usuarios WHERE report.report_id=' . $report_id . ' AND usuarios.user_id=report.user_id');
	my $contact = $query_ret->fetchrow_hashref();
	my ($vul, $frag) = &conta_vul_fra($dbh, $report_id);
    
        system('/bin/echo -e "Prezado(a) senhor(a) ' . $contact->{nome} . ',\n\n\tInformamos que a análise do site \"' . $contact->{site} . '\" foi concluída. O relatório\ncorrespondente pode ser acessado pelo link a seguir:\n\nhttps://on-security.com/ver\nForam encontradas: 0 Vulnerabilidades e '.$frag.' Fragilidades\n\n\nON-Security Segurança da informação\ne-mail: contato@on-security.com" | /usr/bin/mail -s "[ON-S Report] Análise do site: ' . $contact->{site} . '" -a "From:ON-Security <contato@on-security.com>" ' . $contact->{email}) if($vul == 0);
		system('/bin/echo -e "Prezado(a) senhor(a) ' . $contact->{nome} . ',\n\n\tInformamos que a análise do site \"' . $contact->{site} . '\" foi concluída. O relatório\ncorrespondente pode ser acessado pelo link a seguir:\n\nhttps://on-security.com/ver\nForam encontradas: '.$vul.' Vulnerabilidades e '.$frag.' Fragilidades\n\n\nON-Security Segurança da informação\ne-mail: contato@on-security.com" | /usr/bin/mail -s "[ON-S Report] Análise do site: ' . $contact->{site} . '" -a "From:ON-Security <contato@on-security.com>" ' . $contact->{email}) if($vul != 0);

}

sub conta_vul_fra($$){
        my ($dbh,$report_id) = @_;
        my $query_ret = _execute_query($dbh, 'SELECT (historico.crawfck + historico.crawtim + historico.blind + historico.lfi + historico.phpcgi + historico.rce + historico.rfi + historico.sqli + historico.xss + historico.fckeditor + historico.timthumb + historico.lfiest + historico.rceest + historico.rfiest + historico.crawweb + historico.webshell + historico.sqlif + historico.wordpress + historico.heartbleed) as vul,  (historico.backup + historico.sqldisc + historico.phpwarn + historico.phpinfo + historico.phpfatal + historico.loginform + historico.hash + historico.email + historico.dirlist + historico.cpf + historico.cnpj + historico.sourcecode + historico.uploadform + historico.links) as frag from uniscan.historico where report_id=' . $report_id );
        my $resp = $query_ret->fetchrow_hashref();
my $vul = $resp->{vul};
my $frag = $resp->{frag};
        return($vul, $frag);
}


1;
