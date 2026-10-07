#!/usr/bin/perl
my $dbName="/var/www/db/acl.db";
my $dbTable="acl_user";
my $fieldUser="name"; 
my $fieldPass="md5_password";

#===================================================
use Unix::Syslog qw(:macros :subs);
use DBI;
use Digest::MD5 qw(md5 md5_hex md5_base64);
use Encode;


while ( chomp ( $_ = <STDIN>) and length $_){

    my ($op,$user,$domain,$password) = split /:/,$_;
    
    # Filter dangerous characters
    $user     =~ s/[."\n\r'\$`]//g;
    $password =~ s/[."\n\r'\$`]//g;

    # Equivalente exacto a Text::Iconv->convert('cp1251'|'koi8-r', 'utf8'):
    # comprobado byte a byte, incluido el md5 resultante.
    my $pass1251 = Encode::encode('utf-8', Encode::decode('cp1251', $password));
    my $passkoi8 = Encode::encode('utf-8', Encode::decode('koi8-r', $password));

    $md5pass0 = md5_hex($password);
    $md5pass1 = md5_hex($pass1251);
    $md5pass2 = md5_hex($passkoi8);

    my $result;
    my $dbh = DBI->connect("DBI:SQLite:$dbName", '', '') || die "Could not connect to database: $DBI::errstr";
    if ($op eq 'auth') {
        my $query="SELECT COUNT(*) FROM $dbTable WHERE $fieldUser='$user' AND ($fieldPass='$md5pass0' OR $fieldPass='$md5pass1' OR $fieldPass='$md5pass2');";
        #syslog LOG_INFO, sprintf("query: %s", $query);
        my $sth = $dbh->prepare($query);
        $sth->execute();
        @result = $sth->fetchrow_array();
        syslog LOG_INFO, "$user auth result: $result[0]";
    } elsif ($op eq 'isuser') {
        my $query="SELECT COUNT(*) FROM $dbTable WHERE $fieldUser='$user';";
        #syslog LOG_INFO, sprintf("query: %s", $query);
        my $sth = $dbh->prepare($query);
        $sth->execute();
        @result = $sth->fetchrow_array();
        syslog LOG_INFO, "$user existence result: $result[0]";
    } else {
        $result=0;
    }
    my $out = $result[0]?1:0;
    print "$out\n";
}
closelog;
