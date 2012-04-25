##############################################################################
# DBD::SNMP Module                                                           #
# E-mail: Brendan Byrd <Perl@resonatorsoft.org>                              #
##############################################################################

##############################################################################
# DBD::SNMP

package DBD::SNMP;

use common::sense;  # works every time!
use parent qw(DBI::DBD::SqlEngine);

our $VERSION  = "0.50.00";
our $drh      = undef;         # holds driver handle once initialized
our $err      = 0;             # DBI::err
our $errstr   = "";            # DBI::errstr
our $sqlstate = "";            # DBI::state

our $methods_already_installed = 0;

=head1 NAME

DBD::SNMP - DBI driver abstraction for SNMP

=cut

sub driver {
   return $drh if $drh;      # already created - return same one
   my ($class, $attr) = @_;

   $class .= "::dr";

   $drh = DBI::_new_drh($class, {
      'Name'        => 'SNMP',
      'Version'     => $VERSION,
      'Err'         => \$DBD::SNMP::err,
      'Errstr'      => \$DBD::SNMP::errstr,
      'State'       => \$DBD::SNMP::state,
      'Attribution' => 'DBD::SNMP by Brendan Byrd',
   }) || return undef;

   unless ( $methods_already_installed++ ) {
      DBD::SNMP::db->install_method('snmp_connect');
   }   
   
   return $drh;
}

sub CLONE {
   undef $drh;
}

1;

##############################################################################
# DBD::SNMP::dr

package   # hide from PAUSE
   DBD::SNMP::dr;
$DBD::SNMP::dr::imp_data_size = 0;

use common::sense;  # works every time!

require DBI::DBD::SqlEngine;
use parent qw(-norequire DBI::DBD::SqlEngine::dr);

our ($outer_dbh, $dbh);  # unlike in most DBDs, the DBH is also singleton object

=head1 SYNOPSIS

   use DBI;

   # Single host mode
   $dbh = DBI->connect("dbi:SNMP::$host:$port", undef, $community);   # v1/v2c
   $dbh = DBI->connect("dbi:SNMP::$host:$port", $user, $authpasswd);  # v3
   # (see Net::SNMP->session for detailed options)
   $dbh = DBI->connect("dbi:SNMP:hostname=$host;port=$port;...etc", undef, $community);   # v1/v2c
   $dbh = DBI->connect("dbi:SNMP:hostname=$host;port=$port;...etc", $user, $authpasswd);  # v3

   # Multi-host mode
   my $dbh = DBI->connect("dbi:SNMP:");
   foreach my $d (keys %$DEV) {
      my %hostvars = map { $_.'='.$DEV->{$d}{$_} } qw(hostid hostname port timeout retries community);
      DBI->connect("dbi:SNMP:", undef, $hostvars{community}, \%hostvars) || die "DB->Could not connect to $d: ".$dbh->errstr;
   }

   # get_request example
   ### TODO ###

   # get_entries example
   ### TODO ###

   # set_request example
   ### TODO ###

   # trap / inform / snmpv2_trap example
   ### TODO ###

=cut

sub connect ($;$$$$) {
   my ($drh, $hostvars, $user, $auth, $attr) = @_;
   my $driver_prefix = "snmp_"; # the assigned prefix for this driver

   ### FIXME: stuff like community/authpassword/authkey needs string protection ###
   ### FIXME: Need support for multi-host within a single connect ###

   # (Perl can die on non-hash refs naturally)
   my $h = {
      ref $user ? %$user : (),
      ref $auth ? %$auth : (),
      %$attr
   };
   undef $user if (ref $user);
   undef $auth if (ref $auth);
   
   if ($hostvars =~ /;|^\w+\=/) {
      # Process attributes from the DSN; we assume ODBC syntax
      # here, that is, the DSN looks like var1=val1;...;varN=valN

      foreach my $var (split(/(?<!\\);/, $hostvars)) {
         my ($attr_name, $attr_value) = split(/(?<!\\)=/, $var, 2);
         return $drh->set_err($DBI::stderr, "Can't parse DSN part '$var'") unless (defined $attr_value);
         $h->{$attr_name} = $attr_value;
      }
      $h->{hostname} ||= delete $h->{host};
   }
   else {
      my ($none, $host, $port) = split(/\:/, $hostvars);
      ($host, $port) = ($none, $host) if ($none);  # might have forgot the :: part
      $h->{hostname} ||= $host;
      $h->{port}     ||= $port;
   }

   # Username/Password Synonyms
   $user ||= $h->{username} || $h->{Username} || $h->{user};
   $auth ||= $h->{password} || $h->{Password} || $h->{pass} || $h->{auth};
   delete $h->{$_} for (qw/username Username user password Password pass auth/);
   
   # Check user/auth parameters
   if ($auth && !$user) {
      $h->{community} ||= $auth;  # assume it's a community string
   }
   else {
      $h->{username}     ||= $user if ($user);
      $h->{authpassword} ||= $auth if ($auth);
   }
   
   # create first instance of DBH objects
   unless ($outer_dbh || $dbh) {
      ($outer_dbh, $dbh) = DBI::_new_dbh($drh, {
         Name                => 'SNMPdb',
         sql_identifier_case => 2,  # lc
         sql_flags           => {PrintError=>1, RaiseError=>1},
         sql_dialect         => 'SNMP',
         ( snmp_load_all     => $h->{snmp_load_all} ) x!! exists $h->{snmp_load_all},
      }, {});
      $dbh->STORE('Active', 1);

      # Okay, now we can immediately create some default temporary tables
      $dbh->do(
         "CREATE TEMP TABLE dbi_snmp.hosts (
            hostid        INTEGER  NOT NULL,
            hostname      OCTETSTR NOT NULL,
            port          INTEGER,
            localaddr     OCTETSTR,
            localport     INTEGER,
            version       OCTETSTR,
            domain        OCTETSTR,
            timeout       INTEGER,
            retries       INTEGER,
            maxmsgsize    INTEGER,
            translate     INTEGER,
            debug         INTEGER,
            community     OCTETSTR,
            username      OCTETSTR,
            authkey       OCTETSTR,
            authpassword  OCTETSTR,
            authprotocol  OCTETSTR,
            privkey       OCTETSTR,
            privpassword  OCTETSTR,
            privprotocol  OCTETSTR,
            PRIMARY KEY (hostid)
         )"
      );
      $dbh->do(
         'CREATE TEMP TABLE dbi_snmp.host_errors (
            hostid    INTEGER   NOT NULL,
            tablename OCTETSTR  NOT NULL,
            errormsg  OCTETSTR  NOT NULL,
            msgtime   TIMETICKS NOT NULL,
            PRIMARY KEY (hostid, tablename)
         )'
      );
   }

   if ($h->{hostname}) {  # hostname is optional, since the $dbh object can be created prior to connecting
      my ($session, $hostid) = $dbh->snmp_connect($h);
      return $dbh->set_err($DBI::stderr, "SNMP Connection failed!", '08001') unless ($session);
   }
   
   return $outer_dbh;
}

sub data_sources ($;$) {
   my($drh, $attr) = @_;

   ### FIXME: Need to get variables from dbi_snmp.hosts ###
}

# Override DBI version to handle special case of undef/community pair
sub default_user {
   my ($drh, $user, $pass, $attr) = @_;
   ($user, $pass) = ($ENV{DBI_USER}, $ENV{DBI_PASS}) unless ( defined $user || defined $pass);
   $pass = $ENV{DBI_PASS}                            unless (!defined $user || defined $pass);  # only define a default password if the username is already defined
   return ($user, $pass);
}

sub disconnect_all {
   my($drh, $attr) = @_;

   for (values %{$dbh->{snmp_sessions}}) { $_->close(); }
   delete $dbh->{snmp_sessions};
   
   my $sth = $dbh->prepare("DELETE FROM dbi_snmp.hosts") || return $dbh->set_err($DBI::stderr, $dbh->errstr, $dbh->state);
   $sth->execute() || return $dbh->set_err($DBI::stderr, $dbh->errstr, $dbh->state);

   my $sth = $dbh->prepare("DELETE FROM dbi_snmp.host_errors") || return $dbh->set_err($DBI::stderr, $dbh->errstr, $dbh->state);
   $sth->execute() || return $dbh->set_err($DBI::stderr, $dbh->errstr, $dbh->state);
   
   1;
}

1;

##############################################################################
# DBD::SNMP::db

package   # hide from PAUSE
   DBD::SNMP::db;
$DBD::SNMP::db::imp_data_size = 0;

use common::sense;  # works every time!
use SNMP;
use List::Util qw(reduce first);
use List::MoreUtils qw(firstidx uniq any none);
use String::LCSS_XS qw(lcss_all);
use Storable qw(dclone);

use Net::SNMP;
BEGIN { eval 'use Net::SNMP::XS;'; }  # use it if we got it

require DBI::DBD::SqlEngine;
use parent qw(-norequire DBI::DBD::SqlEngine::db);
use subs qw(snmp_info_reference);

our $snmp_specs = {};

sub snmp_connect {
   my ($dbh, $h) = (shift, shift);
   return $dbh->{Driver}->connect($h, @_) if (!ref $h || @_);  # make sure this isn't being called like DBI->connect

   # Defaults
   $h->{version}    ||= 'v2c';
   $h->{domain}     ||= 'udp';
   $h->{port}       ||= 161;
   $h->{timeout}    ||= 30;
   $h->{retries}    ||= 3;
   $h->{maxmsgsize} ||= 32767;
      
   my @keys = grep { !/[A-Z]/ } sort keys %$h;

   # Open SNMP session
   my ($session, $error) = Net::SNMP->session(
      (map { ("-$_" => $h->{$_}) } grep { !/^hostid$/ } @keys),
      -nonblocking => 1,
      -translate     => [
         -octetstring => 0x0,
         -timeticks   => 0x0,
         -opaque      => 0x0,
      ],
   );
   return $dbh->set_err($DBI::stderr, "Net::SNMP: $error", '08001') if ($error);
   
   # Create a new hostid (if not provided)
   unless ($h->{hostid}) {
      my $row = ($dbh->selectall_arrayref("SELECT MAX(hostid) FROM dbi_snmp.hosts"))->[0] || [ 1 ];
      $h->{hostid} = $row->[0] || 1;
   }
   
   # Throw the details into the hosts table
   my $cmd = 'INSERT INTO dbi_snmp.hosts ('.join(',', @keys).') VALUES ('.join(',', ('?') x (scalar @keys)).')';
   $dbh->do($cmd, undef, map { $h->{$_} } @keys) || return $dbh->set_err($DBI::stderr, $dbh->errstr, $dbh->state);

   $dbh->{snmp_sessions}{ $h->{hostid} } = $session;
   return ($session, $h->{hostid});
}

sub prepare {
   my ($dbh, $statement, @attribs) = @_;

   # create a 'blank' sth
   my ($outer, $sth) = DBI::_new_sth($dbh, { Statement => $statement });

   my @params;
   uc($statement) =~ /^\s*(\w+)\s+/;
   my $cmd = $1;
   
   # ReadOnly checks
   if    ($dbh->FETCH('ReadOnly') && $cmd =~ /UPDATE|DELETE|DROP|CREATE|INSERT/) {
      return $dbh->set_err($DBI::stderr, "Driver is in ReadOnly mode; no active SQL statements allowed!", '42808');
   }
   
   # Remove trailing semi-colon
   $statement =~ s/\;\s*$//;

   # Parse out the statement
   $dbh->{sql_parser_object} ||= SQL::Parser->new($dbh->{sql_dialect}, { %{$dbh->{sql_flags}} });  # anonymize sql_flags, as it builds the parser object from that
   my $stmt = DBD::SNMP::Statement->new($statement, $dbh->{sql_parser_object});
   return $dbh->set_err($DBI::stderr, "SQL Syntax Error: ".$stmt->{errstr}, '42000') if (!$stmt || $stmt->{errstr});
   my $cmd = $stmt->{command};
   
   # We like schemas in our tables, thankyouverymuch...
   if ($stmt->{table_names} && $stmt->{org_table_names}) {
      my @tables = @{$stmt->{org_table_names}};
      $stmt->{table_names} = [ map { (-1 == index($_, '"')) ? lc $_ : do { s/\"//g; $_; } } @tables ];
      $stmt->{tables}      = [ map { SQL::Statement::Table->new($_) } @{$stmt->{org_table_names}} ];  # (@tables already has quotes removed)
   }

   # Store basic values
   $sth->STORE('sql_stmt', $stmt);
   $sth->STORE('sql_params', []);
   $sth->STORE('NUM_OF_PARAMS', scalar $stmt->params());
   $sth->{'NUM_OF_PARAMS'} = scalar $stmt->params();
   
   ### TODO: need to figure out which commands are not going to report any data ###
   ### FIXME: Check for SNMP permissions of columns (except for keys) ###
   ### FIXME: Need to check on hosts table for data ###
   
   # easy access table object
   my $s = $stmt->{tables_by_name} = { map {
      my $n = $_->{name}; $n =~ s/\"//g; $n => $_;
   } @{$stmt->{tables}} };
   
   # Handle CREATE/DROP TABLE statements
   unless ($stmt->{is_ram_table}) {
      return $dbh->set_err($DBI::stderr, "Cannot drop a SNMP table",   '0A502') if ($cmd eq 'DROP');
      return $dbh->set_err($DBI::stderr, "Cannot create a SNMP table", '0A502') if ($cmd eq 'CREATE');
   }
   elsif ($cmd eq 'DROP' && @{$stmt->{table_names}} ~~ /^dbi_snmp\./i) {
      return $dbh->set_err($DBI::stderr, "Cannot drop DBD::SNMP system tables", '0A502');
   }
   else {  # Let SQL::Statement create/drop it
      # Fake spec objects for TEMP TABLEs
      snmp_info_reference($dbh, 'load');
      foreach my $table (@{$stmt->{table_names}}) {
         my ($mib, $tbl) = split(/\./, $table);
         ($mib, $tbl) = ('BLANK_SCHEMA', $table) unless ($tbl);
         my $mib_dash = $mib;
         $mib_dash =~ s/_/-/g;
      
         if    ($cmd eq 'CREATE') {
            next if ($snmp_specs->{Full}{tbl}{"$mib.$tbl"});

            # Table definition
            $snmp_specs->{MIB}{$mib}      //= {};
            $snmp_specs->{MIB}{$mib}{all} //= {};
            $snmp_specs->{MIB}{$mib}{tbl} //= {};
            $snmp_specs->{MIB}{$mib}{col} //= {};
            my $m = $snmp_specs->{MIB}{$mib}{all}{$tbl} //= {};
            $snmp_specs->{MIB}{$mib}{tbl}{$tbl}   = $m;
            $snmp_specs->{Full}{all}{"$mib.$tbl"} = $m;
            $snmp_specs->{Full}{tbl}{"$mib.$tbl"} = $m;

            # Special dbi_hostid linkage
            $snmp_specs->{MIB}{dbi_snmp}{key}{dbi_hostid}{tbl} = $m if ("$mib.$tbl" eq 'dbi_snmp.hosts');

            $m->{name}     = $tbl;
            $m->{mibname}  = $mib;
            $m->{fullname} = "$mib.$tbl";
            $m->{type}     = 'tbl';
            
            $m->{mib}  = $snmp_specs->{MIB}{$mib};
            $m->{cols} = [];
            $m->{keys} = [];
            $m->{col}  = {};
            $m->{key}  = {};
            $m->{table_type} = $mib eq 'dbi_snmp' ? 'SYSTEM TABLE' : 'LOCAL TEMPORARY';
            $m->{data} = {
               access   => 'NoAccess',
               label    => $tbl,
               moduleID => $mib_dash,
               status   => 'Current',
            };
            
            # Column definitions
            my $i = 1;
            foreach my $colname (@{$stmt->{org_col_names}}) {
               my $col = $stmt->{table_defs}{columns}{$colname};
               my $ncol = {};
               
               $ncol->{name}     = $colname;
               $ncol->{mibname}  = $mib;
               $ncol->{fullname} = "$mib.$colname";
               $ncol->{type}     = 'col';
               
               $ncol->{tbl}  = $m;
               $ncol->{mib}  = $snmp_specs->{MIB}{$mib};
               $ncol->{data} = {
                  access            => 'ReadWrite',
                  label             => $colname,
                  moduleID          => $mib_dash,
                  status            => 'Current',
                  subID             => $i++,
                  syntax            => $col->{data_type},
                  textualConvention => undef,
                  type              => $col->{data_type},
               };
               
               push @{$m->{cols}}, $ncol;
               $m->{col}{$colname} = $ncol;
               $snmp_specs->{MIB}{$mib}{col}{$colname}   = $ncol;
               $snmp_specs->{Full}{all}{"$mib.$colname"} = $ncol;
               $snmp_specs->{Full}{col}{"$mib.$colname"} = $ncol;
            }
            
            # Key definitions
            my $keydef = first { $_->{type} eq 'PRIMARY' && $_->{local_cols} } values %{$stmt->{table_defs}};
            foreach my $keyname (@{$keydef->{local_cols}}) {
               my $kcol = $m->{col}{$keyname};
               $kcol->{type} = 'key';
            
               push @{$m->{keys}}, $kcol;
               $m->{key}{$keyname} = $kcol;
               $snmp_specs->{MIB}{$mib}{key}{$keyname}   = $kcol;
               $snmp_specs->{Full}{key}{"$mib.$keyname"} = $kcol;
            }
            unshift @{$m->{cols}}, grep { $_ ~~ @{$m->{cols}} } @{$m->{keys}};
            
         }
         elsif ($cmd eq 'DROP') {
            delete $snmp_specs->{MIB}{$mib}{all}{$tbl};
         }
      }
   
      return $outer;
   }
   
   # Need more information about the tables in question
   foreach my $table (@{$stmt->{table_names}}) {
      my ($mib, $tbl) = split(/\./, $table);
      ($mib, $tbl) = (undef, $table) unless ($tbl);
      my $t = snmp_info_reference($dbh, 'table', $mib, $tbl, '', 1);
      snmp_info_reference($dbh, 'column', $t->[0][1], $t->[0][2], '%', 0);  # just to get the data into %ss (non-loose)
      
      my $ss_t = $snmp_specs->{MIB}{$t->[0][1]}{tbl}{$t->[0][2]} ||
         return $dbh->set_err($DBI::stderr, "Unknown table '$table'", '42720');
      $s->{$table}{snmp_specs} = $ss_t;
   }
   
   # Get a complete list of columns to be used
   # (recursively because of the where_clause, functions, etc.)  
   my $where = $stmt->{where_clause};
   my @step = ($where, ( map { $_->{sql_loc} = 'select'; $_; } @{$stmt->column_defs()} ), ( map { {value => $_, type => 'column', sql_loc => 'sort'}; } map { keys %$_ } @{$stmt->{sort_spec_list}} ));
   my @cols;
   while (@step) {
      my $w = shift @step;
      if    (ref $w eq 'HASH' && $w->{value} && $w->{type} && !ref($w->{value})) {
         $w->{sql_loc} ||= 'where';
         push @cols, $w if ($w->{type} eq 'column');  # only care about real columns at this point
      }  
      elsif (ref $w eq 'HASH')           { unshift @step, grep { ref $_ } values %$w; }
      elsif (ref $w eq 'ARRAY')          { unshift @step, grep { ref $_ }        @$w; }
      # functions and the like may have buried columns
      elsif (ref $w->{value} eq 'HASH')  { unshift @step, grep { ref $_ } values %{$w->{value}}; }
      elsif (ref $w->{value} eq 'ARRAY') { unshift @step, grep { ref $_ }        @{$w->{value}}; }
   }

   # Column -> Table validation
   for (my $i = 0; $i < @cols; $i++) {  # ol' fashioned loop for array self-modification
      my $c = $cols[$i];
      # (NOTE: SQL::Parser does table alias translation for us...)
      my ($col, $tbl, $mib) = reverse split(/\./, $c->{value}, 3);  # reversed to account for missing data
      my $t;
      
      # Expand '*'
      if ($col eq '*') {
         # check for table existance
         my $tbl_name = ($mib and $mib.'.').$tbl;
         if ($tbl) {
            $t = (first { /^\Q$tbl_name\E$|^\Q$tbl\E$/i } keys %$s) or
               return $dbh->set_err($DBI::stderr, "Unknown table '$tbl_name' on column '*'", '42720');
         }
         
         # tbl.* = one table
         #     * = all columns in all tables (in the order that they appear)
         my @newcols;
         foreach my $table ($tbl ? ($s->{$t}{snmp_specs}{name}) : @{$stmt->{table_names}}) {
            my $tobj = $s->{$table}{snmp_specs};
            @newcols = ( map { {
               value   => "$table.".$_->{name},
               type    => 'column',
               sql_loc => $c->{sql_loc},
            }; } @{$tobj->{cols}} );
         }
         
         # replace '*' with new columns, backtrack one, and loop back
         splice(@cols, $i--, 1, @newcols);
         next;
      }
      
      ### FIXME: Account for TEMP TABLES ###
      if ($mib || $tbl) {
         # has specific table name
         my $tbl_name = ($mib and $mib.'.').$tbl;
         
         $t = (first { /^\Q$tbl_name\E$|^\Q$tbl\E$/i } keys %$s) or
            return $dbh->set_err($DBI::stderr, "Unknown table '$tbl_name' on column '$col'", '42720');
         $s->{$t}{snmp_specs}{col}{$col} or
            return $dbh->set_err($DBI::stderr, "Column '$col' does not exist in table '$tbl_name'", '42720');
      }
      else {
         # no table name; look in all tables
         my @colobj = grep { $_->{snmp_specs}{col}{$col} } values %$s;
         given (@colobj <=> 1) {
            when  (1) {    # too many
               return $dbh->set_err($DBI::stderr, "Ambiguous column '$col' found on more than one table", '42702');
            }
            when (-1) {    # none found
               return $dbh->set_err($DBI::stderr, "Column '$col' does not exist in any table referenced in the SQL statement", '42720');
            }
            when  (0) {    # just right...
               $t = $colobj[0]->{name};
            }
         }
      }
      
      unless ($s->{$t}{stmt_col_name}{$col}) {
         $c->{tbl}           = $s->{$t};
         $c->{snmp_specs}    = $c->{tbl}{snmp_specs}{col}{$col};
         $c->{is_key}        = $c->{tbl}{snmp_specs}{key}{$col} ? 1 : 0;
         
         $s->{$t}{stmt_cols}     //= [];
         $s->{$t}{stmt_col_name} //= {};
         push(@{$s->{$t}{stmt_cols}}, $c);
         $s->{$t}{stmt_col_name}{$col} = $c;
      }

      # Check permissions
      ### FIXME: INSERT/UPDATE permissions ###
      my $access = $c->{snmp_specs}{data}{access};
      return $dbh->set_err($DBI::stderr, "Column '$col' has access level of $access, and is thus inaccessible", '01007')
         unless ($access =~ /Read|Create/ || $c->{is_key});
   }

   # While we're here, try to figure out exactly what indexes are required via WHERE
   foreach my $tbl (keys %$s) {
      my $t = $s->{$tbl};
      my @step = ($stmt->where);  # using this syntax, since it works better for what we are doing
      my @keys = map { lc($_->{name}) } @{$t->{snmp_specs}{keys}};
      my %wkeys;
      my %val;
      unless ($step[0]) {  # might not have a WHERE clause
         $t->{stmt_key_count} = 0;
         $t->{stmt_key_vals}  = {};
         $t->{stmt_key_abs}   = 0;
         last;
      }
      
      while (@step) {
         my $w = shift @step;

         # check for absurd conditions
         if ($w->left && $w->right &&
              $w->left->isa('SQL::Statement::ConstantTerm') &&
             $w->right->isa('SQL::Statement::ConstantTerm') &&
             !$w->value($w)
         ) {
            # okay, we have something weird like 1=0, so this is ALWAYS going to return no rows
            $t->{stmt_key_abs} = -1;
            last;
         }
         
         # check the operator
         my $col = $w->left and lc($w->left->{VALUE});
         if ($col) {
            $col =~ s/^\Q$tbl\E\.//i;
            given ($w->op) {
               when ('=')        {  #  first level absolute (exact match)
                  # must be in form of c = ##/?
                  $wkeys{$col} = 1;
                  $val{$col} = $w->right;
                  next;
               }
               when (/IN/i)      {  # second level absolute (series of exact matches)
                  if ($wkeys{$col} && $wkeys{$col} > 1) {
                     $wkeys{$col} = 2;
                     $val{$col} = $w->right;
                  }
                  next;
               }
               when (/</)        {  #  third level absolute (start/end index - beginning)
                  if ($wkeys{$col} && $wkeys{$col} > 2) {
                     $wkeys{$col} = 3;
                     $val{$col} ||= {};
                     $val{$col}{start}    = $w->right;
                     $val{$col}{start_op} = $w->op;
                  }
                  next;
               }  
               when (/>/)        {  #  third level absolute (start/end index - ending)
                  if ($wkeys{$col} && $wkeys{$col} > 2) {
                     $wkeys{$col} = 3;
                     $val{$col} ||= {};
                     $val{$col}{end}      = $w->right;
                     $val{$col}{end_op}   = $w->op;
                  }
                  next;
               }
               when (/BETWEEN/i) {  # BETWEEN has both
                  if ($wkeys{$col} && $wkeys{$col} > 2) {
                     $wkeys{$col} = 3;
                     $val{$col} ||= {};
                     $val{$col}{start}    = $w->right->[0];
                     $val{$col}{start_op} = '<=';
                     $val{$col}{end}      = $w->right->[1];
                     $val{$col}{end_op}   = '>=';
                  }
                  next;
               }
               when (/AND/i) {
                  # nothing, but the clauses are still absolute at this point
               }
               default   { next; }  # disqualification for further review (since clauses are no longer absolute)
            }
         }
         elsif ($w->op() !~ /AND/i) { next; }
         
         # add more to the search
         if (ref $w eq 'HASH')     { unshift @step, grep { ref $_ } values %$w; }
         elsif (ref $w eq 'ARRAY') { unshift @step, grep { ref $_ }        @$w; }
      }
      
      # now check the results
      my $i = 0;
      for (@keys) { $wkeys{$_} == 1 ? $i++ : last; }
      $t->{stmt_key_count}   = $i;
      $t->{stmt_key_vals}    = \%val;
      
      # see if there is a fuzzy "absolute" index on the next key
      my $rc = $t->{snmp_specs}{keys}[$i];
      my $rng_col = lc($rc->{name});

      if    ($i >= scalar @keys) {
         $t->{stmt_key_abs} = 1;
      }
      elsif ($rng_col && $wkeys{$rng_col} >= 2) {
         $t->{stmt_key_rng_col} = $rc;
         $t->{stmt_key_abs} = $wkeys{$rng_col} || 0;
      }
   }

   # try to fill in some of the $sth DBI variables
   @cols = grep { $_->{sql_loc} eq 'select' } @cols;  # only need the main column fields
   for (@cols) { $_->{colname} = $_->{value}; $_->{colname} =~ s/^.+\.//; }

   my %type_num;  # SQL::Parser row value types = null|number|empty_string (discontinued)|string|column|placeholder|function|setfunc
   my @names = grep { $_ } map {
      my $ct = $_->{type};
      $ct eq 'column' ? ($_->{alias} || $_->{colname}) : 
                        ($_->{alias} ne $_->{name}) ? $_->{alias} :
                        (uc($_->{name} || $ct).(++$type_num{$ct}));  # dummy name, like STRING4 or NVL3
   } @cols;

   $sth->STORE('NUM_OF_FIELDS', scalar @cols);
   
   my $cache = { map { ($_->{value} => $_->{snmp_specs}{column_info}) } grep { $_->{type} eq 'column' } @cols };
   $sth->{'NAME'}         =             \@names;
   $sth->{'NAME_lc'}      = [ map { lc } @names ];
   $sth->{'NAME_uc'}      = [ map { uc } @names ];
   $sth->{'NAME_hash'}    = { map {    $names[$_]  => $_ } (0 .. (@names - 1)) };
   $sth->{'NAME_lc_hash'} = { map { lc($names[$_]) => $_ } (0 .. (@names - 1)) };
   $sth->{'NAME_us_hash'} = { map { uc($names[$_]) => $_ } (0 .. (@names - 1)) };

   $sth->{'TYPE'}         = [ map { $cache->{$_} && $cache->{$_}[13] } @names ];
   $sth->{'PRECISION'}    = [ map { $cache->{$_} && $cache->{$_}[ 6] } @names ];
   $sth->{'SCALE'}        = [ map { $cache->{$_} && $cache->{$_}[ 8] } @names ];
   $sth->{'NULLABLE'}     = [ map { $cache->{$_} && $cache->{$_}[10] } @names ];

   return $sth;
}

### FIXME: Replace init_valid_attributes, init_default_attributes ###

sub last_insert_id {
   my($dbh, $catalog, $schema, $table, $field) = @_;
   ### TODO ###
   return $dbh->{snmp_last_insert_id}->{$table};
}

sub disconnect {
   ### TODO ###
}

sub get_info {
   my($dbh, $info_type) = @_;
   my $v = $DBD::SNMP::GetInfo::info{int($info_type)};
   $v = $v->($dbh) if (ref $v eq 'CODE');
   return $v;
}

### TODO: This whole mess of hashes and objects needs blessed classes and a good doc reference ###

sub snmp_info_load {
   my $dbh = $_[0];
   
   $SNMP::save_descriptions = 1;
   &SNMP::addMibDirs(split /\w+/, $dbh->{snmp_mib_dirs});
   &SNMP::loadModules('ALL');
   &SNMP::initMib();

   $snmp_specs->{MIB}       = {};
   $snmp_specs->{Full}      = {};
   $snmp_specs->{Full}{all} = {};
   $snmp_specs->{Full}{tbl} = {};
   $snmp_specs->{Full}{key} = {};
   $snmp_specs->{Full}{col} = {};

   foreach my $id (sort keys %SNMP::MIB) {
      my $o = $SNMP::MIB{$id};
      my ($mib, $name) = map { $o->{$_} } qw(moduleID label);
      $mib =~ s/-/_/g;  # convert dashes to underscores
      my $full_name = "$mib.$name";
      
      # table/column data
      # (ML = memory linkage; to keep memory usage down while maintaining greatest accessibility)

      # (this section needs to be fast, as a lot of children can really slow down things...)
      my ($columns, $index_link, $table_type);
      my $c  = $o->{children};
      my $e  = $c->[0];
      my $ek = $e  && $e->{children};
      my $lk = $ek && $ek->[-1];
      my @oo = grep { $_->{access} ne 'NoAccess' && !arrayref_short_cnt($_->{children}) && $_->{syntax} } @$c;
      
      # (can't use $e->{indexes} checks, else this would be easier)
      #                                 (we don't need a total count, just 0, 1, or 2)
      if    ($o->{access} eq 'NoAccess' && !$o->{syntax} &&  arrayref_short_cnt($c)              &&
             $e->{access} eq 'NoAccess' && !$e->{syntax} &&  arrayref_short_cnt($ek)             &&
            $lk->{access} ne 'NoAccess' && $lk->{syntax} && !arrayref_short_cnt($lk->{children})
      ) {
         # Standard table
         $columns    = $ek;
         $index_link = $e;
         $table_type = 'TABLE';
      }
      elsif (!$o->{access} && !$o->{syntax} && @oo) {
         # Global table
         $columns    = \@oo;
         $index_link = { indexes => [] };
         $table_type = 'VIEW';
      }
      
      $snmp_specs->{MIB}{$mib}      //= {};
      $snmp_specs->{MIB}{$mib}{all} //= {};
      my $m = $snmp_specs->{MIB}{$mib}{all}{$name} //= {};
      $snmp_specs->{Full}{all}{$full_name} = $m;  # ML
      $m->{data} = $o;                            # ML to SNMP::MIB
      $m->{mib}  = $snmp_specs->{MIB}{$mib};      # ML
      
      # basic properties
      $m->{name}     = $name;
      $m->{mibname}  = $mib;
      $m->{fullname} = $full_name;
      $m->{type}     = 'all';
      
      if ($columns) {
         $snmp_specs->{MIB}{$mib}{tbl} //= {};
         $snmp_specs->{MIB}{$mib}{tbl}{$name} = $m;  # ML
         $snmp_specs->{Full}{tbl}{$full_name} = $m;  # ML
         $m->{type}       = 'tbl';
         $m->{table_type} = $table_type;
         $m->{raw_cols}   = $columns;
         $m->{index_link} = $index_link if ($index_link);  # cannot directly link to {indexes} without a .05s slowdown
      }
   }

   # fake dbi_hostid object
   my $host_id = {
      access            => 'ReadOnly',
      augments          => undef,
      children          => [],
      defaultValue      => undef,
      description       => 'ID of the host device that the data came from; not part of any SNMP MIB.',
      enums             => {},
      hint              => 'd',
      indexes           => [],
      label             => 'dbi_hostid',
      moduleID          => 'dbi-snmp',  # dashes on moduleID
      nextNode          => undef,
      objectID          => undef,
      parent            => undef,
      ranges            => [{
         high => 2147483647,
         low  => 1,
      }],
      status            => 'Current',
      subID             => 1,
      syntax            => 'INTEGER32',
      textualConvention => undef,
      type              => 'INTEGER32',
      units             => undef,
      varbinds          => [],
   };
   $snmp_specs->{MIB}{dbi_snmp}      //= {};
   $snmp_specs->{MIB}{dbi_snmp}{all} //= {};
   $snmp_specs->{MIB}{dbi_snmp}{key} //= {};
   $snmp_specs->{MIB}{dbi_snmp}{col} //= {};

   my $m = $snmp_specs->{MIB}{dbi_snmp}{all}{dbi_hostid} //= {};
   $snmp_specs->{MIB}{dbi_snmp}{key}{dbi_hostid}   = $m;  # ML
   $snmp_specs->{MIB}{dbi_snmp}{col}{dbi_hostid}   = $m;  # ML
   $snmp_specs->{Full}{all}{'dbi_snmp.dbi_hostid'} = $m;  # ML
   $snmp_specs->{Full}{key}{'dbi_snmp.dbi_hostid'} = $m;  # ML
   $snmp_specs->{Full}{col}{'dbi_snmp.dbi_hostid'} = $m;  # ML

   $m->{data}     = $host_id;                      # ML to SNMP::MIB
   $m->{mib}      = $snmp_specs->{MIB}{dbi_snmp};  # ML
   $m->{name}     = 'dbi_hostid';
   $m->{mibname}  = 'dbi_snmp';
   $m->{fullname} = 'dbi_snmp.dbi_hostid';
   $m->{type}     = 'col';
   
   # Post-processing: columns and keys
   ### TODO: Need NOTIF objects; look at DOCS-IETF-CABLE-DEVICE-NOTIFICATION-MIB::docsDevCmtsInitRegReqFailNotif ###
   foreach my $tobj (values %{$snmp_specs->{Full}{tbl}}) {
      $tobj->{col}  //= {};
      $tobj->{cols} //= [];

      foreach my $ss_c (@{$tobj->{raw_cols}}) {  # directly in to SNMP::MIB obj, unlike other column loops
         my ($mib, $name) = map { $ss_c->{$_} } qw(moduleID label);
         $mib =~ s/-/_/g;  # convert dashes to underscores

         my $cobj = $snmp_specs->{MIB}{$mib}{all}{$name};
         my $full_name = "$mib.$name";
         $cobj->{tbl}  = $tobj;  # ML
         $cobj->{type} = 'col';
         
         $snmp_specs->{MIB}{$mib}{col}{$name} = $cobj;  # ML
         $snmp_specs->{Full}{col}{$full_name} = $cobj;  # ML
         $tobj->{col}{$name} = $cobj;                   # ML
         push @{$tobj->{cols}}, $cobj;                  # ML
      }
      delete $tobj->{raw_cols};
   }

   # Post-processing of indexes, if the user requests it
   if ($dbh->{snmp_load_all}) {
      snmp_process_indexes($dbh, values %{$snmp_specs->{Full}{tbl}});
   }
}

# SNMP::MIB seems to take around 1/20th of a sec to process each $o->{indexes} object.
# So, we do this post-processing on-demand only.
sub snmp_process_indexes {
   my $dbh = shift @_;
   my $good = 1;
   
   TLOOP: foreach my $tobj (@_) {
      next unless ($tobj->{index_link});
      $tobj->{raw_keys} = $tobj->{index_link}{indexes};
      $tobj->{key}  //= {};
      $tobj->{keys} //= [];
      
      foreach my $name ('dbi_hostid', @{$tobj->{raw_keys}}) {
         my $kobj = $snmp_specs->{Full}{col}{ first { /\.\Q$name\E$/i } keys %{$snmp_specs->{Full}{col}} };
         unless ($kobj) {
            $good = $dbh->set_err($dbh->{snmp_load_all} ? '' : 0, "Unknown index key '$name' on table '".$tobj->{name}."'; removing table's existence", '42720');
            
            # From now on, this table will have no identifying marks of any kind.  It will not stand out in any way.  It's
            # entire image is crafted to leave no lasting memory with anyone it encounters.  It's a rumor, recognizable only as
            # deja vu and dismissed just as quickly.  It doesn't exist; it was never even born.  Anonymity is its name.
            # Silence its native tongue.  It's no longer part of the System.  It's above the System.  Over it.  Beyond it.
            # We're "them."  We're "they."  We are the Management Information Base.
            foreach my $obj (@{$tobj->{cols}}, $tobj) {
               my ($mib, $name, $full_name) = map { $obj->{$_} } qw(mib name fullname);
               delete $mib->{$_}{$name}                   for qw(all tbl key col);
               delete $snmp_specs->{Full}{$_}{$full_name} for qw(all tbl key col);
               delete $obj->{$_}                          for qw(data mib tbl);
               
               $obj = {};
               $obj = undef;
               undef $obj;
            }
            
            next TLOOP;
         }
         
         my $mib       = $kobj->{mibname};
         my $full_name = $kobj->{fullname};
         $kobj->{tbl} ||= $tobj;  # ML
         $kobj->{type} = 'key';
         
         $snmp_specs->{MIB}{$mib}{col}{$name} = $kobj;  # ML
         $snmp_specs->{Full}{col}{$full_name} = $kobj;  # ML
         $snmp_specs->{MIB}{$mib}{key}{$name} = $kobj;  # ML
         $snmp_specs->{Full}{key}{$full_name} = $kobj;  # ML
         $tobj->{col}{$name} = $kobj;    # ML
         $tobj->{key}{$name} = $kobj;    # ML
         push @{$tobj->{keys}}, $kobj;   # ML
      }
      $tobj->{cols} = [ sort { $a->{data}{subID} <=> $b->{data}{subID} } uniq(@{$tobj->{keys}}, @{$tobj->{cols}}) ];
      
      delete $tobj->{raw_keys};
      delete $tobj->{index_link};
   }
   
   return $good;
}

sub arrayref_short_cnt { my $c = $_[0]; return $c->[0] ? ($c->[1] ? 2 : 1) : 0; }   

sub snmp_info_reference {
   my ($dbh, $type, $mib, $table, $column, $loose) = @_;
   
   state $snmpLoaded = 0;
   snmp_info_load($dbh) unless ($snmpLoaded);
   $snmpLoaded = 1;
   return undef if ($type =~ /load/i);
   
   # Support wildcards
   my ($mib_re, $table_re, $column_re) = (map { ($type =~ /primary/i) ? quotemeta : sql_wildcard_re($_) } ($mib, $table, $column));
   
   # Look up the spec objects
   my (@mobj, @tobj, @cobj);
   if ($mib) {
      my $s = $snmp_specs->{MIB};
      my @mib;
      if ($loose) {
         @mib = ($mib)        if ($s->{$mib});
         @mib = ($mib.'_MIB') if (!@mib && $s->{$mib.'_MIB'});
         @mib = (first { /^$mib_re(?:_MIB)?$/i } keys %$s) if (!@mib);
      }
      else {
         @mib = grep { /^$mib_re(?:_MIB)?$/i } keys %$s;
      }
      return [] unless (@mib);  # don't have any other way of finding it
      @mobj = map { $s->{$_} } @mib;
   }
   else { @mobj = values %{$snmp_specs->{MIB}}; }

   my $hostid_ss = $snmp_specs->{MIB}{dbi_snmp}{key}{dbi_hostid};
   foreach my $pair ([table => $table], [column => $column]) {
      my ($type, $var) = @$pair;
      my $tbl = $type eq 'table';
      my $tkey = $tbl ? 'tbl' : 'col';
      my $vre = $tbl ? $table_re : $column_re;

      my @obj;
      if (!$var || $var eq '%') {
         @obj = map { @{$_->{$tkey.'s'}} } (@tobj ? @tobj : @mobj);
         $tbl ? (@tobj = @obj) : (@cobj = ($hostid_ss, @obj));
         next;
      };

      if ($loose) {
         my $s = @tobj == 1 ? $tobj[0] : 
                 @mobj == 1 ? $mobj[0] : $snmp_specs->{Full};
         $s = $s->{$tkey};
         
         $var = $s->{$var} || $s->{$var.'Table'} ||
            $s->{(first { /(?:\:\:|^)$vre$/i } keys %$s)} ||
            $s->{(first {           /$vre$/i } keys %$s)} ||
            $s->{(first {           /$vre/i  } keys %$s)};
         @obj = @{[ $var ]} if ($var);
      }
      else {
         foreach my $o (@tobj ? @tobj : @mobj) {
            push @obj, $hostid_ss if (!$tbl && 'dbi_hostid' =~ /^$vre$/i);  # don't forget the hostid if it matches
            push @obj, map { $o->{$tkey}{$_} } grep { /^$vre$/i } keys %{$o->{$tkey}};
         }
      }
         
      return [] unless (@obj);  # don't process if it's specific and it fails to match
      $tbl ? (@tobj = @obj) : (@cobj = @obj);
   }
   
   my @dbi_data;
   given ($type) {
      when (/table/i) {
         foreach my $t (@tobj) {
            my ($schema, $table) = map { $t->{$_} } qw(mibname name);
            my $tbl = $t->{data};

                                  # TABLE_CAT TABLE_SCHEM TABLE_NAME TABLE_TYPE REMARKS
            $t->{table_info} ||= [ undef, $schema, $table, $t->{table_type} eq 'VIEW' ? 'TABLE' : $t->{table_type}, despace($tbl->{description}) ]; 
            push @dbi_data, $t->{table_info};
         }
      }
      when (/column|primary|statistics/i) {
         my $types = &type_info_all;
         shift(@$types);

         $type = ($type =~ /column/i) ? 'column_info' : ($type =~ /primary/i) ? 'primary_key_info' : 'statistics_info';
         
         snmp_process_indexes($dbh, @tobj) || return [];
         foreach my $t (sort { $a->{name} cmp $b->{name} } sort { $a->{mibname} cmp $b->{mibname} } @tobj) {  # grabbing it here, so that shared keys can still get the real table
            my ($schema, $table) = map { $t->{$_} } qw(mibname name);
            my $tbl = $t->{data};
            my $is_full = !$column || $column eq '%';  # is this a full "%" column pull, or a filtered one?
            
            if (scalar @{$t->{$type}} && $is_full && !$loose) {  # already cached that table's data
               push @dbi_data, @{$t->{$type}};
               next;
            }
            
            unless ($loose || !$is_full) {
               $t->{column_info}      = [];
               $t->{primary_key_info} = [];
               $t->{statistics_info}  = [];
            }
            foreach my $ord_pos (1 .. @{$t->{cols}}) {
               my $c = $t->{cols}[$ord_pos-1];
               my ($col, $colname) = map { $c->{$_} } qw(data name);
               next unless scalar grep { $_->{name} eq $colname } @cobj;
               
               # XXX: a dirty first, since $_ is being used by given/when...
               my $ti = (grep { $_->[0] eq $col->{syntax} } @$types)[0];
               $ti  ||= (grep { $_->[0] eq $col->{type}   } @$types)[0];
               
               my $is_key  = $t->{key}{$colname};
               my $is_null = $is_key ? 0 : $ti->[6];

               $c->{column_info} //= [
                  # 0=TABLE_CAT TABLE_SCHEM TABLE_NAME COLUMN_NAME DATA_TYPE TYPE_NAME COLUMN_SIZE BUFFER_LENGTH DECIMAL_DIGITS
                  undef, $schema, $table, $colname, $ti->[0], $col->{syntax}, $ti->[2], undef, $ti->[17] ? int($ti->[14] * log($ti->[17])/log(10)) : undef,  # log(r^l) = l * log(r)
                  # 9=NUM_PREC_RADIX NULLABLE REMARKS COLUMN_DEF SQL_DATA_TYPE SQL_DATETIME_SUB CHAR_OCTET_LENGTH ORDINAL_POSITION IS_NULLABLE
                  $ti->[17], $is_null, despace($col->{description}), undef, $ti->[15], $ti->[16], $ti->[17] ? undef : $ti->[2], $ord_pos, $is_null ? 'YES' : 'NO',
                  # 18=CHAR_SET_CAT CHAR_SET_SCHEM CHAR_SET_NAME COLLATION_CAT COLLATION_SCHEM COLLATION_NAME UDT_CAT UDT_SCHEM UDT_NAME
                  undef, undef, undef, undef, undef, undef, undef, undef, undef,
                  # DOMAIN_CAT DOMAIN_SCHEM DOMAIN_NAME SCOPE_CAT SCOPE_SCHEM SCOPE_NAME MAX_CARDINALITY DTD_IDENTIFIER IS_SELF_REF
                  undef, undef, undef, undef, undef, undef, undef, undef, undef,
               ];
               push @{$t->{column_info}}, $c->{column_info} unless ($loose || !$is_full);
                  
               if ($is_key && $is_full && !$loose) {
                  $c->{primary_key_info} //= [
                     # TABLE_CAT TABLE_SCHEM TABLE_NAME COLUMN_NAME KEY_SEQ PK_NAME
                     undef, $schema, $table, $colname, $ord_pos, $table.'_pk'
                  ];
                  push @{$t->{primary_key_info}}, $c->{primary_key_info};

                  $c->{statistics_info} //= [
                     # TABLE_CAT TABLE_SCHEM TABLE_NAME NON_UNIQUE INDEX_QUALIFIER INDEX_NAME TYPE ORDINAL_POSITION
                     # COLUMN_NAME ASC_OR_DESC CARDINALITY PAGES FILTER_CONDITION
                     undef, $schema, $table, 0, undef, $table.'_pk', 'btree', $ord_pos,
                     $colname, 'A', undef, undef, undef
                  ];
                  push @{$t->{statistics_info}}, $c->{statistics_info};
                  
                  push @dbi_data, $c->{$type};
               }
               elsif ($type =~ /column/i) { push @dbi_data, $c->{column_info}; }
            }
            next if ($loose || !$is_full);
            next if ($t->{table_type} eq 'VIEW');  # can't have a non-hostid index for a global table
            
            # add non-hostid index
            my $index = dclone($t->{statistics_info});
            push @{$t->{statistics_info}}, (map {
               $_->[3] = 1;                     # NON_UNIQUE
               $_->[5] = $table.'_snmp_index';  # INDEX_NAME
               $_->[7]--;                       # ORDINAL_POSITION
               $_;
            } grep { $_->[7] > 1 } @$index);
            @dbi_data = @{$t->{statistics_info}} if ($type =~ /statistics/i);
         }
      }
      when (/foreign/i) { die "Cannot query for foreign key info here"; }
      default { die "Wrong type '$type'"; }
   }
   
   ### FIXME: Make sure the order is correct (according to DBI) ###

   return \@dbi_data;
}

sub sql_wildcard_re {
   my $v = quotemeta($_[0]);
   $v =~ s/(?<!\\\\)_/./g;
   $v =~ s/(?<!\\\\)\\\%/.*/g;  # pre-escaped by quotemeta, so \% is a wildcard and \\\% is a real percentage
   $v =~ s/\\\\_/_/g;
   $v =~ s/\\\\\\\%/\\\%/g;
   $v =~ s/\\\\\\\\/\\\\/g;     # slashy hell... escaping via s///->quotemeta->user input = 8 slashs for one real slash
   return $v;
}

sub despace {
   my $v = $_[0];
   $v =~ s/\r//g;
   
   my $min = 9999;
   while ($v =~ /\n(\s+)/gc) { my $l = length($1); $min = $l if ($l < $min); }  # find the minimum offset
   return $v if ($min == 9999);
   
   $v =~ s/\n\s{$min}/\n/g;
   return $v;
}

sub table_info {
   my ($dbh, $catalog, $schema, $table) = @_;
   my $type = 'TABLE_INFO';
   
   return sponge_sth_loader(
      $dbh,
      $type, 
      [qw( TABLE_CAT TABLE_SCHEM TABLE_NAME TABLE_TYPE REMARKS )],
      snmp_info_reference($dbh, $type, $schema, $table),
   );
}

sub column_info {
   my ($dbh, $catalog, $schema, $table, $column) = @_;
   my $type = 'COLUMN_INFO';

   return sponge_sth_loader(
      $dbh,
      $type,
      [qw(
         TABLE_CAT TABLE_SCHEM TABLE_NAME COLUMN_NAME DATA_TYPE TYPE_NAME COLUMN_SIZE BUFFER_LENGTH DECIMAL_DIGITS
         NUM_PREC_RADIX NULLABLE REMARKS COLUMN_DEF SQL_DATA_TYPE SQL_DATETIME_SUB CHAR_OCTET_LENGTH ORDINAL_POSITION IS_NULLABLE
         CHAR_SET_CAT CHAR_SET_SCHEM CHAR_SET_NAME COLLATION_CAT COLLATION_SCHEM COLLATION_NAME UDT_CAT UDT_SCHEM UDT_NAME
         DOMAIN_CAT DOMAIN_SCHEM DOMAIN_NAME SCOPE_CAT SCOPE_SCHEM SCOPE_NAME MAX_CARDINALITY DTD_IDENTIFIER IS_SELF_REF
      )],
      snmp_info_reference($dbh, $type, $schema, $table, $column),
   );

}

sub primary_key_info {
   my ($dbh, $catalog, $schema, $table) = @_;
   my $type = 'PRIMARY_KEY_INFO';

   return sponge_sth_loader(
      $dbh,
      $type,
      [qw( TABLE_CAT TABLE_SCHEM TABLE_NAME COLUMN_NAME KEY_SEQ PK_NAME )],
      snmp_info_reference($dbh, $type, $schema, $table),
   );
}

sub foreign_key_info {
   my ($dbh, $pk_catalog, $pk_schema, $pk_table, $fk_catalog, $fk_schema, $fk_table) = @_;
   my $type = 'FOREIGN_KEY_INFO';
   my $names = [qw(
      PKTABLE_CAT PKTABLE_SCHEM PKTABLE_NAME PKCOLUMN_NAME FKTABLE_CAT FKTABLE_SCHEM FKTABLE_NAME FKCOLUMN_NAME
      KEY_SEQ UPDATE_RULE DELETE_RULE FK_NAME PK_NAME DEFERRABILITY UNIQUE_OR_PRIMARY
   )];

   # Need to process the entire indexes list at this point (speed hit be damned)
   state $indexesLoaded = $dbh->{snmp_load_all};
   snmp_process_indexes($dbh, values %{$snmp_specs->{Full}{tbl}}) unless ($indexesLoaded);
   $dbh->{snmp_load_all} = $indexesLoaded = 1;
   
   my $pkt = $pk_table && snmp_info_reference($dbh, 'primary', $pk_schema, $pk_table);
   my $fkt = $fk_table && snmp_info_reference($dbh, 'primary', $fk_schema, $fk_table);
   my ($pk_list, $fk_list) = ([$pkt], [$fkt]);
   my $fc_names_list = [];
   my @dbi_data;

   # find the common prefix 
   my $ft = $snmp_specs->{Full}{tbl}{$fkt->[0][1].'.'.$fkt->[0][2]} || return sponge_sth_loader($dbh, $type, $names, []);
   my @fnames = sort map { $_->{name} } grep { $_->{type} ne 'key' } (@{$ft->{cols}}, $ft);
   my %lcss_cnt;
   for my $n1 (0 .. @fnames-1) {
      for my $n2 ($n1+1 .. @fnames-1) {
         $lcss_cnt{$_->[0]}++ for (grep { $_->[1]+$_->[2] == 0 } lcss_all($fnames[$n1], $fnames[$n2], 2));
      }
   }
   pop @fnames;  # remove table name
   # most popular string, with shortest length in case of tie-breakers
   my $lcss = (sort { $lcss_cnt{$b} <=> $lcss_cnt{$a} } sort { length($a) <=> length($b) } keys %lcss_cnt)[0];
   
   # If both PKT and FKT are given, the function returns the foreign key, if any,
   # in table FKT that refers to the primary (unique) key of table PKT.
   if ($pkt && $fkt) {
      # nothing; everything is already set up as ([$pkt], [$fkt])
   }
   # If only PKT is given, then the result set contains the primary key of that table
   # and all foreign keys that refer to it.
   elsif ($pkt) {
      # first, look for any tables with that first column name
      ### FIXME: The first column name is dbi_hostid, so this will grab everything... ###
      my $tbl_list = snmp_info_reference($dbh, 'column', undef, undef, $pkt->[0][3]);
      
      # second, grab all of the primary keys for those tables
      $fk_list = [ map { snmp_info_reference($dbh, 'primary', $_->[1], $_->[2]) } @$tbl_list ];
   }
   # If only FKT is given, then the result set contains all foreign keys in that table
   # and the primary keys to which they refer.
   elsif ($fkt) {
      # for the keys, easiest way is to check keys in snmp_specs and the tbl objects that
      # point differently
      my $k = $ft->{keys};
      
      $pk_list = [
         map { snmp_info_reference($dbh, 'primary', $_->{tbl}{mibname}, $_->{tbl}{name}) }
         grep { $_->{tbl} != $ft }  # object comparison should be enough
         @$k
      ];
      
      # for the columns, this is a more difficult task, as SNMP has its unique name
      # constraint; so truncate the common column name and hope it matches to a key
      # (like prefixBlahBlahBlahIfIndex)
      
      $fc_names_list->[0] = {};
      foreach my $name (@fnames) {
         my $fname = $name;
         $fname = s/^$lcss//;

         my $csir = snmp_info_reference($dbh, 'column', undef, undef, $fname);
         next unless (@$csir);
         
         my $c = $snmp_specs->{Full}{col}{ $csir->[0][1].'.'.$csir->[0][3] } || next;
         next unless ($c->{type} eq 'key');
         
         $fc_names_list->[0]{ $csir->[0][3] } = $name;
         push @$pk_list, snmp_info_reference($dbh, 'primary', $c->{tbl}{mibname}, $c->{tbl}{name});
      }   
   }
   else { return sponge_sth_loader($dbh, $type, $names, []); }

   # main loop
   foreach my $pk (@$pk_list) {
      my @pkey = map { $_->[3] } @$pk;
      $pkey[0] = 'dbi_hostid' if ($pkey[0] eq 'hostid');

      for my $i (0 .. @$fk_list-1) {
         my $fk = $fk_list->[$i];
         my $fcnl = $fc_names_list->[$i];
      
         # part of the foreign key must match all of the primary key
         my @fkey = foundin( [@pkey], [ (map { $_->[3] } @$fk), (keys %$fcnl) ] );
         
         next unless (scalar @pkey == scalar @fkey);
         next if (@fkey == 1 && $pk->[0][1] ne 'dbi_snmp');  # every table shouldn't relate to every global table
         
         my $is_col = scalar @{ foundin( [ keys %$fcnl ], [ @fkey ] ) };
         my $fkey_name = $pk->[0][2].'_fkey_for_'.$fk->[0][2];

         for my $r (0 .. @$pk-1) {
            my ($p, $f) = ($pk->[$r], $fk->[0]);
            my $fname = $is_col ? $fcnl->{$p->[3]} : $p->[3];
            $fname = 'dbi_hostid' if ($fname eq 'hostid' && $f->[1] ne 'dbi_snmp');
            
            push @dbi_data, [
               # 0=PKTABLE_CAT PKTABLE_SCHEM PKTABLE_NAME PKCOLUMN_NAME FKTABLE_CAT FKTABLE_SCHEM FKTABLE_NAME FKCOLUMN_NAME
               @$p[0 .. 3], @$f[0 .. 2], $fname,
               # 8=KEY_SEQ UPDATE_RULE DELETE_RULE FK_NAME PK_NAME DEFERRABILITY UNIQUE_OR_PRIMARY
               $r+1, 3, 3, $fkey_name, $p->[5], 7, 'PRIMARY',
            ];
         }
      }

   }
   
   return sponge_sth_loader($dbh, $type, $names, \@dbi_data);
}

sub statistics_info {
   my ($dbh, $catalog, $schema, $table, $unique_only, $quick) = @_;
   my $type = 'STATISTICS_INFO';
   my $u = $unique_only ? 0 : 1;

   return sponge_sth_loader(
      $dbh,
      $type,
      [qw(
         TABLE_CAT TABLE_SCHEM TABLE_NAME NON_UNIQUE INDEX_QUALIFIER INDEX_NAME TYPE ORDINAL_POSITION
         COLUMN_NAME ASC_OR_DESC CARDINALITY PAGES FILTER_CONDITION
      )],
      [ grep { $_->[3] <= $u } @{snmp_info_reference($dbh, $type, $schema, $table)} ],
   );
}

# Oddly enough, table_info has a separate sub for this, but not the others
sub sponge_sth_loader {
   my ($dbh, $tbl_name, $names, $rows) = @_;

   # (mostly a straight copy from DBI::DBD::SqlEngine)
   my $dbh2 = $dbh->func("sql_sponge_driver");
   my $sth = $dbh2->prepare(
                            $tbl_name,
                            {
                               rows => $rows || [],
                               NAME => $names,
                            }
                          );
   $sth or $dbh->set_err( $DBI::stderr, $dbh2->errstr, $dbh2->state );
   return $sth;
}

sub STORE {
   my ($dbh, $attr, $val) = @_;
   if ($attr eq 'AutoCommit') {
      die "Can't disable AutoCommit: Protocol does not support transactions!" unless ($val);
      return 1;
   }
   if ($attr =~ m/^snmp_/) {
      # Handle only our private attributes here
      # Note that we could trigger arbitrary actions.
      # Ideally we should warn about unknown attributes.
      $dbh->{$attr} = $val; # Yes, we are allowed to do this,
      return 1;             # but only for our private attributes
   }
   # Else pass up to DBI to handle for us
   $dbh->SUPER::STORE($attr, $val);
}

sub FETCH {
   my ($dbh, $attr) = @_;
   return 1 if ($attr eq 'AutoCommit');
   if ($attr =~ m/^snmp_/) {
      # Handle only our private attributes here
      # Note that we could trigger arbitrary actions.
      return $dbh->{$attr}; # Yes, we are allowed to do this,
                            # but only for our private attributes
   }
   # Else pass up to DBI to handle
   $dbh->SUPER::FETCH($attr);
}

sub commit {
   my ($dbh) = @_;
   $dbh->FETCH('Warn') && warn("Commit ineffective: SNMP doesn't support transactions");
   return undef;
}

sub rollback {
   my ($dbh) = @_;
   $dbh->FETCH('Warn') && warn("Rollback ineffective: SNMP doesn't support transactions");
   return undef;
}

sub type_info_all ($) {
   ### TODO: Add a new SQL Type for every discovered syntax...
   ### (It may be a descent into madness, but it would at least
   ### capture the type, limits, description, and other such things)
   
   return [
      {
         TYPE_NAME          => 0,
         DATA_TYPE          => 1,
         PRECISION          => 2,
         LITERAL_PREFIX     => 3,
         LITERAL_SUFFIX     => 4,
         CREATE_PARAMS      => 5,
         NULLABLE           => 6,
         CASE_SENSITIVE     => 7,
         SEARCHABLE         => 8,
         UNSIGNED_ATTRIBUTE => 9,
         FIXED_PREC_SCALE   => 10,
         AUTO_UNIQUE_VALUE  => 11,
         LOCAL_TYPE_NAME    => 12,
         MINIMUM_SCALE      => 13,
         MAXIMUM_SCALE      => 14,
         SQL_DATA_TYPE      => 15,
         SQL_DATETIME_SUB   => 16,
         NUM_PREC_RADIX     => 17,
         INTERVAL_PRECISION => 18,
      },
      # Name         DataType            Max    Literals      Params         Null   Case Search Unsign  Fixed  Auto   LocalTypeName   M/M Scale     SQLDataType         DateTime_Sub  Radix  ItvPrec
      [ "OBJECTID",  DBI::SQL_VARCHAR(),  1408,   "'",   "'",        undef,     1,     0,     3, undef,     0, undef,     "ObjectID", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      [ "OCTETSTR",  DBI::SQL_VARCHAR(), 65536,   "'",   "'", "max length",     1,     1,     3, undef,     0, undef, "Octet String", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      [ "INTEGER",   DBI::SQL_INTEGER(),    32, undef, undef,  "precision",     1,     0,     2,     0,     0,     0,      "Integer",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
      [ "INTEGER32", DBI::SQL_INTEGER(),    32, undef, undef,  "precision",     1,     0,     2,     0,     0,     0,      "Integer",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
      [ "NETADDR",   DBI::SQL_VARCHAR(),    15,   "'",   "'",        undef,     1,     0,     3, undef,     0, undef,   "NetAddress", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      [ "IPADDR",    DBI::SQL_VARCHAR(),    15,   "'",   "'",        undef,     1,     0,     3, undef,     0, undef,    "IPAddress", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      [ "COUNTER",   DBI::SQL_INTEGER(),    32, undef, undef,        undef,     1,     0,     2,     1,     0,     0,    "Counter32",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
      [ "COUNTER64", DBI::SQL_INTEGER(),    64, undef, undef,        undef,     1,     0,     2,     1,     0,     0,    "Counter64",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
      [ "GAUGE",     DBI::SQL_INTEGER(),    32, undef, undef,        undef,     1,     0,     2,     1,     0,     0,      "Gauge32",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
      [ "GAUGE64",   DBI::SQL_INTEGER(),    64, undef, undef,        undef,     1,     0,     2,     1,     0,     0,      "Gauge64",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
      [ "TICKS",     DBI::SQL_INTERVAL_SECOND(),32,undef,undef,      undef,     1,     0,     2,     1,     1,     0,    "TimeTicks",     2,     2, DBI::SQL_INTERVAL(),DBI::SQL_INTERVAL_SECOND(),2,undef],
      [ "TIMETICKS", DBI::SQL_INTERVAL_SECOND(),32,undef,undef,      undef,     1,     0,     2,     1,     1,     0,    "TimeTicks",     2,     2, DBI::SQL_INTERVAL(),DBI::SQL_INTERVAL_SECOND(),2,undef],
      [ "OPAQUE",    DBI::SQL_VARCHAR(), 65536,   "'",   "'", "max length",     1,     1,     3, undef,     0, undef,       "Opaque", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      [ "BITS",      DBI::SQL_INTEGER(),    32, undef, undef,        undef,     1,     0,     2,     1,     1,     0,         "Bits",     0,     0, DBI::SQL_INTERVAL(),       undef,     2, undef],

      [ "Gauge",     DBI::SQL_INTEGER(),    32, undef, undef,        undef,     1,     0,     2,     1,     0,     0,      "Gauge32",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
      [ "Gauge32",   DBI::SQL_INTEGER(),    32, undef, undef,        undef,     1,     0,     2,     1,     0,     0,      "Gauge32",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
      [ "Gauge64",   DBI::SQL_INTEGER(),    64, undef, undef,        undef,     1,     0,     2,     1,     0,     0,      "Gauge64",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],

      [ "Counter",   DBI::SQL_INTEGER(),    32, undef, undef,        undef,     1,     0,     2,     1,     0,     0,    "Counter32",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
      [ "Counter32", DBI::SQL_INTEGER(),    32, undef, undef,        undef,     1,     0,     2,     1,     0,     0,    "Counter32",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
      [ "Counter64", DBI::SQL_INTEGER(),    64, undef, undef,        undef,     1,     0,     2,     1,     0,     0,    "Counter64",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],

      [ "Integer",   DBI::SQL_INTEGER(),    32, undef, undef,  "precision",     1,     0,     2,     0,     0,     0,      "Integer",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
      [ "Integer32", DBI::SQL_INTEGER(),    32, undef, undef,  "precision",     1,     0,     2,     0,     0,     0,      "Integer",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
      [ "Unsigned32",DBI::SQL_INTEGER(),    32, undef, undef,        undef,     1,     0,     2,     1,     0,     0,   "Unsigned32",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],

      ["InetAddress",DBI::SQL_VARCHAR(),  1024,   "'",   "'",        undef,     1,     0,     3, undef,     0, undef,  "InetAddress", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      ["InetAddressIPv4",DBI::SQL_VARCHAR(),15,   "'",   "'",        undef,     1,     0,     3, undef,     0, undef,  "IPv4Address", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      ["InetAddressIPv6",DBI::SQL_VARCHAR(),39,   "'",   "'",        undef,     1,     0,     3, undef,     0, undef,  "IPv6Address", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      ["IpV4orV6Addr",DBI::SQL_VARCHAR(),   39,   "'",   "'",        undef,     1,     0,     3, undef,     0, undef,"IPv4/6Address", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      ["Ipv6AddressIfIdentifierTC",DBI::SQL_VARCHAR(),39,"'","'",    undef,     1,     0,     3, undef,     0, undef, "IP6AddrIfITC", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],

      [ "TimeTicks", DBI::SQL_INTERVAL_SECOND(),32,undef,undef,      undef,     1,     0,     2,     1,     1,     0,    "TimeTicks",     2,     2, DBI::SQL_INTERVAL(),DBI::SQL_INTERVAL_SECOND(),2,undef],
      
      ["DisplayString",DBI::SQL_VARCHAR(), 255,   "'",   "'",        undef,     1,     1,     3, undef,     0, undef,"DisplayString", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      ["PhysAddress",DBI::SQL_VARCHAR(), 65536,   "'",   "'", "max length",     1,     0,     3, undef,     0, undef,  "PhysAddress", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      ["MacAddress", DBI::SQL_CHAR(),       17,   "'",   "'",        undef,     1,     0,     3, undef,     1, undef,   "MacAddress", undef, undef, DBI::SQL_CHAR(),           undef, undef, undef],
      ["BridgeId",   DBI::SQL_VARCHAR(),    23,   "'",   "'",        undef,     1,     0,     3, undef,     0, undef,     "BridgeId", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      ["TruthValue", DBI::SQL_BOOLEAN(),     1, undef, undef,        undef,     1,     0,     2,     1,     1,     0,   "TruthValue",     0,     0, DBI::SQL_BOOLEAN(),        undef,     2, undef],

      ["TestAndIncr",DBI::SQL_INTEGER(),    32, undef, undef,        undef,     1,     0,     2,     1,     1,     0,  "TestAndIncr",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
      ["AutonomousType",DBI::SQL_VARCHAR(),1408,  "'",   "'",        undef,     1,     0,     3, undef,     1, undef,"AutonomousType",undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      ["InstancePointer",DBI::SQL_VARCHAR(),1408, "'",   "'",        undef,     1,     0,     3, undef,     1, undef,"InstancePointer",undef,undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      ["VariablePointer",DBI::SQL_VARCHAR(),1408, "'",   "'",        undef,     1,     0,     3, undef,     1, undef,"VariablePointer",undef,undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      ["RowPointer", DBI::SQL_VARCHAR(),  1408,   "'",   "'",        undef,     1,     0,     3, undef,     1, undef,   "RowPointer", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      [ "RowStatus", DBI::SQL_INTEGER(),     4, undef, undef,        undef,     1,     0,     2,     1,     1,     0,    "RowStatus",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],

      [ "TimeStamp", DBI::SQL_INTERVAL_SECOND(),32,undef,undef,      undef,     1,     0,     2,     1,     1,     0,    "TimeStamp",     2,     2, DBI::SQL_INTERVAL(),DBI::SQL_INTERVAL_SECOND(),2,undef],
      ["TimeInterval",DBI::SQL_INTERVAL_SECOND(),31,undef,undef,     undef,     1,     0,     2,     1,     1,     0, "TimeInterval",     2,     2, DBI::SQL_INTERVAL(),DBI::SQL_INTERVAL_SECOND(),2,undef],
      ["DateAndTime",DBI::SQL_TIMESTAMP(),  30, undef, undef,        undef,     1,     0,     2,     1,     1,     0,  "DateAndTime",     1,     1, DBI::SQL_DATETIME(),DBI::SQL_TYPE_TIMESTAMP(),undef,undef],

      ["StorageType", DBI::SQL_INTEGER(),    4, undef, undef,        undef,     1,     0,     2,     1,     1,     0,  "StorageType",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
      ["TDomain",    DBI::SQL_VARCHAR(),  1408,   "'",   "'",        undef,     1,     0,     3, undef,     1, undef,      "TDomain", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
      ["TAddress",   DBI::SQL_VARCHAR(),   255,   "'",   "'",        undef,     1,     0,     3, undef,     1, undef,     "TAddress", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
   ];
}

# Find items in @B that are in @A
sub foundin (\@\@) { my ($A, $B) = @_; return grep { my $i = $_; any  { $i eq $_ } @$A; } @$B; }
# Find items in @B that are not in @A
sub notin   (\@\@) { my ($A, $B) = @_; return grep { my $i = $_; none { $i eq $_ } @$A; } @$B; }

1;

##############################################################################
# DBD::SNMP::st

package   # hide from PAUSE
   DBD::SNMP::st;
$DBD::SNMP::st::imp_data_size = 0;

use common::sense;  # works every time!

require DBI::DBD::SqlEngine;
use parent qw(-norequire DBI::DBD::SqlEngine::st);

1;

##############################################################################
# DBD::SNMP::Statement

package   # hide from PAUSE
   DBD::SNMP::Statement;

use common::sense;  # works every time!
use DBD::File;
use DBD::SNMP::Table;
use DBD::SNMP::Override;
use parent qw(SQL::Statement);

sub open_table ($$$$$) {
   my ($self, $sth, $table, $createMode, $lockMode) = @_;

   # enforce proper capitalization (even though we probably don't need it)
   $table = index($table, '"') == -1 ? lc $table : $table;
   $table =~ s/"//g;
   
   my $class = ref $self;
   $class =~ s/::Statement/::Table/;
   
   return $class->new($sth, $table, $createMode, $lockMode);
}

1;

##############################################################################
# DBD::SNMP::GetInfo

package   # hide from PAUSE
   DBD::SNMP::GetInfo;

use common::sense;  # works every time!
use parent qw(SQL::Statement::GetInfo);

sub sql_keywords {
   return join(',', keys %{ SQL::Dialects::SNMP::get_config_as_hash()->{reserved_words} });
}

# GetInfo key adjustments
use DBI::Const::GetInfo::ODBC;  # The API for this module is private and subject to change.
   # (Yes, I know, but it hasn't, and it's really handy...)

# More details on these variables here: 
#   http://msdn.microsoft.com/en-us/library/ms711681.aspx
#   http://vieka.com/esqldoc/esqlref/htm/odbcsqlgetinfo.htm
   
my %r = %DBI::Const::GetInfo::ODBC::ReturnValues;
my %i = %DBI::Const::GetInfo::ODBC::InfoTypes;
our %info;
*info = *SQL::Statement::GetInfo::info;

# FIXME: This should actually be in SQL::Statement::GetInfo
$info{ $i{SQL_CREATE_TABLE} }             = $r{SQL_CT_CREATE_TABLE} + $r{SQL_CT_COMMIT_DELETE} + $r{SQL_CT_LOCAL_TEMPORARY};
$info{ $i{SQL_COLUMN_ALIAS} }             = 'Y';
$info{ $i{SQL_SQL92_DATETIME_FUNCTIONS} } = $r{SQL_SDF_CURRENT_DATE} + $r{SQL_SDF_CURRENT_TIME} + $r{SQL_SDF_CURRENT_TIMESTAMP};
$info{ $i{SQL_NUMERIC_FUNCTIONS} }        = 0x00ffffff;  # all of them!
$info{ $i{SQL_SQL92_NUMERIC_VALUE_FUNCTIONS} } = $r{SQL_SNVF_BIT_LENGTH} + $r{SQL_SNVF_CHAR_LENGTH} + $r{SQL_SNVF_CHARACTER_LENGTH} + $r{SQL_SNVF_OCTET_LENGTH} + $r{SQL_SNVF_POSITION};  # (only missing EXTRACT)
$info{ $i{SQL_SQL92_STRING_FUNCTIONS} }   = 0x000000fe;  # (now with TRANSLATE support; only missing CONVERT here)
$info{ $i{SQL_STRING_FUNCTIONS} }         = 0x00ff7fff;  # (only missing DIFFERENCE)
$info{ $i{SQL_SYSTEM_FUNCTIONS} }         = $r{SQL_FN_SYS_DBNAME} + $r{SQL_FN_SYS_IFNULL} + $r{SQL_FN_SYS_USERNAME};

$info{ $i{SQL_ASYNC_MODE} }             = $r{SQL_AM_CONNECTION};  # though, technically, everything is forced as async
$info{ $i{SQL_DATA_SOURCE_READ_ONLY} }  = 'Y';  # for the time being, will change later
$info{ $i{SQL_FILE_USAGE} }             = $r{SQL_FILE_NOT_SUPPORTED};
$info{ $i{SQL_MULTIPLE_ACTIVE_TXN} }    = 'Y';

# RFC2578: OCTET STRING (SIZE (0..65535))
$info{ $i{SQL_MAX_BINARY_LITERAL_LEN} } = 65536;
$info{ $i{SQL_MAX_CHAR_LITERAL_LEN} }   = 65536;
#$info{ $i{SQL_MAX_SCHEMA_NAME_LEN} }   = ???;   # Don't think there's a max MIB name length...
$info{ $i{SQL_MAX_TABLE_NAME_LEN} }     = 768;   # XXX: This needs RFC confirmation
$info{ $i{SQL_MAX_COLUMN_NAME_LEN} }    = 768;   # XXX: This needs RFC confirmation
# RFC2574: msgUserName OCTET STRING (SIZE(0..32)),
$info{ $i{SQL_MAX_USER_NAME_LEN} }      = 32;
# RFC1905: SNMPv2 limits OBJECT IDENTIFIER values to a maximum of 128 sub-identifiers, where each sub-identifier has a
# maximum value of 2**32-1.
$info{ $i{SQL_MAX_COLUMNS_IN_INDEX} }  = 128;
$info{ $i{SQL_MAX_INDEX_SIZE} }        = 128 * 10;

$info{ $i{SQL_SCHEMA_TERM} }           = 'MIB';
$info{ $i{SQL_SCHEMA_USAGE} }          = $r{SQL_SU_DML_STATEMENTS} + $r{SQL_SU_TABLE_DEFINITION};

1;

##############################################################################
# SQL::Dialects::SNMP

package   # hide from PAUSE
   SQL::Dialects::SNMP;

our $VERSION = '1.00';

use parent qw(SQL::Dialects::Role);

sub get_config {
   return <<EOC;
[VALID COMMANDS]
CREATE
DROP
SELECT
DELETE
INSERT
UPDATE

[VALID OPTIONS]
SELECT_MULTIPLE_TABLES
SELECT_AGGREGATE_FUNCTIONS

[VALID COMPARISON OPERATORS]
=
<>
<
<=
>
>=
LIKE
NOT LIKE
CLIKE
NOT CLIKE
RLIKE
NOT RLIKE
IS
IS NOT
IN
NOT IN
BETWEEN
NOT BETWEEN

[VALID DATA TYPES]
OBJECTID
OCTETSTR
INTEGER
INTEGER32
NETADDR
IPADDR
COUNTER
COUNTER64
GAUGE
GAUGE64
TIMETICKS
OPAQUE
Gauge  
Gauge32
Gauge64
Counter
Counter32
Counter64
Integer
Integer32
Unsigned32
TimeTicks
DisplayString
PhysAddress
MacAddress
TruthValue
TestAndIncr
AutonomousType
InstancePointer
VariablePointer
RowPointer
RowStatus
TimeStamp
TimeInterval
DateAndTime
StorageType
TDomain 
TAddress

[RESERVED WORDS]
INTEGERVAL
STRING
REALVAL
IDENT
NULLVAL
PARAM
OPERATOR
IS
AND
OR
ERROR
INSERT
UPDATE
SELECT
DELETE
DROP
CREATE
ALL
DISTINCT
WHERE
ORDER
ASC
DESC
FROM
INTO
BY
VALUES
SET
NOT
TABLE
OBJECTID
OCTETSTR
INTEGER
INTEGER32
NETADDR
IPADDR
COUNTER
COUNTER64
GAUGE
GAUGE64
TIMETICKS
OPAQUE
Gauge  
Gauge32
Gauge64
Counter
Counter32
Counter64
Integer
Integer32
Unsigned32
TimeTicks
DisplayString
PhysAddress
MacAddress
TruthValue
TestAndIncr
AutonomousType
InstancePointer
VariablePointer
RowPointer
RowStatus
TimeStamp
TimeInterval
DateAndTime
StorageType
TDomain 
TAddress
EOC
}

1;

=pod

=head1 NAME

SQL::Dialects::SNMP

=head1 SYNOPSIS

  use SQL::Dialects::SNMP;
  $config = SQL::Dialects::SNMP->get_config();

=head1 DESCRIPTION

This package provides the necessary configuration for SNMP SQL.

=head1 FUNCTIONS

=head2 get_config

Returns the configuration for SNMP SQL. The configuration is delivered in
ini-style:

  [VALID COMMANDS]
  ...

  [VALID OPTIONS]
  ...

  [VALID COMPARISON OPERATORS]
  ...

  [VALID DATA TYPES]
  ...

  [RESERVED WORDS]
  ...

=cut