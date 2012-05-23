##############################################################################
# DBD::SNMP::Table Module                                                    #
# E-mail: Brendan Byrd <Perl@resonatorsoft.org>                              #
##############################################################################

##############################################################################
# DBD::SNMP::Table (SQL::Eval API)

package   # hide from PAUSE
   DBD::SNMP::Table;

use sanity;
use warnings 'all';
use Net::SNMP;
use DBD::SNMP::Override;
use DBD::SNMP::Helpers qw(:all);
BEGIN { eval 'use Net::SNMP::XS;'; }  # use it if we got it
use List::Util qw(first);
use SQL::Eval;
use Time::HiRes qw(time);

use parent qw(-norequire SQL::Eval::Table);

sub new {
   my ($proto, $sth, $table, $createMode, $lockMode) = @_;

   # weirdness with early blessing needed to pass a prior $self object to Net::SNMP's callbacks
   my $class = ref $proto || $proto;
   my $self  = bless(ref $proto ? {%$proto} : {}, $class);
   
   my $dbh  = $sth->{Database};
   my $stmt = $sth->{sql_stmt};
   my $t    = $stmt->{tables_by_name}{$table} || $stmt->{tables_by_name}{lc $table};  ### FIXME: Test if name is exactly what is in key

   # SQL::Statement can get tripped up on quotes around RAM tables
   if ($t->{snmp_specs}{table_type} =~ /^SYSTEM TABLE$|^LOCAL TEMPORARY$/) {
      $table =~ s/^\w+\.//;
      my $ram_tbl = $dbh->{sql_ram_tables}{$table};
      $ram_tbl->seek($sth, 0, 0);
      $ram_tbl->init_table($sth, $table, $createMode, $lockMode) if ($ram_tbl->can('init_table'));
      return $ram_tbl;
   }
   
   # self additions
   $self->{table_obj} = $t;
   $self->{sth}       = $sth;
   
   # Make sure the $createMode/$lockMode is logical
   $createMode and  # if we're here and it's asking for table creation, it's already illegal
      return $dbh->set_err($DBI::stderr, "Cannot create a SNMP table", '0A502');
   ### FIXME ###
   $lockMode and
      return $dbh->set_err($DBI::stderr, "Write operations currently not supported yet!", '0A502');   

   ##############
   ### SELECT ###
   ##############
   
   my $keys    = $t->{snmp_specs}{keys};
   my $rng_col = $t->{stmt_key_rng_col};
   my $rcv     = $rng_col && $t->{stmt_key_vals}{ lc($rng_col->{snmp_specs}{name}) };
   my @opts;
   my $is_req = 0;

   ($self->{IndexRegEx}) = snmp_index2regex($keys->[1]{data}{objectID});  # $keys->[0] is always dbi_hostid

   # Create $index
   my $i = 1;
   my @index;
   for (@$keys) {
      $i++ <= $t->{stmt_key_count} ? 
         push( @index, $t->{stmt_key_vals}{ lc($_->{snmp_specs}{name}) }->value() )
      : last;
   }
   my $index = @index ? '.'.join('.', map { snmp_transform('ASCII', $_); } @index) : '';
   
   # Normally, keys are removed from the OIDs (as _cache_tbl_row will extract them from the result OID, anyway)...
   my @oids  = map { $_->{snmp_specs}{data}{objectID}.$index } grep { $_->{snmp_specs}{data}{objectID} && !$_->{is_key} } @{$t->{stmt_cols}};
   # However, if there's nothing left, just pick one that exists (with the right permissions)
   unless (@oids) {
      my $obj = first { $_->{data}{objectID} && $_->{data}{access} =~ /Read|Create/ } @{$t->{snmp_specs}{cols}};
      push(@oids, $obj->{data}{objectID}.$index) if ($obj);
   }
   return $dbh->set_err($DBI::stderr, "Table '$table' contains no SNMP readable fields", '01007')
      unless (@oids);

   # Figure out what kind of request to send
   ### TODO: Add partial indexes for OBJECTID, OCTETSTR, NETADDR, IPADDR ###
   given ($t->{stmt_key_abs}) {
      when (-1) {  # Absurd non-true constant condition
         @opts = ();
      }
      when (1) {  # Absolute match on all keys
         @opts = (
            -varbindlist => \@oids,
         );
         $is_req = 1;
         ### Result: get_request on a single row ###
      }
      when (2) {  # IN clause match
         my @new_oids;
         foreach my $v (@$rcv) {
            push(@new_oids, map { $_.'.'.snmp_transform('ASCII', $v->value()) } @oids);
         }

         # take a stab at the cardinality (ie: is this the last key)
         $is_req = ($t->{stmt_key_count} >= scalar(@$keys) - 1);
         
         @opts = $is_req ? (
            -varbindlist => \@new_oids,
         ) : (
            -columns     => \@new_oids,
         );
         ### Result: Either a get_request on a few rows, or get_entries on a few sets of rows ###
      }
      when (3) {  # BETWEEN clause match (or > <= => <)
         # x!! = http://www.perlmonks.org/?node_id=564792
         @opts = (
            -columns      => \@oids, perlop
            ( -startindex => $rcv->{start} + ($rcv->{start_op} =~ /\=/ ? 0 : 1) ) x!! $rcv->{start},
            ( -endindex   => $rcv->{end}   - ($rcv->{end_op}   =~ /\=/ ? 0 : 1) ) x!! $rcv->{end},
         );
         $is_req = 0;
         ### Result: get_entries with a start/end index ###
      }
      default {
         @opts = (
            -columns     => \@oids,
         );
         $is_req = 0;
         ### Result: get_entries, possibly grabbing the whole table (if there aren't any key clauses) ###
      }
   }
   $self->{snmp_oids}  = \@oids;
   $self->{snmp_index} = $index;
   
   # This is a singleton object; might as well grab it here...
   $self->{snmp_dispatcher} //= $Net::SNMP::DISPATCHER;
 
   # Define the reference location before fetch_row or cache_*_row use it, so that
   # they are using the same memory location
   $self->{snmp_data}          = [];
   $self->{snmp_total_queries} = [];  # same here; despite being just a single value
   
   ### FIXME: Support these...
   ###   UPDATE
   ###      set_request - Only on Writable OIDs
   ###         (REQUIRE A WHERE CLAUSE!)
   ###   INSERT
   ###      set_request - Only on RowStatus tables (need some extra logic here)
   ###      inform/trap/v2 - Only on compatible tables (might need to be able to specify)
   ###   DELETE
   ###      set_request - Only on RowStatus tables (need some extra logic here)
   ###         (REQUIRE A WHERE CLAUSE!)

   ### FIXME: We should query the dbi_snmp.hosts table, since the user may have filtered some of the hosts ###
   if (@opts) {
      foreach my $hostid (sort { $a <=> $b } keys %{$dbh->{snmp_sessions}}) {
         my $session = $dbh->{snmp_sessions}{$hostid};

         $is_req ? $session->get_request(
            -callback    => [ \&_cache_req_row, $self, $hostid ],
            @opts,
         )       : $session->get_entries(
            -callback    => [ \&_check_session_errors, $self, $hostid ],
            -rowcallback => [ \&_cache_tbl_row, $self, $hostid ],
            -maxrepetitions => 10,  ### TODO: Make this user configurable ###
            @opts,
         ) or return $dbh->set_err($DBI::stderr,
            "Net::SNMP Error from table request '$table' for host '".$session->hostname()."': ".$session->error(), '08S01');

         $session->debug(1+16+8+4);

         $self->{snmp_total_queries}[0]++;
      }
   }
   
   # Final declarations for SQL::Eval::Table->new
   $self->{col_names}    = [ map { $_->{snmp_specs}{name} } @{$t->{stmt_cols}} ];
   $self->{capabilities} = {
      ### FIXME: Should disable for read-only tables ###
      update_one_row      => 1,
      update_specific_row => 0,
      update_current_row  => 1,
      rowwise_update      => 1,
      inplace_update      => 1,
      ### FIXME: Should disable for non-RowStatus tables ###
      delete_one_row      => 1,
      delete_current_row  => 1,
      rowwise_delete      => 1,
      inplace_delete      => 1,
      ### FIXME: Should disable for non-RowStatus tables ###
      insert_new_row      => 1,
   };
 
   return $self->SUPER::new($self);
}

sub __WARN { 
   say @_;          # actually print, unlike what the eval hides
   CORE::warn(@_);  # let CORE::warn do what it has to do
}
sub __DIE { 
   say @_;   # actually print, unlike what the eval hides
   exit(1);  # really f'ing DIE!
}

sub fetch_row ($) {
   my ($self, $sth) = @_;
   my $t    = $self->{table_obj};
   my $data = $self->{snmp_data};
   my $dbh  = $sth->{Database};

   # eval bypasses; which will spread like an infection to the Net::SNMP callbacks
   local $SIG{__WARN__} = \&__WARN;
   local $SIG{__DIE__}  = \&__DIE;
   
   # (no need for caching a bunch of rows; Net::SNMP::Dispatcher handles transactions well enough)
   ### FIXME: Account for multiple statements ###
   while (!@$data && first { !!$_ } values %{$dbh->{snmp_sessions}} && $self->{snmp_total_queries}[0]) {
      ### XXX: This should probably use some minimum form of $session->timeout ###
      $self->{snmp_dispatcher}->one_event(1);  # one second pulses
   }
   
   # fetch a row from cache and send
   my $row = shift @$data;
   map { $_ =~ s/\s+$//; } @$row if ($sth->FETCH('ChopBlanks'));
   return $self->{row} = $row;  # self undef'ing if EOD
}


######################
# Net::SNMP callbacks

sub _cache_req_row {
   my ($session, $self, $hostid) = @_;
   my $sth = $self->{sth};

   if (defined $session->var_bind_list) {
      my %vbl = %{$session->var_bind_list};
      my @results = map { ($vbl{$_} =~ /^(noSuchInstance|noSuchObject)$/) ? undef : $vbl{$_} } @{$self->{snmp_oids}};
      _cache_tbl_row('0', @results, $self, $hostid);
   }

   return _check_session_errors($session, $self, $hostid);
}

sub _cache_tbl_row {
   # column list comes in after the first passed var, so this gets a little weird
   my ($index, $hostid, $self) = (shift, pop, pop);
   my @results = @_;

   my $t = $self->{table_obj};
   my $sth = $self->{sth};
   my $dbh = $sth->{Database};
   
   my @cols = @{$t->{stmt_cols}};
   return undef unless (@results && defined $index && $self && $sth);
   return undef if     (!scalar(grep { defined $_ && $_ ne '' } @results) && $index eq '0' && scalar(@{$t->{snmp_specs}{keys}}));  # empty table result

   my $re = $self->{IndexRegEx};
   my %index_data;
   if ($index =~ $$re) { %index_data = %+; }
   else {
      $dbh->FETCH('Warn') and $dbh->set_err(0, "WARNING: Index for ".$t->{snmp_specs}{fullname}." didn't match: '$index' =~ /".$$re."/", '42888');
      return undef;
   }

   # (Quickly) Analyze the column data
   my @data;
   foreach my $c (@cols) {
      my $data = $c->{colname} eq 'dbi_hostid' ? $hostid :
                 $c->{is_key}                  ? $index_data{ $c->{snmp_specs}{name} } :
                                                 shift @results;
      
      # column transforms
      $data = snmp_transform($c->{snmp_specs}{column_info}[5], $data);  # based on SQL data type
      
      push(@data, $data);
   }

   push(@{$self->{snmp_data}}, \@data);
   return 1;
}

sub _check_session_errors {
   my ($session, $self, $hostid) = @_;

   $self->{snmp_total_queries}[0]--;

   # Store error message (if there is one)
   unless (defined $session && defined $session->var_bind_list) {
      my $dbh   = $self->{sth}->{Database};
      my $table = $self->{table_obj}{snmp_specs}{fullname};
      
      my $cmd = 'INSERT INTO dbi_snmp.host_errors (hostid, tablename, errormsg, msgtime) VALUES (?, ?, ?, ?)';
      $dbh->do($cmd, undef, 
         $hostid, $table, $session->error(), int(time * 100),
      ) or return $dbh->set_err($DBI::stderr, $dbh->errstr, $dbh->state);

      $dbh->FETCH('Warn') and $dbh->set_err(0, "Net::SNMP Error from table request '$table' for host '".$session->hostname()."': ".$session->error(), '08S01');
      return undef;
   }
   
   ### TODO: Add debug status statements from Collector-SNMP.pl ###
   
   return 1;
}

### ALL OPTIONAL FOR NOW! ###
   
# update_one_row      => 1,
# update_current_row  => 1,
# delete_one_row      => 1,
# delete_current_row  => 1,
# insert_new_row      => 1,
   ### FIXME: Use set_request or inform_request or snmpv2_trap or trap ###
   ### Use INSERT DELAYED for trap vs. inform
   ### Depends on situation ###

sub DESTROY {
   my ($self, $sth) = @_;

   delete $self->{$_} for (keys %$self);
   undef $sth;
   undef $self;
   ### FIXME: What else do I need to clean up here? ###
}

##########################
# Unimplemented functions
   
sub truncate ($$) {
   my ($self, $sth) = @_;

   # Only needed for UPDATE/DELETE when no rowwise/inplace update/delete exists
   
   # Since this is potentially dangerous and has a very limited usefulness,
   # this function is purposely unimplemented

   return $sth->{Database}->set_err($DBI::stderr, "Truncate is not implemented in this driver", '0A502');  # we really shouldn't get this far...
}

sub seek ($$$$) {
   my ($self, $sth, $pos, $whence) = @_;
   
   # 0,0 only needed for UPDATE/DELETE when no rowwise/inplace update/delete exists
   # 0,2 only needed for INSERT when no insert_new_row exists
   
   # Since this would require a potentially large cache (for 0,0),
   # this function is purposely unimplemented

   return $sth->{Database}->set_err($DBI::stderr, "Seek is not implemented in this driver", '0A502');  # we really shouldn't get this far...
}

sub push_row ($$) {
   my ($self, $sth, $row) = @_;

   # Only needed for the same conditions as seek (both cases)
   
   # May tie into insert_new_row, but implementation doesn't really make sense
   
   return $sth->{Database}->set_err($DBI::stderr, "Row Push is not implemented in this driver", '0A502');  # we really shouldn't get this far...
}

sub drop ($) {
   my ($self, $sth) = @_;
   return $sth->{Database}->set_err($DBI::stderr, "For the last time: Cannot drop a SNMP table", '0A502');  # we really shouldn't get this far...
}

sub push_names ($$) {
   my ($self, $sth) = @_;
   return $sth->{Database}->set_err($DBI::stderr, "For the last time: Cannot create a SNMP table", '0A502');  # we really shouldn't get this far...
}

1;
