package SNMP::Specs;

use sanity;
use SNMP;
use Scalar::Util qw/weaken/;

use Moo;
with 'MooX::Singleton';

### XXX: Need to add the basic dbi_* stuff here ###
has _mibs => {
   is       => 'rwp',
   isa      => 'HashRef',
   lazy     => 1,
   default  => sub { {}; },
   writer   => '_add_mib',
};
has _full_nodes => {
   is       => 'rwp',
   isa      => 'HashRef',
   lazy     => 1,
   default  => sub { {}; },
   writer   => '_add_full_node',
};
has _types => {
   is       => 'rwp',
   isa      => 'HashRef',
   lazy     => 1,
   default  => sub { {}; },
   writer   => '_add_type',
};

sub mib_lookup {
   my ($self, $mibname) = @_;
   $self->_mibs->{$mibname};
}
sub node_lookup {
   my ($self, $nodename, $filter) = @_;
   ### FIXME: Implement $filter ###
   $self->_full_nodes->{$nodename};
}
sub oid_lookup {
   my ($self, $oid) = @_;
   my $nodename = SNMP::translateObj($oid, 0, 1);
   return $nodename && $self->node_lookup($nodename);
}


sub _add_mib {
   ### FIXME: This should be a MIB creation method, not adding an existing one ###
   my ($self, $mibname, $mib_obj) = @_;
   $_data->{mibs}{$mibname} = $mib_obj;
}

sub _add_full_node {
   ### FIXME: This should be a OID creation method, not adding an existing one ###
   my ($self, $fullname, $oid_obj) = @_;
   # This is the only Node object with a strong ref
   $_data->{full_nodes}{$fullname} = $oid_obj;
}

sub _add_types {

}

### FINISH: Convert this sub ###
sub BUILD {
   ### XXX: Don't use $dbh ###
   my $dbh = $_[0];
   
   $SNMP::save_descriptions = 1;
   &SNMP::addMibDirs(split /\w+/, $dbh->{snmp_mib_dirs});
   &SNMP::loadModules('ALL');
   &SNMP::initMib();

   # Specs
   #    mib_lookup  -> [MIB]
   #    full_lookup -> [OIDObject] (Role)
   
   # Specs->MIBQuery->[MIB]
   
   # Specs->Full
   
   
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
      # $e->{children} is not guaranteed to be sorted in correct subID order, so $ek->[-1] doesn't work...
      # since we are already scanning $ek at this point, might as well do the same thing as @oo...
      my $lk = $ek && first { $_->{access} ne 'NoAccess' && $_->{syntax} && !arrayref_short_cnt($_->{children}) } @$ek;
      my @oo =         grep { $_->{access} ne 'NoAccess' && $_->{syntax} && !arrayref_short_cnt($_->{children}) } @$c;
      
      # (can't use $e->{indexes} checks, else this would be easier)
      #                                 (we don't need a total count, just 0, 1, or 2)
      if    ($o->{access} eq 'NoAccess' && !$o->{syntax} &&  arrayref_short_cnt($c)              &&
             $e->{access} eq 'NoAccess' && !$e->{syntax} &&  arrayref_short_cnt($ek)             &&
            $lk
      ) {
         # Standard table
         $columns    = $ek;
         $index_link = $e;
         $table_type = (first { $_->{syntax} ne 'NOTIF' } @$c) ? 'TABLE' : 'NOTIFY OBJECT';
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
      _process_indexes($dbh, values %{$snmp_specs->{Full}{tbl}});
   }
}

# SNMP::MIB seems to take around 1/20th of a sec to process each $o->{indexes} object.
# So, we do this post-processing on-demand only.
sub _process_indexes {
   my $dbh = shift @_;
   my $good = 1;
   
   my @tobj = @_;
   TLOOP: for (my $i = 0; $i < @tobj; $i++) {  # ol' fashioned loop for array self-modification
      my $tobj = $tobj[$i];
      next unless ($tobj->{index_link});
      $tobj->{raw_keys} = $tobj->{index_link}{indexes};
      $tobj->{key}  //= {};
      $tobj->{keys} //= [];
      
      # (an annoyingly large piece of code worth storing)
      my $lcss_oid = sub {
         # String::LCSS_XS as a weird bug with passing tied variables (RT #76906), so we have to store them first
         my $c = $snmp_specs->{Full}{col}{$_[0]}{data}{objectID};
         my $t = $tobj->{data}{objectID};
         return length( lcss( $c, $t, 10 ) );
      };
   
      foreach my $name ('dbi_hostid', @{$tobj->{raw_keys}}) {
         # MIBs like DOCS-QOS-MIB vs. DOCS-QOS3-MIB throw that whole "unique label" assumption out the window...
         my @poten_labels = grep { /\.\Q$name\E$/i } keys %{$snmp_specs->{Full}{col}};

         unless (@poten_labels) {
            if ($dbh->{snmp_load_all} && !$tobj->{unknown_index_warning}) {
               # Maybe we can find it in a later table
               $dbh->set_err('', "Currently unknown index key '$name' on table '".$tobj->{name}."'; will recheck later...", '42720');
               $tobj->{unknown_index_warning} = 1;
               push(@tobj, $tobj);
            }
            else {
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
            }
            next TLOOP;
         }

         my $label = (@poten_labels == 1) ? $poten_labels[0] :
            # (in other words, use the matched label with the largest common OID...)
            (sort { &$lcss_oid($b) <=> &$lcss_oid($a) } @poten_labels)[0];
            
         my $kobj      = $snmp_specs->{Full}{col}{$label};
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
      $tobj->{cols} = [
         @{$tobj->{keys}},
         sort { $a->{data}{subID} <=> $b->{data}{subID} } notin($tobj->{keys}, $tobj->{cols})
      ];
      
      delete $tobj->{raw_keys};
      delete $tobj->{index_link};
   }
   
   return $good;
}

sub _arrayref_short_cnt { my $c = $_[0]; return $c->[0] ? ($c->[1] ? 2 : 1) : 0; }   
   
1;