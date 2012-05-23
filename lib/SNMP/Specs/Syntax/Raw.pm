package SNMP::Specs::Syntax::Raw;

use sanity qw(sanity -namespace::sweep);
use List::Util qw(first max);
use POSIX qw(strftime);
use namespace::sweep -also => qr/^transform_/;

use Moo;
use MooX::Types::MooseLike qw/Any Bool/;

has value_obj => {
   is       => 'ro',
   isa      => 'SNMP::Specs::Value',
   required => 1,
   weak_ref => 1,
};
has val => {
   is       => 'rw',
   isa      => Any,  # Value, realistically, but Objects might be passed prior to tranformations
   required => 1,
   trigger  => sub {
      my ($self, $val) = @_;
      return $val unless ($self->_should_propagate);
      my $ssv = $self->value_obj;
      $val = $self->_transform($val);
      $ssv->syntax->validate($val);
      $ssv->_last_write($self);  # We are the new leaders
      
      # Propagate to others (if they exist)
      
      # Only one is called, because the other will take care of the third, if all
      # three are active.  Because of this, check order is important: R->F->C->R
      $self->_should_propagate(0);
      if    ($ssv->_has_filtered) { $ssv->val   ($val); }
      elsif ($ssv->_has_cooked)   { $ssv->cooked($val); }
      else                        { $self->val  ($val); }
      $self->_should_propagate(1);
      
      return $val;
   }
};
# this is infinite loop protection
has _should_propagate => {
   is      => 'rw',
   isa     => Bool,
   default => sub { 1; }
}

sub _transform {
   my ($self, $val) = @_;
   my $ssv = $self->value_obj;
   
   my $sub;
   $sub = 'transform_'.$ssv->syntax->name;
   $sub = 'transform_'.$ssv->syntax->base_type unless $self->can($sub);
   $sub = 'transform_NOOP'                     unless $self->can($sub);
   # (can't handle bits as enums here because there may be multiple bits active,
   # and we can't stuff it into an ArrayRef without breaking our standard of
   # non-refs for filtered values)
   $sub = 'transform_ENum' if (%{$ssv->syntax->enums} && $ssv->syntax->base_type =~ /INTEGER/);
   
   return $self->$sub($val);
}

# This is a special "no validation" value set, only used by DBD::SNMP for values
# it acquired from devices, as they are guaranteed to be "raw".  As long as there
# isn't any other filtered/cooked instances active for this Value, it should be
# pretty fast.
sub _force_set {
   my ($self, $val) = @_;
   my $ssv = $self->value_obj;

   # certain indexes need a transform from dotted-decimal to binary
   $val = $self->transform_OCTETSTR($val) if $ssv->syntax->base_type =~ /OCTETSTR|(?:IP|NET)ADDR/;
   
   $self->_should_propagate(0);  # this will disable the trigger
   $self->val($val);

   if    ($ssv->_has_filtered) { $ssv->val   ($val); }
   elsif ($ssv->_has_cooked)   { $ssv->cooked($val); }
   $self->_should_propagate(1);

   $ssv->_last_write($self);  # We are the new leaders

   return $val;
}

##############################################################################
# Transform Subroutines

### FIXME: Transforms for these...

# ["TestAndIncr",DBI::SQL_INTEGER(),    32, undef, undef,        undef,     1,     0,     2,     1,     1,     0,  "TestAndIncr",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
# [ "RowStatus", DBI::SQL_INTEGER(),     4, undef, undef,        undef,     1,     0,     2,     1,     1,     0,    "RowStatus",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
# ["StorageType", DBI::SQL_INTEGER(),    4, undef, undef,        undef,     1,     0,     2,     1,     1,     0,  "StorageType",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
# ["TDomain",    DBI::SQL_VARCHAR(),  1408,   "'",   "'",        undef,     1,     0,     3, undef,     1, undef,      "TDomain", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
# ["TAddress",   DBI::SQL_VARCHAR(),   255,   "'",   "'",        undef,     1,     0,     3, undef,     1, undef,     "TAddress", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],


###############################################################
### FINISH: These are just Filtered transforms right now... ###
###############################################################





sub transform_NOOP { return $_[1]; }
*transform_INTEGER    = \&transform_NOOP;
*transform_INTEGER32  = \&transform_NOOP;
*transform_COUNTER    = \&transform_NOOP;
*transform_COUNTER64  = \&transform_NOOP;
*transform_GAUGE      = \&transform_NOOP;
*transform_GAUGE64    = \&transform_NOOP;
*transform_Gauge      = \&transform_NOOP;
*transform_Gauge32    = \&transform_NOOP;
*transform_Gauge64    = \&transform_NOOP;
*transform_Counter    = \&transform_NOOP;
*transform_Counter32  = \&transform_NOOP;
*transform_Counter64  = \&transform_NOOP;
*transform_Integer    = \&transform_NOOP;
*transform_Integer32  = \&transform_NOOP;
*transform_Unsigned32 = \&transform_NOOP;
*transform_OPAQUE     = \&transform_NOOP;
*transform_DisplayString = \&transform_NOOP;

sub transform_ENum {
   my ($self, $val) = @_;
   my $enums = $self->value_obj->syntax->enums;
   
   # exact match
   return $val if ($enums->{$val});
   # int to enum match
   return first { $enums->{$_} == $val } keys %$enums if ($val =~ /^\d+$/);
   # fuzzy match
   $val =~ s/\W+//g;
   my $match = first { /^$val$/i } keys %$enums;
   $match and return $match;
   
   return $_[1];  # (giving up...)
}

sub transform_BITS {
   my ($self, $val) = @_;
   $val = pack('b*', $val) if ($val =~ /^[01]+$/);  # ScdmaSelectionString does this

   my $len = length($val);
                   #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
   my @pack_type = qw(C C n N N H H H H H H H H H H H H);

   return unpack($pack_type[$len].'*', $val);
}
      
sub transform_TruthValue {
   my ($self, $val) = @_;
   return 2 if (!$val || $val == 2 || $val =~ /^[NF]/i);
   return 1;
}

# Unlike Filtered, Raw can't just accept any format, so we need to be more fussy about
# not combining too many transforms.
sub transform_IPADDR {
   my ($self, $val) = @_;
   return $val if length($val) == 4;  # already there
   
   my $ip = SNMP::Specs::Syntax::Filtered::_normalize_ip(@_);
   # no zones, no IPv6
   $ip =~ s/\%(\d+)$//g;
   $ip = $1 if ($ip =~ /(\d{1,3}(?:\.\d{1,3}){3})/);
   return $self->transform_OCTETSTR($ip);
}
*transform_NETADDR         = \&transform_IPADDR;
*transform_InetAddressIPv4 = \&transform_IPADDR;


*transform_InetAddress     = \&transform_IPADDR;
*transform_InetAddressIPv6 = \&transform_IPADDR;
*transform_IpV4orV6Addr    = \&transform_IPADDR;
*transform_Ipv6AddressIfIdentifierTC = \&transform_IPADDR;

sub transform_MacAddress {
   my ($self, $val) = @_;

   my $t = $self->value_obj->_parsehex($val, 12, '[0-9a-f]{2}(?::[0-9a-f]{2}){5}');
   return $val if (!$t || $t eq '!');

   my $mac = $self->value_obj->_addr2hex($val, $t);
   $mac =~ s/(\w{2})(?=\w)/$1\:/g;  # in IEEE format

   return $mac;
}

sub transform_PhysAddress {
   my ($self, $val) = @_;

   my $t = $self->value_obj->_parsehex($val, '12,', '[0-9a-f]{2}(?::[0-9a-f]{2}){5,}');
   return $val if (!$t || $t eq '!');

   my $mac = $self->value_obj->_addr2hex($val, $t);
   $mac =~ s/(\w{2})(?=\w)/$1\:/g;  # in IEEE format

   return $mac;
}

sub transform_BridgeId {
   my ($self, $val) = @_;

   my $t = $self->value_obj->_parsehex($val, 16, '\d{1,5}\#[0-9a-f]{2}(?::[0-9a-f]{2}){5}');
   return $val if (!$t || $t eq '!');

   my $mac = $self->value_obj->_addr2hex($val, $t);
   my $pri = hex(substr($mac, 0, 4));

   $mac = substr($mac, 4);
   $mac =~ s/(\w{2})(?=\w)/$1\:/g;  # in IEEE format

   return $pri.'#'.$mac;   # looks like 32767#00:00:ce:34:8d:2f
}

sub transform_ASCII {
   my ($self, $val) = @_;
   return $val if     ($val =~ /^\d{1,3}(\.\d{1,3})+$|^\d+$/);
   $val =~ s/(.)(?=.)/unpack('C', $1).'.'/sge;  # binary to dotted-decimal
   $val =~ s/(.)$/unpack('C', $1)/se;
   return $val;
}

sub transform_OCTETSTR {
   my ($self, $val) = @_;
   return $val unless ($val =~ /^\d{1,3}(\.\d{1,3})+$/);
   $val =~ s/(\d{1,3})(?:\.|$)/chr($1)/ge;      # dotted-decimal to binary
   return $val;
}

sub transform_TIMETICKS {
   # from centi-seconds to DDD HH:MI:SSXFF
   # ie: 100 15:45:59.45

   my ($self, $val) = @_;

   # fake the interval as an epoch, since yday only needs to go to 248 days
   my $epoch = ($val / 100);
   my $secfrac = substr($epoch - int($epoch), 1, 3);  # gmtime only gives back integer seconds

   my $yday = (gmtime($epoch))[7];  # strftime uses 1-based yday, so use gmtime's version
   return strftime $yday.' %H:%M:%S'.$secfrac, gmtime($epoch);
}
*transform_TICKS        = \&transform_TIMETICKS;
*transform_TimeStamp    = \&transform_TIMETICKS;
*transform_TimeInterval = \&transform_TIMETICKS;
*transform_TimeTicks    = \&transform_TIMETICKS;

sub transform_DateAndTime {
   # from DateAndTime OCTETSTRING to DD-MON-RR HH.MI.SSXFF AM TZR
   # ie: 30-APR-11 02:31:59.45 AM +05:30

   my ($self, $val) = @_;

   my $t;
   given ($val) {
      when (/^\d{1,3}(?:\.\d{1,3}){7,10}$/) { $t = 'o';     }  # 8/11-byte OBJECTID
      when (/^.{8,11}$/s)                   { $t = 'b';     }  # 8/11-byte binary
      default                               { return undef; }  # (giving up...)
   }

   $val = transform_ASCII($val) if ($t eq 'b');  # binary to dotted-decimal

   # From SNMPv2-TC:
   #
   # field  octets  contents                  range
   # -----  ------  --------                  -----
   #   1      1-2   year*                     0..65536
   #   2       3    month                     1..12
   #   3       4    day                       1..31
   #   4       5    hour                      0..23
   #   5       6    minutes                   0..59
   #   6       7    seconds                   0..60
   #                (use 60 for leap-second)
   #   7       8    deci-seconds              0..9
   #   8       9    direction from UTC        '+' / '-'
   #   9      10    hours from UTC*           0..13
   #  10      11    minutes from UTC          0..59
   my @dt = (0, split(/\./, $val));  # make it one-based for clarity with above

   # sanity checks
   return undef if (
         $dt[3]  > 12     # month
      || $dt[4]  > 31     # day
      || $dt[5]  > 23     # hour
      || $dt[6]  > 59     # minutes
      || $dt[7]  > 60     # seconds
      || $dt[8]  > 9      # deci-seconds
      || (@dt > 8 && (    # timezone check
            $dt[10] > 13  # TZ hours
         || $dt[11] > 59  # TZ minutes
      ))
   );

   #   0     1    2     3     4    5
   # ($sec,$min,$hour,$mday,$mon,$year) = @timevar;
   my @timevar = ($dt[1] * 256 + $dt[2], @dt[3 .. 7]);  # start reversed first, though
   @timevar = reverse @timevar;

   # mangle timevar to strftime/gmtime's goofy zero-based behaviors
   $timevar[4]--;
   $timevar[5] -= 1900;

   my $secfrac = '.'.$dt[8];  # gmtime only gives back integer seconds
   my $tz = (@dt > 8) ? chr($dt[9]).sprintf('%02u:%02u', @dt[10,11]) : '';

   return strftime '%d-%b-%Y %I:%M:%S'.$secfrac.' %p '.$tz, @timevar;
}

sub transform_RowPointer {
   # ie: IP-MIB::ipAddressPrefixOrigin.2000001.ipv4."10.175.4.1".24
   my ($self, $val) = @_;
   return undef if ($val eq '0.0');  # SNMPv2-SMI::zeroDotZero = SNMP NULL
   return undef unless $val;

   # Figure out what kind of pointer it is and what its indexes are
   my $specs = SNMP::Specs->instance;
   my $node = $specs->oid_lookup($val);
   return undef unless $node;
   ### FINISH: FIXME ###
   my ($index_regex, @indexes) = &snmp_index2regex($oidname);
   my ($objname, $index) = split(/\./, $oidname, 2);
   my $mib = (split(/\:/, $oidname, 2))[0];
   ### FINISH: FIXME ###

   # Grab the index values
   my %index_data;
   if ($index =~ $$index_regex) { %index_data = %+; }
   else                         { return "$objname | $index"; }  # (giving up...)

   my @joinstr = ($objname);
   foreach my $i (@indexes) {
      my $data = $index_data{$i};
      # TODO: See if any of the indexes require any transforms

      push(@joinstr, $data);
   }

   # Return the OIDName and index data, separated by pipes
   return join('|', @joinstr);
}
*transform_OBJECTID        = \&transform_RowPointer;
*transform_AutonomousType  = \&transform_RowPointer;
*transform_InstancePointer = \&transform_RowPointer;
*transform_VariablePointer = \&transform_RowPointer;

1;
