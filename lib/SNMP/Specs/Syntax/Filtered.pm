package SNMP::Specs::Syntax::Filtered;

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
      if    ($ssv->_has_cooked) { $ssv->cooked($val); }
      elsif ($ssv->_has_raw)    { $ssv->raw   ($val); }
      else                      { $self->val  ($val); }
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

##############################################################################
# Transform Subroutines

### FIXME: Make sure it can handle all three types ###

### FIXME: Transforms for these...

# ["TestAndIncr",DBI::SQL_INTEGER(),    32, undef, undef,        undef,     1,     0,     2,     1,     1,     0,  "TestAndIncr",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
# [ "RowStatus", DBI::SQL_INTEGER(),     4, undef, undef,        undef,     1,     0,     2,     1,     1,     0,    "RowStatus",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
# ["StorageType", DBI::SQL_INTEGER(),    4, undef, undef,        undef,     1,     0,     2,     1,     1,     0,  "StorageType",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
# ["TDomain",    DBI::SQL_VARCHAR(),  1408,   "'",   "'",        undef,     1,     0,     3, undef,     1, undef,      "TDomain", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
# ["TAddress",   DBI::SQL_VARCHAR(),   255,   "'",   "'",        undef,     1,     0,     3, undef,     1, undef,     "TAddress", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],

# Per RFC 2579, 3.1:
# The DISPLAY-HINT clause must not be present if the Textual Convention is defined with
# a syntax of:  OBJECT IDENTIFIER, IpAddress, Counter32, Counter64, or any enumerated
# syntax (BITS or INTEGER).
sub transform_NOOP { return $_[1]; }
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
*transform_OPAQUE     = \&transform_NOOP;
*transform_DisplayString = \&transform_NOOP;

sub transform_INTEGER {
   my ($self, $val) = @_;
   my $syntax  = $self->value_obj->syntax;
   my $hint    = $syntax->hint;
   my $hint_re = $syntax->hint2re;
   
   return $val unless defined $hint;  # no hint, so it's a no-op
   return $val if ($val =~ $$hint_re);  # already transformed

   return sprintf('%#'.$1, $val) if ($hint =~ /([xob])/);
   return $val / 10**$1          if ($hint =~ /d-(\d+)/);
   return $val;
}
*transform_INTEGER32  = \&transform_INTEGER;
*transform_Integer    = \&transform_INTEGER;
*transform_Integer32  = \&transform_INTEGER;
*transform_Unsigned32 = \&transform_INTEGER;

sub transform_OCTETSTR {
   my ($self, $val) = @_;
   my $origval = $val;
   $val = $self->_dd2bin($val);  # dotted-decimal to binary
   my $syntax  = $self->value_obj->syntax;
   my $hint    = $syntax->hint;
   my $hint_re = $syntax->hint2re;

   return $val unless defined $hint;  # no hint, so it's a no-op (except for that dd2bin part)
   return $val unless length $val;
   
   # Trying to detect already transformed values is going to be a
   # challenge here, but we have the hint template, and we can at
   # least look for some clues.
   unless ($origval eq $val) {  # did we just transform this with _dd2bin?  then it's definitely not hint-transformed
      my ($val, $r) = ($_[0], $self->ranges);
      my $max = $r and @$r and $r->[0]{max};
      return $val if ($val =~ $$hint_re or $max && length($val) > $max);
   }
   
   # Okay, it must not be hint-transformed
   my ($repeat_count, $replay_log, $newval) = (1, '', '');
   while (length $hint) {
      if ($hint =~ s/^\*//) {
         $val =~ s/^(.)//;
         $repeat_count = ord $1;
      }
      
      ############### FINISH ##################
      
      
      if ($hint =~ s/^(\d+)([xdoat])//) {
         $re .= ("\t" x $repeating+1).'(?:'.$num2re->{$2}.'){'.($1 || 1)."}  # $1$2\n";
      }
      else {  # this is NOT optional!
         warn "Invalid hint format: ".$snmp->hint;
         return \(qr/.+/);
      }
      
      if ($hint =~ s/^([^\d\*])?([^\d\*])?//) {
         $re .= ("\t" x $repeating+1).'(?:\Q'.$1.'\E'.($2 ? ')?' : '|$)')."  # separator\n";
         if ($2) {
            unless ($repeating) {
               warn "Invalid hint format: ".$snmp->hint;
               return \(qr/.+/);
            }
            $re .= "\t".'){0,255}(?:\Q'.$2.'\E|$)'."  # end repeat + terminator char\n";  # limited to one octet
            $repeating = 0;
         }
      }
   };
   
   
   return $val;
}

sub transform_ENum {
   my ($self, $val) = @_;
   my $enums = $self->value_obj->syntax->snmp_data->enums;
   
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
   return $val if ($val =~ /^0[xb]/i);  # already transformed
   my $is_hex = length($val) > 4;
   
   # process a char at a time, to avoid potential int overflows
   my $bits = $is_hex ? '0b' : '0x';
   $bits .= sprintf($is_hex ? '%8b' : '%2X', ord) for (split //, $val);
   return $bits;
}
      
sub transform_TruthValue {
   my ($self, $val) = @_;
   return 0 if (!$val || $val == 2 || $val =~ /^[NF]/i);
   return 1;
}

sub _normalize_ip {
   my ($self, $val) = @_;
   my $hex = '[0-9a-fA-F]{0,4}';

   # identify
   my ($ip, $zone, $t);
   for ($val) {
      when (/^($hex(?::$hex){1,7})(\%\d+)?$/)                           { ($ip, $zone, $t) = ($1,    $2, 's6'); }  # IPv6 string
      when (/^($hex(?::$hex){1,5}:\d{1,3}(?:\.\d{1,3}){3})(\%\d+)?$/)   { ($ip, $zone, $t) = ($1,    $2, 'sm'); }  # IPv4 address in IPv6 format
      when (/^(\d{1,3}(?:\.\d{1,3}){3})(\%\d+)?$/)                      { return $val;                          }  # IPv4 string (also covers 4-byte OBJECTID)
      when (/^(\d{1,3}(?:\.\d{1,3}){15})\.(\d{1,3}(?:\.\d{1,3}){3})$/)  { ($ip, $zone, $t) = ($1,    $2, 'o6'); }  # 20-byte OBJECTID (IPv6 + zone)
      when (/^(\d{1,3}(?:\.\d{1,3}){15})$/)                             { ($ip, $zone, $t) = ($1, undef, 'o6'); }  # 16-byte OBJECTID (IPv6)
      when (/^(\d{1,3}(?:\.\d{1,3}){3})\.(\d{1,3}(?:\.\d{1,3}){3})$/)   { ($ip, $zone, $t) = ($1,    $2, 'o4'); }  #  8-byte OBJECTID (IPv4 + zone)
      when (/^(?:\w(?:[\-\w]*\w)?\.)+[a-z]+$/i)                         { return $val;                          }  # Domain name
      when (/^(.{16})(.{4})$/s)                                         { ($ip, $zone, $t) = ($1,    $2, 'b6'); }  # 20-byte binary   (IPv6 + zone)
      when (/^(.{16})$/s)                                               { ($ip, $zone, $t) = ($1, undef, 'b6'); }  # 16-byte binary   (IPv6)
      when (/^(.{4})(.{4})$/s)                                          { ($ip, $zone, $t) = ($1,    $2, 'b4'); }  #  8-byte binary   (IPv4 + zone)
      when (/^(.{4})$/s)                                                { ($ip, $zone, $t) = ($1, undef, 'b4'); }  #  4-byte binary   (IPv4)
      default                                                           { return $val;                          }  # (giving up...)
   }

   # transform
   for ($t) {
      when ('b4')    {                              # convert binary to octet string
         $ip = $self->_bin2dd($ip);
      }
      when ('b6')    { $ip = $self->value_obj->_addr2hex($ip, 'b'); }  # convert binary to hex
      when (/o6|sm/) {                              # convert decimal to hex
         $ip =~ s/(?:^|(?<=[\:\.]))(\d{1,3})(?=\.|$)/sprintf('%02x', $1)/ge;
      }
   }
   if ($zone) {
      given ($t) {
         when (/b/) {                               # convert binary to int
            $zone = unpack('N', $zone);
         }
         when (/o/) {                               # convert decimal to int
            $zone =~ s/(?:^|\.)(\d{1,3})/chr($1)/ge;
            $zone = unpack('N', $zone);
         }
      }
   }

   # (finished with IPv4)
   return $ip.($zone ? '#'.$zone : '') if ($t =~ /4/);

   $ip = lc($ip);
   $ip =~ s/[^\:0-9a-f]+//g;  # remove any non-hex characters, so that \w will be reliable

   # replace leading zeroes
   $ip =~ s/(?:^|(?<=:))(\w{1,3})(?=:|$)/('0' x (4 - length($1))).$1/ge;

   # groups of zeroes
   $ip =~ s/::/Z/;
   $ip =~ s/[:\.]+//g;
   $ip =~ s/Z/('0' x (33 - length($ip)))/e;

   # use mixed notation for certain situations
   if ($t =~ /sm/ || $ip =~ /^0{20}(0000|ffff)\w{8}$|((0a|e[089af])\w{6}|ac1\w{5}|c0a8\w{4})$/ && $ip !~ /00\w{6}$/) {
      $ip =~ s|(\w{8})$|join('.', map { hex } ($1 =~ /\w{2}/g))|e;
   }

   # add colons
   $ip = join(':', ($ip =~ /\w{4}|.+/g));

   # remove leading zeroes again
   $ip =~ s/(?:^|(?<=:))0+(\w{1,3})(?=:|$)/$1/g;

   # groups of zeroes (find the largest group first)
   my $m = max map { int(length() / 2 + .5); } ($ip =~ /((^|(?<=:))0(:|$))+/g);
   $ip =~ s/((^|(?<=:))0(:|$))+/::/ if ($m);  # (no g; only once)
   $ip =~ s/:::/::/;  # might happen with xxx::xxx

   # (finally finished with IPv6)
   return $ip.($zone ? '#'.$zone : '');
}
*transform_IPADDR          = \&_normalize_ip;
*transform_NETADDR         = \&transform_IPADDR;
*transform_InetAddress     = \&transform_IPADDR;
*transform_InetAddressIPv4 = \&transform_IPADDR;
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

sub transform_TIMETICKS {
   my ($self, $val) = @_;

   # fake the interval as an epoch, since yday only needs to go to 248 days
   my $epoch = ($val / 100);
   my $yday = (gmtime($epoch))[7];  # strftime uses 1-based yday, so use gmtime's version
   return strftime $yday.' %H:%M:%OS2', gmtime($epoch);
}
*transform_TICKS        = \&transform_TIMETICKS;
*transform_TimeStamp    = \&transform_TIMETICKS;
*transform_TimeInterval = \&transform_TIMETICKS;
*transform_TimeTicks    = \&transform_TIMETICKS;

sub transform_DateAndTime {
   my ($self, $val) = @_;

   my $t;
   for ($val) {
      when (/^\d{1,3}(?:\.\d{1,3}){7,10}$/) { $t = 'o';     }  # 8/11-byte OBJECTID
      when (/^.{8,11}$/s)                   { $t = 'b';     }  # 8/11-byte binary
      default                               { return undef; }  # (giving up...)
   }

   $val = $self->_bin2dd($val) if ($t eq 'b');  # binary to dotted-decimal

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

   my $tz = (@dt > 8) ? ' '.chr($dt[9]).sprintf('%02u:%02u', @dt[10,11]) : '';

   return strftime '%Y-%m-%d %H:%M:%OS2'.$tz, @timevar;
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
