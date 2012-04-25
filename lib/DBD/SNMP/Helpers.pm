##############################################################################
# DBD::SNMP Module                                                           #
# E-mail: Brendan Byrd <Perl@resonatorsoft.org>                              #
##############################################################################

##############################################################################
# DBD::SNMP::Helpers

package   # hide from PAUSE
   DBD::SNMP::Helpers;

use common::sense;  # works every time!
use SNMP;
use List::Util qw(max);
use POSIX qw(strftime);

# Export tags
use parent qw(Exporter);
our %EXPORT_TAGS = (
   'all' => [ qw(snmp_transform snmp_index2regex) ],
);
#$EXPORT_TAGS{'all'} = [ map { @{ $EXPORT_TAGS{$_} } } keys %EXPORT_TAGS ];
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our $VERSION = $DBD::SNMP::VERSION;

sub snmp_transform {
   my ($sub, $val) = @_;
   $sub = 'transform_'.$sub;
   return DBD::SNMP::Helpers->can($sub) ? &$sub($val) : transform_NOOP($val);
}

sub snmp_index2regex {
   my ($oid) = @_;
   my @SNMPIndex = @{$SNMP::MIB{$oid}->{parent}{index}};

   # Figure out the exact index format for the multi-column indexes (some with multiple subIDs)
   my $regex = '^';
   foreach my $name (@SNMPIndex) {
      my $s = $SNMP::MIB{$name};
      my $t = $s->{type};
      my $r = $s->{ranges}[0];
      my ($min, $max) = $r ? ($r->{low}, $r->{high}) : (undef, undef);

      my $uncap_re;
      my $cap_re = '(?<'.$name.'>';

      given ($t) {  # RFC2578 Section 7.7
         # RFC: 4 sub-identifiers, in the familiar a.b.c.d notation
         when (/NETADDR|IPADDR/) {
            $uncap_re = '1\.' if ($t =~ /NETADDR/);  # RFC1155: internet -> IpAddress
            $cap_re .= '\d{1,3}(?:\.\d{1,3}){3}';
         }
         # RFC: fixed-length strings (or variable-length preceded by the IMPLIED keyword): 'n' sub-identifiers, where 'n' is the length
         # of the string (each octet of the string is encoded in a separate sub-identifier)
         when (/OBJECTID|OCTETSTR/) {
            my $len = '{1,'.(($t =~ /OBJECTID/) ? 10 : 3).'}';

            if ($min && $max && $min == $max) {
               my $rng = '{'.($min - 1).','.($max - 1).'}';
               $cap_re .= '\d'.$len.'(?:\.\d'.$len.')'.$rng;
            }
            else {
               # RFC: variable-length strings (not preceded by the IMPLIED keyword): 'n+1' sub-identifiers, where 'n' is the length of the
               # string (the first sub-identifier is 'n' itself, following this, each octet of the string is encoded in a separate
               # sub-identifier)

               # Okay, welcome to the mouth of madness, folks!  These variable-length strings drive me insane...
               # (??{ }) = Code that looks at previous capture groups to compile a RE

               $uncap_re = '(\d{1,3})\.'.($min ? '' : '?');     # length of the string, with an unnamed capture (dot is optional, since it might be zero)
               $cap_re  .= '(?:\d'.$len.')'.($min ? '' : '?');  # first char (the one without the dot)

               # Yes, this is a subroutine to build a regular expression that calls another anonymous sub to build a subset of a
               # regular expression...

               # embedded code = '(?:\.\d{1,3}){'.(int($^N) ? int($^N) - 1 : 0).'}'
               $cap_re  .= "(??{\n\t'(?:".'\.\d'.$len."){'.(int(\$^N) ? int(\$^N) - 1 : 0).'}'\n})";  # read the length now, and use that in the RE (as its found)
            }
         }
         # RFC: a single sub-identifier taking the integer value (this works only for non-negative integers)
         when (/INTEGER|UNSIGNED/) {
            # convert to bits, so that we aren't trying to store BigInts
            my $bits = 32;
            $bits = $1 if ($t =~ /(\d+)/);

            ($min, $max) = map { $_ ? (log(abs $_) / log(2) + 1) : 1 } ($min, $max) if ($min || $max);
            $min ||= 1;
            $max ||= $bits;
            $max = $bits if ($r->{high} && $r->{high} < $r->{low});  # sometimes Net-SNMP gets confused with large numbers

            $cap_re .= '\d{1,'.int(max(abs($min), $max) * (log(2) / log(10)) + 1).'}';
         }
         default {
            die "Unusable index column type of $t, found on OID $name (related to OID $oid)\nValid types are: OBJECTID, OCTETSTR, NETADDR, IPADDR, INTEGER (and possibly UNSIGNED)";
         }
      }

      $regex .= $uncap_re.$cap_re.')\.';
   }
   $regex =~ s/\\\.$/\$/;
   $regex = '^0$' unless (@SNMPIndex);

   use re 'eval';  # need this for (??{ })
   $regex = qr/$regex/;

   return (\$regex, @SNMPIndex);
}

##############################################################################
# Transform Subroutines

### FIXME: Enum map

### FIXME: Transforms for these...

# ["TestAndIncr",DBI::SQL_INTEGER(),    32, undef, undef,        undef,     1,     0,     2,     1,     1,     0,  "TestAndIncr",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
# [ "RowStatus", DBI::SQL_INTEGER(),     4, undef, undef,        undef,     1,     0,     2,     1,     1,     0,    "RowStatus",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
# ["StorageType", DBI::SQL_INTEGER(),    4, undef, undef,        undef,     1,     0,     2,     1,     1,     0,  "StorageType",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
# ["TDomain",    DBI::SQL_VARCHAR(),  1408,   "'",   "'",        undef,     1,     0,     3, undef,     1, undef,      "TDomain", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
# ["TAddress",   DBI::SQL_VARCHAR(),   255,   "'",   "'",        undef,     1,     0,     3, undef,     1, undef,     "TAddress", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],

sub transform_NOOP { return $_[0]; }
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

sub transform_BITS {
   my ($val) = @_;
   $val = pack('b*', $val) if ($val =~ /^[01]+$/);  # ScdmaSelectionString does this

   my $len = length($val);
                   #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
   my @pack_type = qw(C C n N N H H H H H H H H H H H H);

   return unpack($pack_type[$len].'*', $val);
}
      
sub transform_TruthValue {
   return $_[0] ? 1 : 0;
}

sub transform_IPADDR {
   my ($val) = @_;
   my $hex = '[0-9a-fA-F]{0,4}';

   # identify
   my ($ip, $zone, $t);
   given ($val) {
      when (/^($hex(?::$hex){1,7})(\#\d+)?$/)                           { ($ip, $zone, $t) = ($1,    $2, 's6'); }  # IPv6 string
      when (/^($hex(?::$hex){1,5}:\d{1,3}(?:\.\d{1,3}){3})(\#\d+)?$/)   { ($ip, $zone, $t) = ($1,    $2, 'sm'); }  # IPv4 address in IPv6 format
      when (/^(\d{1,3}(?:\.\d{1,3}){3})(\#\d+)?$/)                      { return $val;                          }  # IPv4 string (also covers 4-byte OBJECTID)
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
   given ($t) {
      when ('b4')    {                              # convert binary to octet string
         $ip = transform_ASCII($ip);
      }
      when ('b6')    { $ip = addr2hex($ip, 'b'); }  # convert binary to hex
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
*transform_NETADDR         = \&transform_IPADDR;
*transform_InetAddress     = \&transform_IPADDR;
*transform_InetAddressIPv4 = \&transform_IPADDR;
*transform_InetAddressIPv6 = \&transform_IPADDR;
*transform_IpV4orV6Addr    = \&transform_IPADDR;
*transform_Ipv6AddressIfIdentifierTC = \&transform_IPADDR;

sub transform_MacAddress {
   my ($val) = @_;

   my $t = parsehex($val, 12, '[0-9a-f]{2}(?::[0-9a-f]{2}){5}');
   return $val if (!$t || $t eq '!');

   my $mac = addr2hex($val, $t);
   $mac =~ s/(\w{2})(?=\w)/$1\:/g;  # in IEEE format

   return $mac;
}

sub transform_PhysAddress {
   my ($val) = @_;

   my $t = parsehex($val, '12,', '[0-9a-f]{2}(?::[0-9a-f]{2}){5,}');
   return $val if (!$t || $t eq '!');

   my $mac = addr2hex($val, $t);
   $mac =~ s/(\w{2})(?=\w)/$1\:/g;  # in IEEE format

   return $mac;
}

sub transform_BridgeId {
   my ($val) = @_;

   my $t = parsehex($val, 16, '\d{1,5}\#[0-9a-f]{2}(?::[0-9a-f]{2}){5}');
   return $val if (!$t || $t eq '!');

   my $mac = addr2hex($val, $t);
   my $pri = hex(substr($mac, 0, 4));

   $mac = substr($mac, 4);
   $mac =~ s/(\w{2})(?=\w)/$1\:/g;  # in IEEE format

   return $pri.'#'.$mac;   # looks like 32767#00:00:ce:34:8d:2f
}

sub transform_ASCII {
   my ($val) = @_;
   return $val if     ($val =~ /^\d{1,3}(\.\d{1,3})+$|^\d+$/);
   $val =~ s/(.)(?=.)/unpack('C', $1).'.'/sge;  # binary to dotted-decimal
   $val =~ s/(.)$/unpack('C', $1)/se;
   return $val;
}

sub transform_OCTETSTR {
   my ($val) = @_;
   return $val unless ($val =~ /^\d{1,3}(\.\d{1,3})+$/);
   $val =~ s/(\d{1,3})(?:\.|$)/chr($1)/ge;      # dotted-decimal to binary
   return $val;
}

sub transform_TIMETICKS {
   # from centi-seconds to DDD HH:MI:SSXFF
   # ie: 100 15:45:59.45

   my ($val) = @_;

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

   my ($val) = @_;

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
   my ($val) = @_;
   return undef if ($val eq '0.0');  # SNMPv2-SMI::zeroDotZero = SNMP NULL
   return undef unless ($val);

   # Figure out what kind of pointer it is and what its indexes are
   my $oidname = &oid2name($val);
   my ($index_regex, @indexes) = &snmp_index2regex($oidname);
   my ($objname, $index) = split(/\./, $oidname, 2);
   my $mib = (split(/\:/, $oidname, 2))[0];

   # Grab the index values
   my %index_data;
   if ($index =~ $$index_regex) { %index_data = %+; }
   else                         { return "$objname | $index"; }  # (giving up...)

   my @joinstr = ($objname);
   foreach my $i (@indexes) {
      my $data = $index_data{$i};

      # See if any of the indexes require any transforms
      
      ### FIXME: This probably won't work in its current form... ###
      
      # my $syntax = $SNMP::MIB{"$mib::$i"}->{syntax};
      # my $ct = (search_tree(@{$main::XML->{Syntaxes}->{Syntax}}, 'SyntaxName', $syntax))->{ColumnTransform} if ($syntax);  # (yes, we're abusing $main::XML here...)
      # if ($ct) {
         # my @p = ($data);
         # my ($sub, $var) = ($ct =~ /(\w+)\((\w)\)/) ? ($1, $2) : ($ct, undef);
         # &tech_error("Transform type $ct not available within RowPointer transform at this time!") if ($var);  ### TODO ###

         # $data = &{'transform_'.$sub}(@p);
      # }

      push(@joinstr, $data);
   }

   # Return the OIDName and index data, separated by pipes
   return join('|', @joinstr);
}
*transform_OBJECTID        = \&transform_RowPointer;
*transform_AutonomousType  = \&transform_RowPointer;
*transform_InstancePointer = \&transform_RowPointer;
*transform_VariablePointer = \&transform_RowPointer;

##############################################################################
# Misc. functions

### FIXME: Should be using $snmp_spec data... ###

sub name2oid { return (&oid2all($_[0]))[0]; }
sub oid2name { return (&oid2all($_[0]))[1]; }
sub oid2tree { return (&oid2all($_[0]))[2]; }
sub oid2all  {
   my $oid = $_[0];
   &SNMP::initMib();  # load it if not already loaded

   my $n = SNMP::translateObj($oid, 0, 1);
   my $o = SNMP::translateObj($n  , 0, 1);
   ($o, $n) = ($n, $o) if ($o =~ /[a-z\:]+/i);
   my $t = SNMP::translateObj($o  , 1, 0);

   # check to see if we even have MIBs loaded
   unless ($o) {
      my $ss = $SNMP::MIB{'SNMPv2-MIB::system'};
      die ("SNMP MIBs not loaded; please configure Net-SNMP to read them!") unless ($ss->{objectID});
      return ($oid, $oid);
   }

   # remove prefix dot
   $o =~ s/^\.//;
   $t =~ s/^\.//;

   # in case of MIB mismatch, use the MIB name provided in the parameter
   $n =~ s/^([\w\-]+)::/$1::/ if ($oid =~ /^([\w\-]+)::/ && $n !~ /^\Q$1\E::/);
   # (though, we can't do much about the other direction...)

   return ($o, $n, $t);
}

sub parsehex ($$$) {
   my ($val, $len, $re) = @_;
   $val = lc($val);

   # define some lengths (acronyms: two-minus, four-minus, two, one-plus)
   my ($ltm, $lfm) = map { int(int($len) / $_ - 1) } qw(2 4);
   my ($lt,  $lop) = (int($len) / 2, $len + 1);
   
   # in the form of #, for minimum only
   if ($len =~ /\,/) { $ltm.=','; $lfm.=','; $lt.=','; } 

   given ($val) {
      when (/^$re$/)                                { return '!';   }  # correct format
      when (/^[0-9a-f]{2}(?::[0-9a-f]{2}){$ltm}$/)  { return 's';   }  # String (in IEEE 2:2:2:2:2:2 format)
      when (/^[0-9a-f]{4}(?:\.[0-9a-f]{4}){$lfm}$/) { return 's';   }  # String (in 4.4.4 format)
      when (/^([0-9a-f]{$len})$/)                   { return 's';   }  # String (in bare word format)
      when (/^\d{1,3}(?:\.\d{1,3}){$ltm}$/)         { return 'o';   }  # ##-byte OBJECTID
      when (/^.{$lt}$/s)                            { return 'b';   }  # ##-byte binary
      when (/^[\s\!-\@\[-f\{-\~]{$lop,}$/)          { return 's';   }  # String (in unknown, but ASCII format)
      default                                       { return undef; }  # (giving up...)
   }
}

sub addr2hex ($$) {
   my ($val, $t) = @_;

   given ($t) {
      when ('o') { $val =~ s/(\d{1,3})(?:\.|$)/sprintf('%02x', $1)/ge; }  # decimal/OBJECTID
      when ('b') { $val =~ s/(.)/unpack('H2', $1)/sge;                 }  # binary
      default    { $val =~ s/[^0-9a-fA-F]+//g;                         }  # ASCII string (with hex)
   }

   return lc($val);
}

1;
