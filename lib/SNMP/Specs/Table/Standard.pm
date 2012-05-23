package SNMP::Specs::Table::Standard;

use sanity;
use Moo;
use MooX::Types::MooseLike qw/ArrayRef HashRef/;

sub type { 'Table' }
has snmp_data => {
   is       => 'ro',
   isa      => 'SNMP::MIB::NODE'
   required => 1,
   handles  => {
      description => 'description',
      name        => 'label',
      moduleID    => 'moduleID',
      objectID    => 'objectID',
      status      => 'status',
   },
};

with 'SNMP::Specs::Node';

sub table_type { 'TABLE' }

### FIXME: Figure out exactly how this will get populated ###
has cols => {
   is       => 'rwp',
   isa      => 'ArrayRef',
   lazy     => 1,
   default  => sub { []; },
   writer   => '_add_col',
};
has 'keys' => {
   is       => 'rwp',
   isa      => 'ArrayRef',
   lazy     => 1,
   default  => sub { []; },
   writer   => '_add_col',
};

      $m->{cols} = [];
      $m->{keys} = [];
      $m->{col}  = {};
      $m->{key}  = {};
      $tobj->{raw_keys} = $tobj->{index_link}{indexes};
      delete $tobj->{raw_keys};
      delete $tobj->{index_link};

1;

### FIXME: This needs to be a method ###
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

