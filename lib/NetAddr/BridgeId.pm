package NetAddr::BridgeID;

use sanity;
use NetAddr::MAC;
use Moo;
use MooX::Types::MooseLike::Base qw/Str/;
use MooX::Types::MooseLike::CLike qw/UShort/;

has original => {
   is       => 'ro',
   isa      => Str,
   required => 1,
};
has priority => {
   is       => 'ro',
   isa      => UShort,
   required => 1,
};
has mac_obj => {
   is       => 'ro',
   isa      => 'NetAddr::MAC',
   required => 1,
   handles  => {
      (map { $_ => $_ } qw(
         is_eui48
         is_eui64
         is_multicast
         is_unicast
         is_local
         is_universal
         as_basic
         as_bpr
         as_cisco
         as_ieee
         as_ipv6_suffix
         as_microsoft
         as_singledash
         as_sun
         as_tokenring
         to_eui48
         to_eui64
      )),
      qw(
         mac  original
      ),
   },
};

sub bridge_id { $_[0]->priority.'#'.$_[0]->as_basic; }

sub BUILDARGS {
   my ($class, %opts) = @_;

   if (@_ == 2) {
      %opts = ();
      my $arg = pop;
      for (ref $arg) {
         when ('NetAddr::BridgeID') { $opts{bridge_id} = $arg->bridge_id; }
         when ('NetAddr::MAC')      { $opts{mac_obj}   = $arg; }
         default                    { $opts{bridge_id} = $arg; }
      }
   }

   # parse vars from bridge_id
   if (defined $opts{bridge_id}) {
      $opts{bridge_id} =~ /^(\d+)\#(.+)$/;
      $opts{priority}  //= $1;
      $opts{mac}       //= $2;
   }

   # parse mac from mac_obj
   $opts{mac} //= $opts{mac_obj}->original if (defined $opts{mac_obj});

   # defaults
   $opts{priority}  //= 0;
   $opts{bridge_id} //= $opts{priority}.'#'.$opts{mac};
   $opts{mac_obj}   //= NetAddr::MAC->new($opts{mac});
   
   # bridge_id is actually 'original'
   $opts{original} = delete $opts{bridge_id};
   delete $opts{mac};

   return \$opts;
};

1;