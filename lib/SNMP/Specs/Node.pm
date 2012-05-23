package SNMP::Specs::Node;

use sanity;
use Moo::Role;
use MooX::Types::MooseLike qw/Str/;

requires qw(type snmp_data);

has name => {
   is       => 'ro',
   isa      => 'Str',
   required => 1,
};
has mib  => {
   is       => 'ro',
   isa      => 'SNMP::Specs::MIB',
   required => 1,
   handles  => { mibname => 'name' },
   weak_ref => 1,
};
sub fullname { $_[0]->mibname.'.'.$_[0]->name; }

1;
