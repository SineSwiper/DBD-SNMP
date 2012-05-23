package SNMP::Specs::MIB;

use sanity;
use Moo;
use MooX::Types::MooseLike qw/Str HashRef/;
use Scalar::Util qw/weaken/;

has name => {
   is       => 'ro',
   isa      => 'Str',
   required => 1,
};

has _nodes => {
   is       => 'rwp',
   isa      => 'HashRef',
   lazy     => 1,
   default  => sub { {}; },
   writer   => '_add_node',
};

sub _add_node {
   my ($self, $oidname, $obj) = @_;
   my $specs = SNMP::Specs->instance;
   my $fullname = $self->name."::$oidname";
   
   # Make sure it's in _full_oids first
   $spec->node_lookup($fullname) || $spec->_add_full_node($fullname, $obj);
   $self->_nodes->{$oidname} = $obj;
   weaken $self->_nodes->{$oidname};
}

1;
