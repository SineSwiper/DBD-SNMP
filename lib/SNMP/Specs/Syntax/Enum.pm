package SNMP::Specs::Syntax::Enum;

use sanity;
use Moo;
use MooX::Types::MooseLike::Base qw/Str HashRef/;

has name => {
   is       => 'ro',
   isa      => Str,
   required => 1,
};
has label_hash => {
   is        => 'ro',
   isa       => HashRef,
   predicate => '_has_label_hash',
   lazy      => 1,
   default   => sub {
      my ($self) = @_;
      $self->_has_num_hash or die "Enum must have either a label_hash or num_hash!";
      { reverse %{$self->num_hash} };
   }
};
has num_hash => {
   is        => 'ro',
   isa       => HashRef,
   predicate => '_has_num_hash',
   lazy      => 1,
   default   => sub {
      my ($self) = @_;
      $self->_has_label_hash or die "Enum must have either a label_hash or num_hash!";
      { reverse %{$self->label_hash} };
   }
};

1;