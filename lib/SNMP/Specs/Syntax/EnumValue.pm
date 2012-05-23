package SNMP::Specs::Syntax::EnumValue;

use sanity;
use Moo;
use MooX::Types::MooseLike::Base qw/Str Int Bool/;
use List::Util qw(first);

has enum_obj => {
   is       => 'ro',
   isa      => 'SNMP::Specs::Syntax::Enum',
   required => 1,
   handles  => [qw(name label_hash num_hash)],
};
has num => {
   is        => 'rw',
   isa       => Int,
   trigger   => sub {
      my ($self, $val) = @_;
      
      die "Integer $val not found in Enum ".$self->name
         unless (exists $self->num_hash->{$val});
      
      return $val;
   }
};

# using num for storage, since it's cleaner
sub label {
   my ($self, $val) = @_;
   return $self->num_hash->{ $self->num } unless defined $val;
   
   # fuzzy parsing
   my $label_hash = $self->label_hash;
   unless (exists $label_hash->{$val}) {
      $val =~ s/[\W_]+//g;
      $val = first { /^$val$/i } keys %$hash;
   }
   die "Label $val not found in Enum ".$self->name
      unless (exists $label_hash->{$val});
   
   $self->num( $label_hash->{$val} );
   return $val;
};

sub as_underscored {
   my ($self) = @_;
   my $label = $self->num_hash->{ $self->num };
   $label =~ s/([A-Z])/_$1/g;
   return lc $label;
}
sub as_uc_camelcase {
   my ($self) = @_;
   my $label = $self->num_hash->{ $self->num };
   return ucfirst $label;
}
sub as_proper {
   my ($self) = @_;
   my $label = $self->num_hash->{ $self->num };
   $label =~ s/([A-Z])/ $1/g;
   return ucfirst $label;
}

1;