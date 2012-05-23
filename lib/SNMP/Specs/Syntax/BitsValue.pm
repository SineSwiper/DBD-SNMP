package SNMP::Specs::Syntax::BitsValue;

use sanity;
use Moo;
use MooX::Types::MooseLike::Base qw/ArrayRef/;
use List::Util qw(first max);
use POSIX qw(ceil);

has enum_obj => {
   is       => 'ro',
   isa      => 'SNMP::Specs::Syntax::Enum',
   required => 1,
   handles  => [qw(name label_hash num_hash)],
};
has nums => {
   is        => 'rw',
   isa       => ArrayRef,
   trigger   => sub {
      my ($self, $array) = @_;
      
      for (@$array) {
         die "Integer $_ not found in Enum ".$self->name
            unless (exists $self->num_hash->{$_});
      }
      
      return $array;
   }
};

# using nums for storage, since it's cleaner
sub label {
   my $self = shift;
   my ($labels) = @_;
   unless defined $labels {
      my $num_hash = $self->num_hash;
      return [ @$num_hash{ @{$self->nums} } ];
   }
   
   # accepts arrays, array refs, or single scalars
   $labels = [ @_ ] unless (ref $labels eq 'ARRAY');
   
   # fuzzy parsing
   my $label_hash = $self->label_hash;
   foreach my $val (@$labels) {
      unless (exists $label_hash->{$val}) {
         $val =~ s/[\W_]+//g;
         $val = first { /^$val$/i } keys %$hash;
      }
      die "Label $val not found in Enum ".$self->name
         unless (exists $label_hash->{$val});
      # modifications stay
   }
   
   $self->num( @$label_hash{@$labels} );
   return $labels;
};

sub bits {
   my ($self, $bits) = @_;
   unless defined $bits {
      my @nums = @{$self->nums};
      my $max = ceil( (max(keys %{$self->num_hash}) + 1) / 8) * 8 - 1;
      my $is_hex = $max >= 32;  # zero-based, so >=
      
      my $bitmap = '';
      foreach my $i (0 .. $max) { $bitmap .= (@nums ~~ $i) ? '1' : '0'; }
      return '0b'.$bitmap unless $is_hex;
      
      $bits = '0x';
      while (length $bitmap) {
         $bitmap =~ s/^(\d{8})//;
         $bits .= sprintf('%2X', oct "0b$1");
      }
      return $bits;
   }
   
   # process a char at a time, to avoid potential int overflows
   unless ($bits =~ /^0b/i) {
      my $val = $bits;
      $bits = '0b';
      my $is_hex = ($val =~ s/^0x//i);
      $bits .= sprintf('%8b', $is_hex ? hex : ord) for (split //, $val);
   }
   
   # now process through the results (backwards)
   my @nums;
   my $bitmap = scalar reverse $bits;
   $bitmap =~ s/b0$//i;  # 0b
   foreach my $i (0 .. length($bits)-1) {
      $bits =~ s/^(\d)//;
      push @nums, $i if $1;
   }
   
   $self->num( \@nums );
   return $bits;
}

sub as_underscored {
   my ($self) = @_;
   my $num_hash = $self->num_hash;
   my $labels = [ @$num_hash{ @{$self->nums} } ];
   
   for (@$labels) { s/([A-Z])/_$1/g; $_ = lc; }
   return $labels;
}
sub as_uc_camelcase {
   my ($self) = @_;
   my $num_hash = $self->num_hash;
   my $labels = [ @$num_hash{ @{$self->nums} } ];
   
   for (@$labels) { $_ = ucfirst; }
   return $labels;
}
sub as_proper {
   my ($self) = @_;
   my $num_hash = $self->num_hash;
   my $labels = [ @$num_hash{ @{$self->nums} } ];
   
   for (@$labels) { s/([A-Z])/ $1/g; $_ = ucfirst; }
   return $labels;
}

1;