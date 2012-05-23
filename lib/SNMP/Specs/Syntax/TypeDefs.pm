package SNMP::Specs::Syntax::TypeDefs;

use sanity;
use MooX::Types::MooseLike;
use List::Util qw(min max);
use List::MoreUtils qw(all);

# these get repeated a lot
my $true = sub { 1 };
sub __alias_subtype {
   return {
      name       => $_[0],
      subtype_of => $_[1],
      from       => 'SNMP::Specs::Syntax::TypeDefs',
      test       => $true,
      message    => $true,
   };
};

our $TD = [
   ### Helper types to be subtyped ###
   {
      name       => 'Signed32',
      subtype_of => 'Int',
      from       => 'MooX::Types::MooseLike::Base',
      test       => sub { $_[0] >= -2**31 and $_[0] <= 2**31-1 },
      message    => sub { "Not a signed 32-bit integer: $_[0]" },
   },
   {
      name       => 'Unsigned32',
      subtype_of => 'Int',
      from       => 'MooX::Types::MooseLike::Base',
      test       => sub { $_[0] >= 0 and $_[0] <= 2**32-1 },
      message    => sub { "Not a unsigned 32-bit integer: $_[0]" },
   }, 
   {
      name       => 'Unsigned64',
      subtype_of => 'Int',
      from       => 'MooX::Types::MooseLike::Base',
      test       => sub { $_[0] >= 0 and $_[0] <= 2**64-1 },
      message    => sub { "Not a unsigned 64-bit integer: $_[0]" },
   }, 

   ### These are the raw data types, subtyped per RFC2578 ###
   (map { __alias_subtype($_, 'Signed32') } qw(INTEGER INTEGER32 ENum_Value)),
   
   {
      name       => 'ENum_Label',
      subtype_of => 'Str',
      from       => 'MooX::Types::MooseLike::Base',
      # SMIv1 allows hyphens, so we will allow it
      test       => sub { length($_[0]) <= 64 && $_[0] =~ /^[a-z]([a-zA-Z0-9\-]+)$/ },
      message    => sub { "Syntax check for ENum Label fails (RFC2578 7.1.1): $_[0]" },
   },

   {
      name       => 'OCTETSTR',
      subtype_of => 'Str',
      from       => 'MooX::Types::MooseLike::Base',
      # No Unicode allowed!
      test       => sub { length($_[0]) <= 65535 and all { oct <= 255 } split (//, $_[0]) },
      message    => sub { "Syntax check for type OCTETSTR fails (RFC2578 7.1.2): ".substr($_[0], 0, 255)."..." },
   },
   {
      name       => 'OBJECTID',
      subtype_of => 'Str',
      from       => 'MooX::Types::MooseLike::Base',
      test       => sub { 
         $_[0] =~ /^\.?\d{1,10}(?:\.\d{1,10}){0,127}$/
         and all { $_ <= 2**31-1 }
            split (/\./,
               ($_[0] =~ /^\./ ? substr($_[0], 1) : $_[0])
            )
      },
      message    => sub { "Syntax check for type OBJECTID fails (RFC2578 7.1.3): $_[0]" },
   },
   
   (map { __alias_subtype($_, 'OCTETSTR') } qw(OPAQUE BITS)),
   
   {
      name       => 'BITS_Label',
      subtype_of => 'Str',
      from       => 'MooX::Types::MooseLike::Base',
      test       => sub { length($_[0]) <= 64 && $_[0] =~ /^[a-z]([^\W_]+)$/ },
      message    => sub { "Syntax check for BITS Label fails (RFC2578 7.1.4): $_[0]" },
   },
   {
      name       => 'BITS_Array',
      subtype_of => 'ArrayRef',  # ArrayRef[BITS Label]
      from       => 'MooX::Types::MooseLike::Base',
      test       => sub { all { length <= 64 && /^[a-z]([^\W_]+)$/ } @{$_[0]} },
      message    => sub { "Syntax check for BITS Array fails" },
   },

   {  
      name       => 'Raw_IPADDR',
      subtype_of => 'OCTETSTR',
      from       => 'SNMP::Specs::Syntax::TypeDefs',
      test       => sub { length($_[0]) == 4 },
      message    => sub { "Syntax check for IPADDR (raw) fails (RFC2578 7.1.5): (Decimal) ".join(' ', map(ord, split(//, $_[0]))) },
   }, 
   {  
      name       => 'IPADDR',
      subtype_of => 'Str',
      from       => 'MooX::Types::MooseLike::Base',
      test       => sub { $_[0] =~ /^(?:\d{1,3}\.){3}\d{1,3}/ },
      message    => sub { "Syntax check for IPADDR fails (Not a string IP): $_[0]" },
   }, 
   __alias_subtype('Raw_NETADDR', 'Raw_IPADDR'),
   __alias_subtype(    'NETADDR',     'IPADDR'),
   (map { __alias_subtype($_, 'Unsigned32') } qw(COUNTER COUNTER32 GAUGE GAUGE32 Raw_TICKS)),
   __alias_subtype('COUNTER64',   'Unsigned64'),
   
   ### TODO: Need TICKS and Cook_TICKS ###
   
];
our $ORIGINAL_TYPE_COUNT = scalar @$TD;
our %TYPES;
$TYPES{ $_->{name} } = $_ for (@$TD);
 
MooX::Types::MooseLike::register_types($TD, __PACKAGE__);

sub add_typedef {
   my ($self) = @_;  # this isn't really a ::Syntax subclass, but we'll treat it as such here...
   
   unless ($TYPES{ $self->name }) {
      my $defs = [{
         name       => $self->name,
         subtype_of => $self->base_type,
         from       => 'SNMP::Specs::Syntax::TypeDefs',
         message    => sub { "Syntax check for type '".$self->name."' fails: $_[0]" },
         test       => $self->ranges ?
            sub {
               my ($val, $r) = ($_[0], $self->ranges);
               my ($min, $max) = @$r{qw(low high)};
               return 1 if ($max && $max < $min);  # sometimes Net-SNMP gets confused with large numbers
               
               my $len = length($val);
               given ($self->base_type) {
                  when (/INTEGER/i)         { return 0 unless ($val >= $min && $val <= $max); }
                  when (/OCTETSTR|OPAQUE/i) { return 0 unless ($len >= $min && $len <= $max); }
                  default {
                     die "Invalid base type ".$self->base_type." for range checks, found on syntax ".$self->name." (related to ".$self->snmp_data->label.")\nValid types are: INTEGER, OCTETSTR, and OPAQUE";
                  }
               }
               return 1;
            } : sub { 1 },
      }];
      
      if (keys $self->enums) {
         my @evals = values $self->enums;
         my @ekeys = keys   $self->enums;
         my ($min, $max) = (min(@evals), max(@evals));
         die "Invalid base type ".$self->base_type." for enums, found on syntax ".$self->name." (related to ".$self->snmp_data->label.")\nValid types are: INTEGER and BITS"
            unless ($self->base_type =~ /INTEGER|BITS/);
            
         push @$defs, { %{$defs->[0]} };  # clone
         $defs->[0]{name} = 'Raw_'.$self->name;
         # 0 = the raw version, 1 = the 'filtered' version

         if ($self->base_type =~ /INTEGER/) {
            $defs->[0]{test} = sub { $_[0] >= $min && $_[0] <= $max };
            $defs->[1]{test} = sub { $_[0] ~~ @ekeys };
            $defs->[0]{subtype_of} = 'ENum Value';
            $defs->[1]{subtype_of} = 'ENum Label';
         }
         else {
            $defs->[0]{test} = sub { length($_[0]) && length($_[0]) <= int($max / 8) + 1 };
            $defs->[1]{test} = sub { all { $_ ~~ @ekeys } @{$_[0]} };
            $defs->[1]{subtype_of} = 'BITS Array';
         }
      }
      elsif ($self->hint) {
         ### FINISH ####
      }

   }
}

sub validate {
   my ($self, $val) = @_;
   
   ### FINISH ####
}

1;
