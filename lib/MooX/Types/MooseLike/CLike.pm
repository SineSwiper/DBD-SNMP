package MooX::Types::MooseLike::CLike;
use MooX::Types::MooseLike::Base qw(Int Num Str);
use Exporter 5.57 'import';
our @EXPORT_OK = ();

use Scalar::Util qw(blessed);
use Config;
use POSIX qw(ceil);
use Math::BigInt;
use Math::BigFloat;

# these get repeated a lot
my $true = sub { 1 };
sub __alias_subtype {
   return {
      name       => $_[0],
      subtype_of => $_[1],
      from       => __PACKAGE__,
      test       => $true,
      message    => $true,
   };
};

my $bigtwo = Math::BigFloat->new(2);
$bigtwo->accuracy(41);

sub __integer_builder {
   my ($bits, $signed_names, $unsigned_names) = @_;
   
   my   $signed = shift   @$signed_names;
   my $unsigned = shift @$unsigned_names;
   my $sbits = $bits - 1;
   
   # Some pre-processing math
   my $is_perl_safe = $Config{ivsize} >= ceil($bits / 8);
   my ($neg, $spos, $upos) = $is_perl_safe ?
      (-2**$sbits, 2**$sbits-1, 2**$bits-1) :
      (
         $bigtwo->copy->bpow($sbits)->bmul(-1),
         $bigtwo->copy->bpow($sbits)->bsub(1),
         $bigtwo->copy->bpow( $bits)->bsub(1),
      );
   my $sdigits = ceil( log(2) / log(10) * $sbits );
   my $udigits = ceil( log(2) / log(10) *  $bits );
   
   return (
      {
         name       => $signed,
         subtype_of => 'Int',
         from       => 'MooX::Types::MooseLike::Base',
         test       => $is_perl_safe ?
            sub { $_[0] >= $neg and $_[0] <= $spos } :
            sub {
               my $val = $_[0];
               blessed $val =~ /^Math::BigInt|^bigint/ and
               ( $val->accuracy || $val->precision || $val->div_scale ) >= $udigits and
               $val >= $bigtwo->copy->bpow($sbits)->bmul(-1) and
               $val <= $bigtwo->copy->bpow($sbits)->bsub(1);
            },
         message    => sub { "$_[0] is not a $bits-bit signed integer!" },
      },
      (map { __alias_subtype($_, $signed) } @$signed_names),
      {
         name       => $unsigned,
         subtype_of => 'Int',
         from       => 'MooX::Types::MooseLike::Base',
         test       => $is_perl_safe ?
            sub { $_[0] >= 0 and $_[0] <= $upos } :
            sub {
               my $val = $_[0];
               blessed $val =~ /^Math::BigInt|^bigint/ and
               ( $val->accuracy || $val->precision || $val->div_scale ) >= $udigits and
               $val >= 0 and $val <= $bigtwo->copy->bpow($bits)->bsub(1);
            },
         message    => sub { "$_[0] is not a $bits-bit unsigned integer!" },
      },
      (map { __alias_subtype($_, $unsigned) } @$unsigned_names),
   );
};

sub __float_builder {
   my ($bits, $ebits, $names) = @_;
   my $name = shift @$names;
   my $sbits = $bits - 1 - $ebits;  # remove sign bit and exponent bits = significand precision
   
   my $is_perl_safe = $Config{ivsize} >= ceil($bits / 8);
   my $digits = ceil( log(2) / log(10) * $sbits );
   
   # MAX = (1 + (1 - 2**(-$sbits-1))) * 2**(2**$ebits-1)
   my $emax = $bigtwo->copy->bpow($ebits)->bsub(1);               # Y = (2**$ebits-1)
   my $emin = $bigtwo->copy->bpow(-$sbits-1)->bmul(-1)->badd(2);  # Z = (1 + (1 - X)) = -X + 2  (where X = 2**(-$sbits-1) )
   my $max  = $bigtwo->copy->bpow($emax)->bmul($emin);            # MAX = 2**Y * Z
   
   return (
      {
         name       => $name,
         subtype_of => 'Num',
         from       => 'MooX::Types::MooseLike::Base',
         test       => sub {
            my $val = $_[0];
            $is_perl_safe or (
               blessed $val =~ /^Math::BigFloat|^bignum/ and
               ( $val->accuracy || $val->precision || $val->div_scale ) >= $digits
            ) and
            $val >= -$max and $val <= $max;
         },
         message    => sub { "$_[0] is not a $bits-bit floating point number!" },
      },
      (map { __alias_subtype($_, $name) } @$names),
   );
};

sub __char_builder {
   my ($bits, $names) = @_;
   my $name = shift @$names;

   return (
      {
         name       => $name,
         subtype_of => 'WChar',
         from       => __PACKAGE__,
         test       => sub { ord($_[0]) < 2**$bits },
         message    => sub { "$_[0] is not a $bits-bit character!" },
      },
      (map { __alias_subtype($_, $name) } @$names),
   );
}

my $type_definitions = [
   ### Integer definitions ###
                             # being careful with char here...
   __integer_builder(  4, [qw(SNibble SSemiOctet Int4 Signed4)],            [qw(Nibble SemiOctet UInt4 Unsigned4)]),
   __integer_builder(  8, [qw(SByte SOctet TinyInt Int8 Signed8)],          [qw(Byte Octet UnsignedTinyInt UInt8 Unsigned8)]),
   __integer_builder( 16, [qw(Short SmallInt Int16 Signed16)],              [qw(UShort UnsignedSmallInt UInt16 Unsigned16)]),
                             # cannot alias Int because it is already taken...
   __integer_builder( 32, [qw(Int32 Signed32)],                             [qw(UInt UnsignedInt UInt32 Unsigned32)]),
   __integer_builder( 64, [qw(Long LongLong BigInt Int64 Signed64)],        [qw(ULong UnsignedBigInt UInt64 Unsigned64)]),
   __integer_builder(128, [qw(SOctaWord SDoubleQuadWord Int128 Signed128)], [qw(OctaWord DoubleQuadWord UInt128 Unsigned128)]),

   ### Float definitions ###
   __float_builder( 16,  4, [qw(ShortFloat)]),
   __float_builder( 16,  5, [qw(Half Float16 Binary16 Decimal16)]),
   __float_builder( 32,  8, [qw(Single Float Float32 Binary32 Decimal32)]),
   __float_builder( 40,  8, [qw(ExtendedSingle Float40 Binary32 Decimal32)]),
   __float_builder( 64, 11, [qw(Double Float64 Binary64 Decimal64)]),
   __float_builder( 80, 15, [qw(ExtendedDouble Float80 Binary80 Decimal80)]),
   __float_builder(128, 15, [qw(Decimal Quadruple Quad Float128 Decimal128)]),

   ### Char definitions ###
   {
      name       => 'WChar',
      subtype_of => 'Str',
      from       => 'MooX::Types::MooseLike::Base',
      test       => sub { length($_[0]) == 1 },  # length() will do a proper Unicode char length
      message    => sub { "$_[0] is not a single character!" },
   },
   __char_builder( 8, [qw(Char Char8)]),
   __char_builder(16, [qw(Char16)]),
   __char_builder(32, [qw(Char32)]),
   __char_builder(48, [qw(Char48)]),
   __char_builder(64, [qw(Char64)]),
];
 
MooX::Types::MooseLike::register_types($type_definitions, __PACKAGE__);  ### TODO: MooseX translation ###
our %EXPORT_TAGS = ('all' => \@EXPORT_OK);
 
1;
 
__END__
