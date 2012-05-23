package SNMP::Specs::Syntax;

use sanity;
use Moo;
use MooX::Types::MooseLike qw(Any RegexpRef);
use List::Util qw(min max);
use List::MoreUtils qw(all);

use SNMP::Specs::Syntax::TypeDefs;

has snmp_data => {
   is       => 'ro',
   isa      => 'SNMP::MIB::NODE',
   required => 1,
   handles  => {qw(
      default    defaultValue
      hint       hint
      ranges     ranges
      base_type  type
      units      units
   )},
};
has enum => {
   is       => 'ro',
   isa      => Any,  # could be undefined or SNMP::Specs::Syntax::Enum
   init_arg => undef,
   lazy     => 1,
   default  => sub {
      my ($self) = @_;
      $self->has_enum and SNMP::Specs::Syntax::Enum->new(
         name       => $self->name,
         label_hash => $self->enums,
      );
   },
};

my $num2re = {
   x => '[\da-fA-F]{2}',
   d => '\d{1,3}',
   o => '[0-7]{1,3}',
   a => '[\x00-\xff]',
   t => '.',            # this may or may not work...
};
has hint2re => {
   is       => 'ro',
   isa      => RegexpRef,
   init_arg => undef,
   lazy     => 1,
   default  => sub {
      my ($self) = @_;
      my $hint = $self->hint;
      return \(qr/.+/) if (!$hint or $self->base_type !~ /(?:INTEGER|Unsigned)\d*|OCTETSTR/i or $self->has_enum);
      
      # When the syntax has an underlying primitive type of INTEGER, the hint consists of an integer-format specification, containing two parts.
      
      unless ($self->base_type =~ /OCTETSTR/i) {
         # The first part is a single character suggesting a display format, either:
         # 'x' for hexadecimal, or 'd' for decimal, or 'o' for octal, or 'b' for binary.
         $hint =~ s/([xobd])//;
         my $l = $1;
         
         my $num_re = '^';
         $num_re .= '0' if ($l =~ /[xbo]/);
         $num_re .= $l  if ($l =~ /[xb]/);
         $num_re .= $num2re->{$l};
         $num_re =~ s/\{.+\}$//;
         $num_re .= '+';
         # The second part is always omitted for 'x', 'o' and 'b', and need not be present for 'd'.  If present, the second part
         # starts with a hyphen and is followed by a decimal number, which defines the implied decimal point when rendering the value.
         $num_re .= '(?:\.\d+)*' if ($hint =~ /-\d+/);
         $num_re .= '$';
         
         return \(qr/$num_re/i);
      }
      
      # The five parts of a octet-format specification are:
      
      my $re = "(?x)^(?:\n";  # to prevent mass insanity trying to debug these things, we are going to pretty this up
      my $repeating = 0;
      while (length $hint) {
         # (1)  the (optional) repeat indicator; if present, this part is a '*', and indicates that the current octet of the value is to be used as
         #      the repeat count.  The repeat count is an unsigned integer (which may be zero) which specifies how many times the remainder of this
         #      octet-format specification should be successively applied.  If the repeat indicator is not present, the repeat count is one.

         if ($hint =~ s/^\*//) {
            $repeating = 1;
            $re .= "\t(?:  # repeat indicator\n";  # prepare for a massive capture
         }
         
         # (2)  the octet length: one or more decimal digits specifying the number of octets of the value to be used and formatted by this octet-
         #      specification.  Note that the octet length can be zero.  If less than this number of octets remain in the value, then the lesser
         #      number of octets are used.
         # (3)  the display format, either:  'x' for hexadecimal, 'd' for decimal, 'o' for octal, 'a' for ascii, or 't' for UTF-8.  If the octet
         #      length part is greater than one, and the display format part refers to a numeric format, then network-byte ordering (big-endian
         #      encoding) is used interpreting the octets in the value.  The octets processed by the 't' display format do not necessarily form an
         #      integral number of UTF-8 characters.  Trailing octets which do not form a valid UTF-8 encoded character are discarded.

         if ($hint =~ s/^(\d+)([xdoat])//) {
            ### XXX: This doesn't follow that last part of item 2, but making the   ###
            ### RE too flexible (like allowing {0,X}) would make it mostly useless. ###
            $re .= ("\t" x $repeating+1).'(?:'.$num2re->{$2}.'){'.($1 || 1)."}  # $1$2\n";
         }
         else {  # this is NOT optional!
            warn "Invalid hint format: ".$snmp->hint;
            return \(qr/.+/);
         }
         
         # (4)  the (optional) display separator character; if present, this part is a single character which is produced for display after each
         #      application of this octet-specification; however, this character is not produced for display if it would be immediately followed by the
         #      display of the repeat terminator character for this octet-specification.  This character can be any character other than a
         #      decimal digit and a '*'.
         # (5)  the (optional) repeat terminator character, which can be present only if the display separator character is present and this octet-
         #      specification begins with a repeat indicator; if present, this part is a single character which is produced after all the zero or more
         #      repeated applications (as given by the repeat count) of this octet-specification.  This character can be any character other
         #      than a decimal digit and a '*'.

         if ($hint =~ s/^([^\d\*])?([^\d\*])?//) {
            $re .= ("\t" x $repeating+1).'(?:\Q'.$1.'\E'.($2 ? ')?' : '|$)')."  # separator\n";
            if ($2) {
               unless ($repeating) {
                  warn "Invalid hint format: ".$snmp->hint;
                  return \(qr/.+/);
               }
               $re .= "\t".'){0,255}(?:\Q'.$2.'\E|$)'."  # end repeat + terminator char\n";  # limited to one octet
               $repeating = 0;
            }
         }
      };
      $re = ")+\$\n";  # pattern can be repeated more than once

      $re = qr/$re/;
      return \$re;
   },
};

sub name {
   my ($self) = @_;
   return $self->textualConvention || $self->snmp_data->($self->has_enum ? 'label' : 'type');
}
sub description {
   my ($self) = @_;
   return $self->TCDescription || $self->snmp_data->($self->has_enum ? 'description' : 'type');
}

sub has_enum { !! scalar keys %{$_[0]->snmp_data->enums} }

sub validate {
   my ($self, $val) = @_;
   
   ### FINISH ####
}

1;
