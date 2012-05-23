package SNMP::Specs::Value;

use sanity;
use Moo;
use MooX::Types::MooseLike::Base qw/Object/;

use SNMP::Specs::Syntax::Raw;
use SNMP::Specs::Syntax::Filtered;
use SNMP::Specs::Syntax::Cooked;

has column => {
   is       => 'ro',
   isa      => 'SNMP::Specs::Column',
   required => 1,
   weak_ref => 1,
   handles  => ['syntax'],
};

has _raw_obj => {
   is        => 'ro',
   isa       => 'SNMP::Specs::Syntax::Raw',
   init_arg  => undef,
   lazy      => 1,
   predicate => 1,
   default   => sub {
      my ($self) = @_;
      SNMP::Specs::Syntax::Raw->new(
         value_obj => $self,
         val       => $self->_has_last_write ? $self->_current_val : $self->syntax->default,
      );
   },
   handles  => { raw => 'val' },
};
has _filtered_obj => {
   is        => 'ro',
   isa       => 'SNMP::Specs::Syntax::Filtered',
   init_arg  => undef,
   lazy      => 1,
   predicate => 1,
   default   => sub {
      my ($self) = @_;
      SNMP::Specs::Syntax::Filtered->new(
         value_obj => $self,
         val       => $self->_has_last_write ? $self->_current_val : $self->syntax->default,
      );
   },
   handles  => ['val'],
};
has _cooked_obj => {
   is        => 'rw',
   isa       => 'SNMP::Specs::Syntax::Cooked',
   init_arg  => undef,
   lazy      => 1,
   predicate => 1,
   default   => sub {
      my ($self) = @_;
      SNMP::Specs::Syntax::Cooked->new(
         value_obj => $self,
         val       => $self->_has_last_write ? $self->_current_val : $self->syntax->default,
      );
   },
};

# smart handle for _cooked_obj
sub cooked {
   my ($self, $val) = @_;
   defined $val ? $self->_cooked_obj->val($val) : $self->_cooked_obj->obj;
}

has _last_write => {
   is        => 'rw',
   isa       => 'Object',
   init_arg  => undef,
   lazy      => 1,
   predicate => 1,
   handles   => { '_current_val' => 'val' },
};

# the DWIM set
sub set {
   my ($self, $val) = @_;
   ref $val ? $self->cooked($val) : 
      $self->_has_last_write ? $self->_current_val($val) : $self->val($val);
}

##############################################################################
# Misc. functions (used by the Syntax::* classes)

sub _parsehex ($$$) {
   my ($self, $val, $len, $re) = @_;
   $val = lc($val);

   # define some lengths (acronyms: two-minus, four-minus, two, one-plus)
   my ($ltm, $lfm) = map { int(int($len) / $_ - 1) } qw(2 4);
   my ($lt,  $lop) = (int($len) / 2, $len + 1);
   
   # in the form of #, for minimum only
   if ($len =~ /\,/) { $ltm.=','; $lfm.=','; $lt.=','; } 

   given ($val) {
      when (/^$re$/)                                { return '!';   }  # correct format
      when (/^[0-9a-f]{2}(?::[0-9a-f]{2}){$ltm}$/)  { return 's';   }  # String (in IEEE 2:2:2:2:2:2 format)
      when (/^[0-9a-f]{4}(?:\.[0-9a-f]{4}){$lfm}$/) { return 's';   }  # String (in 4.4.4 format)
      when (/^([0-9a-f]{$len})$/)                   { return 's';   }  # String (in bare word format)
      when (/^\d{1,3}(?:\.\d{1,3}){$ltm}$/)         { return 'o';   }  # ##-byte OBJECTID
      when (/^.{$lt}$/s)                            { return 'b';   }  # ##-byte binary
      when (/^[\s\!-\@\[-f\{-\~]{$lop,}$/)          { return 's';   }  # String (in unknown, but ASCII format)
      default                                       { return undef; }  # (giving up...)
   }
}

sub _addr2hex ($$) {
   my ($self, $val, $t) = @_;

   given ($t) {
      when ('o') { $val =~ s/(\d{1,3})(?:\.|$)/sprintf('%02x', $1)/ge; }  # decimal/OBJECTID
      when ('b') { $val =~ s/(.)/unpack('H2', $1)/sge;                 }  # binary
      default    { $val =~ s/[^0-9a-fA-F]+//g;                         }  # ASCII string (with hex)
   }

   return lc($val);
}

sub _hint2sprintf ($) {
   my ($self) = @_;
   my $snmp = $self->column->snmp_data;
   my ($hint, $type) = @$snmp{qw(hint type)};
   return ($type eq 'OCTETSTR') ? '%s' : '%d' unless defined $hint;

   # String format specification
   if ($type eq 'OCTETSTR') {
      my $format = $hint;
      $format =~ s/\%/\%\%/g;  # handle literal-% before we litter the landscape with percent signs

      # If the syntax of the TEXTUAL-CONVENTION has an underlying primitive type of OCTET STRING,
       
      # <octetDisplayHint> = number <displayFormat> [<sepChar>]
      #                      number <displayFormat> [<sepChar> [<repTermChar>]]
       
      # number - unsigned integer
      # <displayFormat> - d | a | o | x
      # <sepChar> - separator character: any character except * and decimal digit
      # <repTermChar> - repeat terminator character: any character other than * and decimal digit
       
      # Example for DISPLAY-HINT is "2a:"
       
      # where 2 is the number
      # a is the display format
      # : is the separator character
      
      
      
   }
   # Integer format specification
   else {
      # <intDisplayHint> = "d" ["-" number] | <singleChar>
      # <singleChar> = o | x | b

      # The hint can be a single character for the display format, 'x' for hexadecimal, 'd' for decimal, 'o' for octal and 'b' for binary.

      # For displaying the value in the decimal format, the "d" can be followed by a hyphen and a decimal number,
      # which defines the implied decimal point for the value.
      return "%#$1"      if ($hint =~ /([xob])/);
      return '%.'.$1.'d' if ($hint =~ /d-(\d+)/);
      return '%d';
   }
}

sub _bin2dd {
   my ($self, $val) = @_;
   return $val if     ($val =~ /^\d{1,3}(\.\d{1,3})+$|^\d+$/);
   $val =~ s/(.)(?=.)/unpack('C', $1).'.'/sge;  # binary to dotted-decimal
   $val =~ s/(.)$/unpack('C', $1)/se;
   return $val;
}

sub _dd2bin {
   my ($self, $val) = @_;
   return $val unless ($val =~ /^\d{1,3}(\.\d{1,3})+$/);
   $val =~ s/(\d{1,3})(?:\.|$)/chr($1)/ge;      # dotted-decimal to binary
   return $val;
}


1;