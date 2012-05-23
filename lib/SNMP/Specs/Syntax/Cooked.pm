package SNMP::Specs::Syntax::Cooked;

use sanity qw(sanity -namespace::sweep);
use List::Util qw(first max);
use Scalar::Util qw(blessed);
use POSIX qw(strftime);
use Storable ();
use namespace::sweep -also => qr/^build_/;

use Moo;
use MooX::Types::MooseLike qw/Any Object Bool/;

has value_obj => {
   is       => 'ro',
   isa      => 'SNMP::Specs::Value',
   required => 1,
   weak_ref => 1,
};

# Cooked operates a little differently, using obj for the real object and val for the underlying value
has obj => {
   is        => 'rwp',
   isa       => Object,
   predicate => 1,
   default   => sub { die "First call to ->obj must be a set operation"; },   
};

# Given that the object acts at the real storage for val,
# this turns into a "smart handle", instead of an attribute.
sub val {
   my ($self, $val) = @_;
   my $ssv = $self->value_obj;
   
   # set
   if (defined $val) {
      ### Happy coincidence: This is a regular method, not an after trigger, so
      ### normally we should set our transformed value.  However, propagation is done
      ### first, so we can just return.
      return $val unless ($self->_should_propagate);
      
      # de-blessing
      my $obj;
      if (blessed $val) {
         my $obj = $val;
         my $method = $self->_val_handle(0, $val);
         $val = $self->$method() if $method;  # otherwise, let's hope that overloads work
      }
      
      # use filtered as a value transformer by propagating first
      # (same propagation rules apply)
      $self->_should_propagate(0);
      if    ($ssv->_has_raw)      { $ssv->raw($val); }
      elsif ($ssv->_has_filtered) { $ssv->val($val); }
      $self->_should_propagate(1);
      $val = $ssv->val;  # may auto-create if filtered didn't exist before
      
      $ssv->_last_write($self);  # We are the new leaders

      # if the object already exists, just re-use it
      if ($self->has_obj) {
         my $method = $self->_val_handle(1);
         if ($method eq 'new') {  # constructor only
            return $self->_set_obj  ($obj) if ($obj && blessed($obj) eq blessed($self->obj));
            return $self->_build_obj($val);
         }
         return $self->$method($val);
      }
      
      $self->_build_obj($val);
      return $val;
   }
   
   # get
   my $method = $self->_val_handle;
   die "Cooked object ".ref($obj)." not recognized for ".$ssv->syntax unless $method;
   return $self->$method();
}
# this is infinite loop protection
has _should_propagate => {
   is      => 'rw',
   isa     => Bool,
   default => sub { 1 }
}

sub _val_handle {
   my ($self, $is_write, $obj) = @_;
   $obj //= $self->obj;  # will autodie if get was the first call
   for (ref $obj) {
      when ('Number::Object')        { return 'val';   }
      when ('Class::Value::String')  { return 'value'; }
      when ('Class::Value::Boolean') { return 'value'; }
      when ('NetAddr::IP')           { return $is_write ? 'new' : 'full';      }
      when ('NetAddr::MAC')          { return $is_write ? 'new' : 'as_basic';  }
      when ('NetAddr::BridgeID')     { return $is_write ? 'new' : 'bridge_id'; }
      default                        { return undef; }
   }
}

# custom builder (this would normally be _transform, but it happens only once)
sub _build_obj {
   my ($self, $val) = @_;
   my $ssv = $self->value_obj;
   
   my $sub;
   $sub = 'build_'.$ssv->syntax->name;
   $sub = 'build_'.$ssv->syntax->base_type unless $self->can($sub);
   $sub = 'build_NOOP'                     unless $self->can($sub);
   $sub = 'build_ENum' if (%{$ssv->syntax->enums});
   $sub = 'build_BITS' if ($ssv->syntax->base_type eq 'BITS');
   die "Cooked values should always have a class, yet somehow we're defaulting to NOOP for ".$ssv->syntax."..."
      if ($sub eq 'build_NOOP');
   
   $self->_set_obj( $self->$sub($val) );
}

##############################################################################
# Build Subroutines

### FIXME: Transforms for these...

# ["TestAndIncr",DBI::SQL_INTEGER(),    32, undef, undef,        undef,     1,     0,     2,     1,     1,     0,  "TestAndIncr",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
# [ "RowStatus", DBI::SQL_INTEGER(),     4, undef, undef,        undef,     1,     0,     2,     1,     1,     0,    "RowStatus",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
# ["StorageType", DBI::SQL_INTEGER(),    4, undef, undef,        undef,     1,     0,     2,     1,     1,     0,  "StorageType",     0,     0, DBI::SQL_INTEGER(),        undef,     2, undef],
# ["TDomain",    DBI::SQL_VARCHAR(),  1408,   "'",   "'",        undef,     1,     0,     3, undef,     1, undef,      "TDomain", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],
# ["TAddress",   DBI::SQL_VARCHAR(),   255,   "'",   "'",        undef,     1,     0,     3, undef,     1, undef,     "TAddress", undef, undef, DBI::SQL_VARCHAR(),        undef, undef, undef],

sub build_INTEGER {
   return Number::Object->new($_[1]);
}
*build_INTEGER32  = \&build_INTEGER;
*build_Integer    = \&build_INTEGER;
*build_Integer32  = \&build_INTEGER;
*build_Unsigned32 = \&build_INTEGER;

sub build_COUNTER {
   return Number::Object->new($_[1], {
      load_plugins => [qw/Counter/],
   });
}
*build_COUNTER   = \&build_COUNTER;
*build_COUNTER64 = \&build_COUNTER;
*build_GAUGE     = \&build_COUNTER;
*build_GAUGE64   = \&build_COUNTER;
*build_Gauge     = \&build_COUNTER;
*build_Gauge32   = \&build_COUNTER;
*build_Gauge64   = \&build_COUNTER;
*build_Counter   = \&build_COUNTER;
*build_Counter32 = \&build_COUNTER;
*build_Counter64 = \&build_COUNTER;

sub build_OCTETSTR {
   return Class::Value::String->new($_[1]);
}
*build_OPAQUE        = \&build_OCTETSTR;
*build_DisplayString = \&build_OCTETSTR;

sub build_Enum {
   my ($self, $val) = @_;
   my $enum_val = SNMP::Specs::Syntax::EnumValue->new( enum_obj => $self->value_obj->syntax->enum );
   $enum_val->label($val);
   return $enum_val;
}
sub build_BITS {
   my ($self, $val) = @_;
   my $enum_val = SNMP::Specs::Syntax::BitsValue->new( enum_obj => $self->value_obj->syntax->enum );
   $enum_val->bits($val);
   return $enum_val;
}

sub build_TruthValue {
   return Class::Value::Boolean->new($_[1]);
}

sub build_IPADDR {
   return NetAddr::IP->new($_[1]);
}
*build_IPADDR          = \&build_IPADDR;
*build_NETADDR         = \&build_IPADDR;
*build_InetAddress     = \&build_IPADDR;
*build_InetAddressIPv4 = \&build_IPADDR;
*build_InetAddressIPv6 = \&build_IPADDR;
*build_IpV4orV6Addr    = \&build_IPADDR;
*build_Ipv6AddressIfIdentifierTC = \&build_IPADDR;

sub build_MacAddress {
   return NetAddr::MAC->new($_[1]);
}
*build_PhysAddress = \&build_MacAddress;

sub build_BridgeID {
   return NetAddr::BridgeID->new($_[1]);
}

sub build_TIMETICKS {
   return DateTime::Format::SNMP::parse_interval($_[1], 'f');
}
*build_TICKS        = \&build_TIMETICKS;
*build_TimeStamp    = \&build_TIMETICKS;
*build_TimeInterval = \&build_TIMETICKS;
*build_TimeTicks    = \&build_TIMETICKS;

sub build_DateAndTime {
   return DateTime::Format::SNMP::parse_datetime($_[1], 'f');
}

### FIXME: ###
# sub transform_RowPointer {
# *transform_OBJECTID        = \&transform_RowPointer;
# *transform_AutonomousType  = \&transform_RowPointer;
# *transform_InstancePointer = \&transform_RowPointer;
# *transform_VariablePointer = \&transform_RowPointer;

1;
