package SNMP::Specs::Column;

use sanity;
use Moo;

sub type { 'Column' }
has snmp_data => {
   is       => 'ro',
   isa      => 'SNMP::MIB::NODE',
   required => 1,
   handles  => {
      qw(
         access      access     
         description description
         name        label       
         moduleID    moduleID   
         objectID    objectID   
         subID       subID      
         status      status     
      ),
   },
};
has syntax => {
   is       => 'ro',
   isa      => 'SNMP::Specs::Syntax',
   lazy     => 1,
   default  => sub {
      my $self = @_;
      my $specs = SNMP::Specs->instance;
      my $snmp = $self->snmp_data;
      my $type = $snmp->textualConvention || $snmp->(%{$snmp->enums} ? 'label' : 'type');
      
      ### XXX: use $specs->_add_type ###
      return $specs->_types->{$type} ||= SNMP::Specs::Syntax->new( snmp_data => $snmp );
   },
}

with 'SNMP::Specs::Node';

has tbl  => {
   is       => 'ro',
   isa      => 'SNMP::Specs::Table::Standard',   ### XXX: Does this work for subclasses? ###
   required => 1,
   handles  => { tblname => 'name' },
   weak_ref => 1,
};

1;