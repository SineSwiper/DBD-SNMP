package SNMP::Specs::Table::LocalTemp;

use sanity;
use Moo;

extends 'SNMP::Specs::Table::Standard';

sub table_type { 'LOCAL TEMPORARY' }

### XXX: Removal of snmp_data? ###

1;