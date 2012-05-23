package SNMP::Specs::Table::Global;

use sanity;
use Moo;

extends 'SNMP::Specs::Table::Standard';

sub table_type { 'VIEW' }

1;