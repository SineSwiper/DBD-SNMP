package SNMP::Specs::Table::Notify;

use sanity;
use Moo;

extends 'SNMP::Specs::Table::Standard';

sub table_type { 'NOTIFY OBJECT' }

1;