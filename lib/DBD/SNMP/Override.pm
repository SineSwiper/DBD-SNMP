##############################################################################
# DBD::SNMP::Override Module                                                 #
# E-mail: Brendan Byrd <Perl@resonatorsoft.org>                              #
##############################################################################

##############################################################################
# DBD::SNMP::Override

# Overrides various functions from various modules that are not part of the
# standard set of overloads for SQL::Statement drivers

package   # hide from PAUSE
   DBD::SNMP::Override;

use sanity;
use Net::SNMP ();
use Net::SNMP::Dispatcher ();
use Net::SNMP::Transport ();
BEGIN { eval 'use Net::SNMP::XS;'; }  # use it if we got it

use SQL::Parser ();

our $VERSION  = $DBD::SNMP::VERSION;

##############################################################################
# Net::SNMP

# There are several patches here for Net::SNMP to improve the effectiveness
# of the Dispatcher, as well as a few other small tweaks.  Until David 
# agrees with them and adds them into Net::SNMP, these overrides will 
# use the new code for this module.

# The patches can be found in the following CPAN RT tickets:

# SNMP.pm Debug flag patch
   # https://rt.cpan.org/Ticket/Display.html?id=70580

# Event Sub/Host logging patch for Dispatcher.pm
   # https://rt.cpan.org/Ticket/Display.html?id=70583

# Small change to make Net::SNMP::PDU::var_bind_list more compatible with Net::SNMP::XS
   # https://rt.cpan.org/Ticket/Display.html?id=70584

# Receive buffer emptying patch
   # https://rt.cpan.org/Ticket/Display.html?id=70586

# Max Requests per host/IP patch
   # https://rt.cpan.org/Ticket/Display.html?id=70589

package Net::SNMP;

# (our doesn't scope within packages, which is stupid...)
our (%EXPORT_TAGS, $DEBUG_MASK, $DEBUG, $DISPATCHER);
*EXPORT_TAGS = \%Net::SNMP::EXPORT_TAGS;
*DEBUG_MASK  = \$Net::SNMP::DEBUG_MASK;
*DEBUG       = \$Net::SNMP::DEBUG;
*DISPATCHER  = \$Net::SNMP::DISPATCHER;

###################
# Extra debug flag

push @{$EXPORT_TAGS{debug}}, 'DEBUG_SNMP';

sub DEBUG_SNMP        { 0x01 }  # Main Net::SNMP functions

our $DEBUG_MASK = DEBUG_NONE;   # Debug mask
our $DEBUG      = 0;            # Debug mode for just Net::SNMP

sub debug
{
   my (undef, $mask) = @_;

   if (@_ == 2) {

      $DEBUG_MASK = ($mask =~ /^\d+$/) ? $mask : ($mask) ? DEBUG_ALL : DEBUG_NONE;

      $DEBUG = $DEBUG_MASK & DEBUG_SNMP;
      eval { Net::SNMP::Message->debug($DEBUG_MASK & DEBUG_MESSAGE);              };
      eval { Net::SNMP::Transport->debug($DEBUG_MASK & DEBUG_TRANSPORT);          };
      eval { Net::SNMP::Dispatcher->debug($DEBUG_MASK & DEBUG_DISPATCHER);        };
      eval { Net::SNMP::MessageProcessing->debug($DEBUG_MASK & DEBUG_PROCESSING); };
      eval { Net::SNMP::Security->debug($DEBUG_MASK & DEBUG_SECURITY);            };

   }

   return $DEBUG_MASK;
}

######################
# Max requests option

{
   my @trans_argv = qw(
      hostname (?:de?st|peer)?(?:addr|port) (?:src|sock|local)(?:addr|port)
      maxrequests? maxmsgsize mtu retries timeout domain listen
   );

   *new = \&Net::SNMP::new;
}

sub max_requests
{
   my $this = shift;

   if (!defined $this->{_transport}) {
      return $this->_error('The session is closed');
   }

   if (defined (my $max_requests = $this->{_transport}->max_requests(@_))) {
      return $max_requests;
   }

   return $this->_error($this->{_transport}->error());
}

####################################################################
# send_pdu_priority changes for receive/requests Dispatcher changes

# (reimplementing entire functions just for the send_pdu -> send_pdu_priority change...)

sub _perform_discovery
{
   my ($this) = @_;

   return TRUE if ($this->{_security}->discovered());

   # RFC 3414 - Section 4: "Discovery... ...may be accomplished by
   # generating a Request message with a securityLevel of noAuthNoPriv,
   # a msgUserName of zero-length, a msgAuthoritativeEngineID value of
   # zero length, and the varBindList left empty."

   # Create a new PDU
   if (!defined $this->_create_pdu()) {
      return $this->_discovery_failed();
   }

   # Create the callback and assign it to the PDU
   $this->{_pdu}->callback(
      sub
      {
         $this->{_pdu} = $_[0];
         $this->_error_clear();
         if ($this->{_pdu}->error()) {
            $this->_error($this->{_pdu}->error() . ' during discovery');
         }
         $this->_discovery_engine_id_cb();
         return;
      }
   );

   # Prepare an empty get-request
   if (!defined $this->{_pdu}->prepare_get_request()) {
      $this->_error($this->{_pdu}->error());
      return $this->_discovery_failed();
   }

   # Send the PDU (as a priority, so that we don't build up a
   # large discovery queue)
   $DISPATCHER->send_pdu_priority($this->{_pdu});

   if (!$this->{_nonblocking}) {
      snmp_dispatcher();
   }

   return ($this->{_error}) ? $this->_error() : TRUE;
}

sub _discovery_engine_id_cb
{
   my ($this) = @_;

   # "The response to this message will be a Report message containing
   # the snmpEngineID of the authoritative SNMP engine...  ...with the
   # usmStatsUnknownEngineIDs counter in the varBindList."  If another
   # error is returned, we assume snmpEngineID discovery has failed.

   if ($this->{_error} !~ /usmStatsUnknownEngineIDs/) {
      return $this->_discovery_failed();
   }

   # Clear the usmStatsUnknownEngineIDs error
   $this->_error_clear();

   # If the security model indicates that discovery is complete,
   # we send any pending messages and return success.  If discovery
   # is not complete, we probably need to synchronize with the
   # remote authoritative engine.

   if ($this->{_security}->discovered()) {
      DEBUG_INFO('discovery complete');
      return $this->_discovery_complete();
   }

   # "If authenticated communication is required, then the discovery
   # process should also establish time synchronization with the
   # authoritative SNMP engine.  This may be accomplished by sending
   # an authenticated Request message..."

   # Create a new PDU
   if (!defined $this->_create_pdu()) {
      return $this->_discovery_failed();
   }

   # Create the callback and assign it to the PDU
   $this->{_pdu}->callback(
      sub
      {
         $this->{_pdu} = $_[0];
         $this->_error_clear();
         if ($this->{_pdu}->error()) {
            $this->_error($this->{_pdu}->error() . ' during synchronization');
         }
         $this->_discovery_synchronization_cb();
         return;
      }
   );

   # Prepare an empty get-request
   if (!defined $this->{_pdu}->prepare_get_request()) {
      $this->_error($this->{_pdu}->error());
      return $this->_discovery_failed();
   }

   # Send the (priority) PDU
   $DISPATCHER->send_pdu_priority($this->{_pdu});

   if (!$this->{_nonblocking}) {
      snmp_dispatcher();
   }

   return ($this->{_error}) ? $this->_error() : TRUE;
}

# (reimplementing _get_entries_cb for DEBUG_INFO removals and send_pdu_priority changes)

sub _get_entries_cb
{
   my ($this, $argv) = @_;

   # Get the current callback.
   my $callback = $this->{_pdu}->callback();

   # Assign the user callback to the PDU.
   $this->{_pdu}->callback($argv->{callback});

   # Iterate through the response OBJECT IDENTIFIERs.  The response(s)
   # will (should) be grouped in the same order as the columns that
   # were requested.  We use this assumption to map the response(s) to
   # get-next/bulk-requests.  When using get-bulk-requests, "holes" in
   # the table may cause certain columns to run ahead or behind other
   # columns, so we cache all entries and sort it out when processing
   # the row.

   my $list       = $this->var_bind_list();
   my $types      = $this->var_bind_types();
   my @names      = $this->var_bind_names();
   my $max_index  = (defined $argv->{last_index}) ? $argv->{last_index} : '0';
   my $last_entry = TRUE;
   my $cache      = {};

   while (@names) {

      my @row = ();
      my $row_index = undef;

      # Match up the responses to the requested columns.

      for my $col_num (0 .. $#{$argv->{columns}}) {

         my $name = shift @names;

         if (!defined $name) {

            # Due to transport layer limitations, the response could have
            # been truncated, so do not consider this the last entry.

            DEBUG_INFO('column number / oid number mismatch');
            $last_entry = FALSE;
            @row = ();
            last;
         }

         my $column = quotemeta $argv->{columns}->[$col_num];
         my $index;

         if ($name =~ m/$column\.(\d+(:?\.\d+)*)/) {

            # Requested column and response column match up.
            $index = $1;

         } else {

            # The response column does not map to the the request, there
            # could be a "hole" or we are out of entries.

            $last_entry = TRUE;
            next;
         }

         # Validate the index of the response.

         if ((defined $argv->{start_index}) &&
             (oid_lex_cmp($index, $argv->{start_index}) < 0))
         {
            DEBUG_INFO(
               'index [%s] less than start_index [%s]',
               $index, $argv->{start_index}
            );
            if (oid_lex_cmp($index, $max_index) > 0) {
               $max_index = $index;
               $last_entry = FALSE;
               DEBUG_INFO('new max_index [%s]', $max_index);
            }
            next;
         } elsif ((defined $argv->{end_index}) &&
                  (oid_lex_cmp($index, $argv->{end_index}) > 0))
         {
            DEBUG_INFO(
               'last_entry: index [%s] greater than end_index [%s]',
                $index, $argv->{end_index}
            );
            $last_entry = TRUE;
            next;
         }

         # Cache the current column since it falls into the requested range.

         $cache->{$index}->[$col_num] = $name;

         # To handle "holes" in the conceptual row, checks need to be made
         # so that the lowest index for each group of responses is used.

         if (!defined $row_index) {
            $row_index = $index;
         }

         my $index_cmp = oid_lex_cmp($index, $row_index);

         if ($index_cmp == 0) {

            # The index for this response entry matches, so fill in
            # the corresponding row entry.

            $row[$col_num] = $name;

         } elsif ($index_cmp < 0) {

            # The index for this response is less than the current index,
            # so we throw out everything and start over.

            @row = ();
            $row_index = $index;
            $row[$col_num] = $name;

         } else {

            # There must be a "hole" in the row, do nothing here since this
            # entry was cached and will hopefully be taken care of later.

            DEBUG_INFO(
               'index [%s] greater than current row_index [%s]',
               $index, $row_index
            );

         }

      }

      # No row information found, continue.

      if (!@row || !defined $row_index) {
         next;
      }

      # Now store the results for the conceptual row.

      for my $col_num (0 .. $#{$argv->{columns}}) {

         # Check for cached values that may have been lost due to "holes".
         if (!defined $row[$col_num]) {
            if (defined $cache->{$row_index}->[$col_num]) {
               DEBUG_INFO('using cache: %s', $cache->{$row_index}->[$col_num]);
               $row[$col_num] = $cache->{$row_index}->[$col_num];
            } else {
               next;
            }
         }

         # Actually store the results.
         if (!exists $argv->{entries}->{$row[$col_num]}) {
            $last_entry = FALSE;
            $argv->{entries}->{$row[$col_num]} = $list->{$row[$col_num]};
            $argv->{types}->{$row[$col_num]}   = $types->{$row[$col_num]};
         } else {
            DEBUG_INFO('not adding duplicate: %s', $row[$col_num]);
         }

      }

      # Execute the row callback if it is defined.
      $this->_get_entries_exec_row_cb($argv, $row_index, \@row);

      # Store the maximum index found to be used for the next request.
      if (oid_lex_cmp($row_index, $max_index) > 0) {
         $max_index = $row_index;
      }

   }

   # Make sure we are not stuck (looping) on a single index.

   if (defined $argv->{last_index}) {
      if (oid_lex_cmp($max_index, $argv->{last_index}) > 0) {
         $argv->{last_index} = $max_index;
      } elsif ($last_entry == FALSE) {
         DEBUG_INFO(
            'last_entry: max_index [%s] not greater than last_index [%s])',
            $max_index, $argv->{last_index}
         );
         $last_entry = TRUE;
      }
   } else {
      $argv->{last_index} = $max_index;
   }

   # If we have not reached the last requested entry, generate another
   # get-next/bulk-request message.

   if ($last_entry == FALSE) {
      my $vbl = [ map { join q{.}, $_, $max_index } @{$argv->{columns}} ];
      $this->_get_table_entries_request_next($argv, $callback, $vbl);
      return;
   }

   # Clear the PDU error on a noSuchName(2) error status.
   if ($this->error_status() == 2) {
      $this->{_pdu}->error(undef);
   }

   # Check for an empty or nonexistent table.
   if (!$this->{_pdu}->error() && !defined $argv->{entries}) {
      $this->{_pdu}->error('The requested entries are empty or do not exist');
   }

   # Copy the table to the var_bind_list.
   $this->{_pdu}->var_bind_list($argv->{entries}, $argv->{types});

   # Execute the row callback, if there has been an error.
   if ($this->{_pdu}->error()) {
      $this->_get_entries_exec_row_cb($argv, 0, []);
   }

   # Notify the command generator to process the results.
   $this->{_pdu}->process_response_pdu();

   return;
}

sub _get_table_entries_request_next
{
   my ($this, $argv, $callback, $vbl) = @_;

   # Copy the current PDU for use in error conditions.
   my $pdu = $this->{_pdu};

   # Create a new PDU.
   if (!defined $this->_create_pdu()) {
      $pdu->status_information($this->error());
      return;
   }

   # Override the callback with the saved callback.
   $this->{_pdu}->callback($callback);

   # Use the contextEngineID and contextName from the previous request
   # because the values stored in the object could change.

   if (defined $pdu->context_engine_id()) {
      $this->{_pdu}->context_engine_id($pdu->context_engine_id());
   }

   if (defined $pdu->context_name()) {
      $this->{_pdu}->context_name($pdu->context_name());
   }

   # Create the appropriate request.

   if ($argv->{use_bulk}) {
      if (!defined $this->{_pdu}->prepare_get_bulk_request(0,
                                                           $argv->{max_reps},
                                                           $vbl))
      {
         $pdu->status_information($this->{_pdu}->error());
         return;
      }
   } else {
      if (!defined $this->{_pdu}->prepare_get_next_request($vbl)) {
         $pdu->status_information($this->{_pdu}->error());
         return;
      }
   }

   # Send the next PDU as a priority
   # (Existing requests get priority over new ones)
   $DISPATCHER->send_pdu_priority($this->{_pdu});

   return;
}

1;

##############################################################################
# Net::SNMP::Dispatcher

package Net::SNMP::Dispatcher;

# (our doesn't scope within packages, which is stupid...)
our (%SUBREFS, $MESSAGE_PROCESSING);
*SUBREFS = \%Net::SNMP::Dispatcher::SUBREFS;
*MESSAGE_PROCESSING = \$Net::SNMP::Dispatcher::MESSAGE_PROCESSING;

# (unfortunately, a huge portion of this module needs to be replaced,
# since there are changes scattered everywhere...)

#########################
# Event Sub/Host logging

sub _HOSTNAME  { 5 }      # Destination hostname

# Code reference to sub name matching

# (since we are monkey patching here, we actually need to re-run this %SUBREF
# thing later)

INIT
{
   %SUBREFS = map { *{ $Net::SNMP::Dispatcher::{$_} }{CODE} => '&'.$_ } (keys %Net::SNMP::Dispatcher::);
}

sub _event_info
{
   my (undef, $event) = @_;
   return sprintf('[%s ==> %s for %s]', $event, $SUBREFS{$event->[_CALLBACK][0]}, $event->[_HOSTNAME]);
}

sub _event_create
{
   my ($this, $time, $hostname, $callback) = @_;

   # Create a new event anonymous array and add it to the queue.
   # The event is initialized based on the currrent state of the
   # Dispatcher object.  If the Dispatcher is not currently running
   # the event needs to be created such that it will get properly
   # initialized when the Dispatcher is started.

   return $this->_event_insert(
      [
         $this->{_active},                          # State of the object
         $this->{_active} ? time() + $time : $time, # Execution time
         $callback,                                 # Callback reference
         undef,                                     # Previous event
         undef,                                     # Next event
         $hostname,                                 # Hostname of destination
      ]
   );
}

sub _event_insert
{
   my ($this, $event) = @_;
   my $event_info = $this->_event_info($event);

   # If the head of the list is not defined, we _must_ be the only
   # entry in the list, so create a new head and tail reference.

   if (!defined $this->{_event_queue_h}) {
      DEBUG_INFO('created new head and tail %s', $event_info);
      return $this->{_event_queue_h} = $this->{_event_queue_t} = $event;
   }

   # Estimate the midpoint of the list by calculating the average of
   # the time associated with the head and tail of the list.  Based
   # on this value either start at the head or tail of the list to
   # search for an insertion point for the new Event.

   my $midpoint = (($this->{_event_queue_h}->[_TIME] +
                    $this->{_event_queue_t}->[_TIME]) / 2);

   if ($event->[_TIME] >= $midpoint) {

      # Search backwards from the tail of the list

      for (my $e = $this->{_event_queue_t}; defined $e; $e = $e->[_PREVIOUS]) {
         if ($e->[_TIME] <= $event->[_TIME]) {
            $event->[_PREVIOUS] = $e;
            $event->[_NEXT] = $e->[_NEXT];
            if ($e eq $this->{_event_queue_t}) {
               DEBUG_INFO('modified tail %s', $event_info);
               $this->{_event_queue_t} = $event;
            } else {
               DEBUG_INFO('inserted %s into list', $event_info);
               $e->[_NEXT]->[_PREVIOUS] = $event;
            }
            return $e->[_NEXT] = $event;
         }
      }

      DEBUG_INFO('added %s to head of list', $event_info);
      $event->[_NEXT] = $this->{_event_queue_h};
      $this->{_event_queue_h} = $this->{_event_queue_h}->[_PREVIOUS] = $event;

   } else {

      # Search forward from the head of the list

      for (my $e = $this->{_event_queue_h}; defined $e; $e = $e->[_NEXT]) {
         if ($e->[_TIME] > $event->[_TIME]) {
            $event->[_NEXT] = $e;
            $event->[_PREVIOUS] = $e->[_PREVIOUS];
            if ($e eq $this->{_event_queue_h}) {
               DEBUG_INFO('modified head %s', $event_info);
               $this->{_event_queue_h} = $event;
            } else {
               DEBUG_INFO('inserted %s into list', $event_info);
               $e->[_PREVIOUS]->[_NEXT] = $event;
            }
            return $e->[_PREVIOUS] = $event;
         }
      }

      DEBUG_INFO('added %s to tail of list', $event_info);
      $event->[_PREVIOUS] = $this->{_event_queue_t};
      $this->{_event_queue_t} = $this->{_event_queue_t}->[_NEXT] = $event;

   }

   return $event;
}

sub _event_delete
{
   my ($this, $event) = @_;

   my $info = q{};

   # Update the previous event
   if (defined $event->[_PREVIOUS]) {
      $event->[_PREVIOUS]->[_NEXT] = $event->[_NEXT];
   } elsif ($event eq $this->{_event_queue_h}) {
      if (defined ($this->{_event_queue_h} = $event->[_NEXT])) {
          $info = sprintf ', defined new head %s', $this->_event_info($event->[_NEXT]);
      } else {
         DEBUG_INFO('deleted %s, list is now empty', $this->_event_info($event));
         $this->{_event_queue_t} = undef @{$event};
         return FALSE; # Indicate queue is empty
      }
   } else {
      die 'FATAL: Attempted to delete Event object with an invalid head';
   }

   # Update the next event
   if (defined $event->[_NEXT]) {
      $event->[_NEXT]->[_PREVIOUS] = $event->[_PREVIOUS];
   } elsif ($event eq $this->{_event_queue_t}) {
      $info .= sprintf ', defined new tail %s', $this->_event_info($event->[_PREVIOUS]);
      $this->{_event_queue_t} = $event->[_PREVIOUS];
   } else {
      die 'FATAL: Attempted to delete Event object with an invalid tail';
   }

   DEBUG_INFO('deleted %s%s', $this->_event_info($event), $info);
   undef @{$event};

   # Indicate queue still has entries
   return TRUE;
}

sub _event_init
{
   my ($this, $event) = @_;

   DEBUG_INFO('initializing event %s', $this->_event_info($event));

   # Save the time, callback, & hostname because they will be cleared.
   my ($time, $callback, $hostname) = @{$event}[_TIME, _CALLBACK, _HOSTNAME];

   # Remove the event from the queue.
   $this->_event_delete($event);

   # Update the appropriate fields.
   $event->[_ACTIVE]   = $this->{_active};
   $event->[_TIME]     = $this->{_active} ? time() + $time : $time;
   $event->[_CALLBACK] = $callback;
   $event->[_HOSTNAME] = $hostname;

   # Insert the event back into the queue.
   $this->_event_insert($event);

   return TRUE;
}

#########################################
# Hostname passing and send_pdu_priority

sub send_pdu
{
   my ($this, $pdu, $delay) = @_;

   # Clear any previous errors
   $this->_error_clear();

   if ((@_ < 2) || !ref $pdu) {
      return $this->_error('The required PDU object is missing or invalid');
   }

   # If the Dispatcher is active and the delay value is negative,
   # send the message immediately.

   if ($delay < 0) {
      if ($this->{_active}) {
         return $this->_send_pdu($pdu, $pdu->retries());
      }
      $delay = 0;
   }

   $this->schedule($delay, $pdu->hostname(), [\&_send_pdu, $pdu, $pdu->retries()]);

   return TRUE;
}

*send_pdu_priority = \&Net::SNMP::Dispatcher::return_response_pdu;

sub schedule
{
   my ($this, $time, $hostname, $callback) = @_;

   return $this->_event_create($time, $hostname, $this->_callback_create($callback));
}

sub register
{
   my ($this, $transport, $hostname, $callback) = @_;

   # Transport Domain, file descriptor, and destination hostname must be valid.
   my $fileno;

   if (!defined($transport) || !defined($hostname) || !defined($fileno = $transport->fileno())) {
      return $this->_error('The Transport Domain object is invalid');
   }

   # NOTE: The callback must read the data associated with the
   #       file descriptor or the Dispatcher will continuously
   #       call the callback and get stuck in an infinite loop.

   if (!exists $this->{_descriptors}->{$fileno}) {

      # Make sure that the "readable" vector is defined.
      if (!defined $this->{_rin}) {
         $this->{_rin} = q{};
      }

      # Add the file descriptor to the list.
      $this->{_descriptors}->{$fileno} = [
         $this->_callback_create($callback), # Callback
         $transport,                         # Transport Domain object
         1                                   # Reference count
      ];

      # Add the file descriptor to the "readable" vector.
      vec($this->{_rin}, $fileno, 1) = 1;

      DEBUG_INFO('added handler for descriptor [%d]', $fileno);

   } else {
      # Bump up the reference count.
      $this->{_descriptors}->{$fileno}->[2]++;
   }

   if (!exists $this->{_hostnames}->{$hostname}) {

      # Add the hostname to the list.
      $this->{_hostnames}->{$hostname} = [
         undef,       # Callback (undef for now; possible future use)
         $transport,  # Transport Domain object
         1            # Reference count
      ];

      DEBUG_INFO('added handler for hostname [%s]', $hostname);

   } else {
      # Bump up the reference count.
      $this->{_hostnames}->{$hostname}[2]++;
   }

   return $transport;
}

sub deregister
{
   my ($this, $transport, $hostname) = @_;

   # Transport Domain, file descriptor, and destination hostname must be valid.
   my $fileno;

   if (!defined($transport) || !defined($hostname) || !defined($fileno = $transport->fileno())) {
      return $this->_error('The Transport Domain object is invalid');
   }

   if (exists $this->{_descriptors}->{$fileno}) {

      # Check reference count.
      if (--$this->{_descriptors}->{$fileno}->[2] < 1) {

         # Remove the file descriptor from the list.
         delete $this->{_descriptors}->{$fileno};

         # Remove the file descriptor from the "readable" vector.
         vec($this->{_rin}, $fileno, 1) = 0;

         # Undefine the vector if there are no file descriptors,
         # some systems expect this to make select() work properly.

         if (!keys %{$this->{_descriptors}}) {
            $this->{_rin} = undef;
         }

         DEBUG_INFO('removed handler for descriptor [%d]', $fileno);
      }

   } else {
      return $this->_error('The Transport Domain object is not registered');
   }

   if (exists $this->{_hostnames}->{$hostname}) {

      # Check reference count.
      if (--$this->{_hostnames}->{$hostname}->[2] < 1) {
         delete $this->{_hostnames}->{$hostname};
         DEBUG_INFO('removed handler for hostname [%s]', $hostname);
      }

   } else {
      return $this->_error('The Transport Domain object is not registered for hostname [%s]', $hostname);
   }

   return $transport;
}

####################
# Private functions

sub _new
{
   my ($class) = @_;

   # The constructor is private since we only want one
   # Dispatcher object.

   return bless {
      '_active'        => FALSE,  # State of this Dispatcher object
      '_error'         => undef,  # Error message
      '_event_queue_h' => undef,  # Head of the event queue
      '_event_queue_t' => undef,  # Tail of the event queue
      '_rin'           => undef,  # Readable vector for select()
      '_descriptors'   => {},     # List of file descriptors to monitor
      '_hostnames'     => {},     # Reference counts of destinations
   }, $class;
}

sub _send_pdu
{
   my ($this, $pdu, $retries) = @_;

   # Pass the PDU to Message Processing so that it can
   # create the new outgoing message.

   my $msg = $MESSAGE_PROCESSING->prepare_outgoing_msg($pdu);

   if (!defined $msg) {
      # Inform the command generator about the Message Processing error.
      $pdu->status_information($MESSAGE_PROCESSING->error());
      return;
   }

   # Actually send the message.

   if (!defined $msg->send()) {

      # Delete the msgHandle.
      if ($pdu->expect_response()) {
         $MESSAGE_PROCESSING->msg_handle_delete($msg->msg_id());
      }

      # A crude attempt to recover from temporary failures.
      if (($retries-- > 0) && ($!{EAGAIN} || $!{EWOULDBLOCK})) {
         DEBUG_INFO('attempting recovery from temporary failure');
         $this->schedule($pdu->timeout(), $pdu->hostname(), [\&_send_pdu, $pdu, $retries]);
         return FALSE;
      }

      # Inform the command generator about the send() error.
      $pdu->status_information($msg->error());

      return;
   }

   # Schedule the timeout handler if the message expects a response.

   if ($pdu->expect_response()) {
      $this->register($msg->transport(), $pdu->hostname(), [\&_transport_response_received]);
      $msg->timeout_id(
         $this->schedule(
            $pdu->timeout(), $pdu->hostname(),
            [\&_transport_timeout, $pdu, $retries, $msg->msg_id()]
         )
      );
   }

   return TRUE;
}

# (additions for max_requests option)

sub _transport_timeout
{
   my ($this, $pdu, $retries, $handle) = @_;

   # Stop waiting for responses.
   $this->deregister($pdu->transport(), $pdu->hostname());

   # Delete the msgHandle.
   $MESSAGE_PROCESSING->msg_handle_delete($handle);

   # Set the max new requests to 1, since the host is known to be slow.
   $pdu->transport() && $pdu->transport()->max_requests(1);

   if ($retries-- > 0) {

      # Resend a new message.
      DEBUG_INFO('retries left %d', $retries);
      return $this->_send_pdu($pdu, $retries);

   } else {

      # Inform the command generator about the timeout.
      $pdu->status_information(
          q{No response from remote host "%s"}, $pdu->hostname()
      );
      return;

   }
}

# (more hostname passing)

sub _transport_response_received
{
   my ($this, $transport) = @_;

   # Clear any previous errors
   $this->_error_clear();

   if (!ref $transport) {
      die 'FATAL: The Transport Domain object is invalid';
   }

   # Create a new Message object to receive the response
   my ($msg, $error) = Net::SNMP::Message->new(-transport => $transport);

   if (!defined $msg) {
      die sprintf 'Failed to create Message object: %s', $error;
   }

   # Read the message from the Transport Layer
   if (!defined $msg->recv()) {
      if (!$transport->connectionless()) {
         $this->deregister($transport, $msg->hostname());
      }
      return $this->_error($msg->error());
   }

   # For connection-oriented Transport Domains, it is possible to
   # "recv" an empty buffer if reassembly is required.

   if (!$msg->length()) {
      DEBUG_INFO('ignoring zero length message');
      return FALSE;
   }

   # Hand the message over to Message Processing.
   if (!defined $MESSAGE_PROCESSING->prepare_data_elements($msg)) {
      return $this->_error($MESSAGE_PROCESSING->error());
   }

   # Set the error if applicable.
   if ($MESSAGE_PROCESSING->error()) {
      $msg->error($MESSAGE_PROCESSING->error());
   }

   # Cancel the timeout.
   $this->cancel($msg->timeout_id());

   # Stop waiting for responses.
   $this->deregister($transport, $msg->hostname());

   # Notify the command generator to process the response.
   return $msg->process_response_pdu();
}

#####################################################
# Receive buffer emptying / Max Requests per host/IP

sub _event_handle
{
   my ($this, $timeout) = @_;
   my ($time, $event) = (time(), $this->{_event_queue_h});

   # First, make sure this host isn't maxed out so that the dispatcher
   # doesn't overload it with different requests.
   my $hostname_ref = $this->{_hostnames}->{$event->[_HOSTNAME]};
   while (defined $event && defined $hostname_ref->[1] &&
          $hostname_ref->[2] >= $hostname_ref->[1]->max_requests() &&
          $SUBREFS{$event->[_CALLBACK][0]} eq '&_send_pdu') {
      $event = $event->[_NEXT];
      $hostname_ref = $this->{_hostnames}->{$event->[_HOSTNAME]};
   }

   if (defined $event) {
      # If the event was inserted with a non-zero delay while the
      # Dispatcher was not active, the scheduled time of the event
      # needs to be updated.

      if (!$event->[_ACTIVE] && $event->[_TIME]) {
         return $this->_event_init($event);
      }

      if ($event->[_TIME] <= $time) {

         # If the scheduled time of the event is past, execute it and
         # set the timeout to zero to poll the descriptors immediately.

         $this->_callback_execute($event->[_CALLBACK]);
         $this->_event_delete($event);
         $timeout = 0;

      } elsif (!defined $timeout) {

         # Calculate the timeout for the next event unless one was
         # specified by the caller.

         $timeout = $event->[_TIME] - $time;
         DEBUG_INFO('event %s, timeout = %.04f', $this->_event_info($event), $timeout);

      }

   }

   # Check the file descriptors for activity.
   my $nfound = 0;
   do {
      my $stime = time();
      $nfound = select(my $rout = $this->{_rin}, undef, undef, $timeout);

      if (!defined $nfound || $nfound < 0) {

         if ($!{EINTR}) { # Recoverable error
            return FALSE;
         } else {
            die sprintf 'FATAL: select() error: %s', $!;
         }

       } elsif ($nfound > 0) {

         DEBUG_INFO('found ready descriptors after %.04fs, timeout = %.04f', time() - $stime, $timeout);

         # Find out which file descriptors have data ready for reading.

         if (defined $rout) {
            for (keys %{$this->{_descriptors}}) {
               if (vec $rout, $_, 1) {
                  DEBUG_INFO('descriptor [%d] ready for read', $_);
                  $stime = time();
                  $this->_callback_execute(@{$this->{_descriptors}->{$_}}[0,1]);
                  DEBUG_INFO('total receiving packet processing took %.04fs', time() - $stime);
               }
            }
         }

      }

      # If any receiving data was found, keep instant polling to see if there is
      # anything else in the socket buffers.  If so, keep running through the
      # receiving data until its clear before any more new events are sent
      # through the pipe.  As soon as the dispatcher has to wait a millisecond more
      # than instant, return out and the dispatcher will eventually return to
      # processing the event lists.

      # This provides a heathly balance between fast polling, and keeping the
      # dispatcher from getting overloaded.

      $timeout = 0 if ($nfound);

   } while ($nfound);
   DEBUG_INFO('socket buffer empty, total event processing = %.04fs, timeout = %.04f', time() - $time, $timeout);

   return TRUE;
}

# (this is a new re-definition of one_event that accepts a timeout value.
# Needs a RT ticket, but not sure if he would bother with it.)
sub one_event
{
   my ($this, $timeout) = @_;

   return TRUE if ($this->{_active});

   if (defined $this->{_event_queue_h} || keys %{$this->{_descriptors}}) {
      $this->{_active} = TRUE;
      $this->_event_handle($timeout || 0);
      $this->{_active} = FALSE;
   }

   return (defined $this->{_event_queue_h} || keys %{$this->{_descriptors}});
}

# (since we are monkey patching here, we actually need to re-run this %SUBREF
# thing now, after the routines have just been redefined.)
%SUBREFS = map { *{ $Net::SNMP::Dispatcher::{$_} }{CODE} => '&'.$_ } (keys %Net::SNMP::Dispatcher::);

1;

##############################################################################
# Net::SNMP::Transport

# (these changes are for the max_requests option)

package Net::SNMP::Transport;

# (our doesn't scope within packages, which is stupid...)
our $SOCKETS;
*SOCKETS = \$Net::SNMP::Transport::SOCKETS;

sub MAX_REQUESTS_DEFAULT {     3 }
sub MAX_REQUESTS_MINIMUM {     0 }
sub MAX_REQUESTS_MAXIMUM { 65535 }

sub max_requests
{
   my ($this, $max_requests) = @_;

   if (@_ < 2) {
      return $this->{_max_requests};
   }

   $this->_error_clear();

   if ($max_requests !~ m/^\d+(?:\.\d+)?$/) {
      return $this->_error(
         'The max requests value "%s" is expected in positive numeric format',
         $max_requests
      );
   }

   if ($max_requests < MAX_REQUESTS_MINIMUM || $max_requests > MAX_REQUESTS_MAXIMUM) {
      return $this->_error(
         'The max requests value %s is out of range (%d..%d)',
         $max_requests, MAX_REQUESTS_MINIMUM, MAX_REQUESTS_MAXIMUM
      );
   }

   return $this->{_max_requests} = $max_requests;
}

# (gotta replace _new for 3 whole lines...)
   
sub _new
{
   my ($class, %argv) = @_;

   my $this = bless {
      '_dest_hostname' => 'localhost',                 # Destination hostname
      '_dest_name'     => undef,                       # Destination sockaddr
      '_error'         => undef,                       # Error message
      '_max_msg_size'  => $class->_msg_size_default(), # maxMsgSize
      '_max_requests'  => MAX_REQUESTS_DEFAULT,        # Max # of new requests
      '_retries'       => RETRIES_DEFAULT,             # Number of retries
      '_socket'        => undef,                       # Socket object
      '_sock_hostname' => q{},                         # Socket hostname
      '_sock_name'     => undef,                       # Socket sockaddr
      '_timeout'       => TIMEOUT_DEFAULT,             # Timeout period (secs)
   }, $class;

   # Default the values for the "name (sockaddr) hashes".

   my $sock_nh = { port => 0,         addr => $this->_addr_any()      };
   my $dest_nh = { port => SNMP_PORT, addr => $this->_addr_loopback() };

   # Validate the "port" arguments first to allow for a consistency
   # check with any values passed with the "address" arguments.

   my ($dest_port, $sock_port, $listen) = (undef, undef, 0);

   for (keys %argv) {

      if (/^-?debug$/i) {
         $this->debug(delete $argv{$_});
      } elsif (/^-?(?:de?st|peer)?port$/i) {
         $this->_service_resolve(delete($argv{$_}), $dest_nh);
         $dest_port = $dest_nh->{port};
      } elsif (/^-?(?:src|sock|local)port$/i) {
         $this->_service_resolve(delete($argv{$_}), $sock_nh);
         $sock_port = $sock_nh->{port};
      }

      if (defined $this->{_error}) {
         return wantarray ? (undef, $this->{_error}) : undef;
      }
   }

   # Validate the rest of the arguments.

   for (keys %argv) {

      if (/^-?domain$/i) {
         if ($argv{$_} ne $this->domain()) {
            $this->_error(
               'The domain value "%s" was expected, but "%s" was found',
               $this->domain(), $argv{$_}
            );
         }
      } elsif ((/^-?hostname$/i) || (/^-?(?:de?st|peer)?addr$/i)) {
         $this->_hostname_resolve(
            $this->{_dest_hostname} = $argv{$_}, $dest_nh
         );
         if (defined($dest_port) && ($dest_port != $dest_nh->{port})) {
            $this->_error(
               'Inconsistent %s port information was specified (%d != %d)',
               $this->type(), $dest_port, $dest_nh->{port}
            );
         }
      } elsif (/^-?(?:src|sock|local)addr$/i) {
         $this->_hostname_resolve(
            $this->{_sock_hostname} = $argv{$_}, $sock_nh
         );
         if (defined($sock_port) && ($sock_port != $sock_nh->{port})) {
            $this->_error(
               'Inconsistent %s port information was specified (%d != %d)',
               $this->type(), $sock_port, $sock_nh->{port}
            );
         }
      } elsif (/^-?listen$/i) {
         if (($argv{$_} !~ /^\d+$/) || ($argv{$_} < 1)) {
            $this->_error(
               'The listen queue size value "%s" was expected in positive ' .
               'non-zero numeric format', $argv{$_}
            );
         } elsif (!$this->connectionless()) {
            $listen = $argv{$_};
         }
      } elsif ((/^-?maxmsgsize$/i) || (/^-?mtu$/i)) {
         $this->max_msg_size($argv{$_});
      } elsif (/^-?maxrequests?$/i) {
         $this->max_requests($argv{$_});
      } elsif (/^-?retries$/i) {
         $this->retries($argv{$_});
      } elsif (/^-?timeout$/i) {
         $this->timeout($argv{$_});
      } else {
         $this->_error('The argument "%s" is unknown', $_);
      }

      if (defined $this->{_error}) {
         return wantarray ? (undef, $this->{_error}) : undef;
      }

   }

   # Pack the socket name (sockaddr) information.
   $this->{_sock_name} = $this->_name_pack($sock_nh);

   # Pack the destination name (sockaddr) information.
   $this->{_dest_name} = $this->_name_pack($dest_nh);

   # For all connection-oriented transports and for each unique source
   # address for connectionless transports, create a new socket.

   if (!$this->connectionless() || !exists $SOCKETS->{$this->{_sock_name}}) {

      # Create a new IO::Socket object.

      if (!defined ($this->{_socket} = $this->_socket_create())) {
         $this->_perror('Failed to open %s socket', $this->type());
         return wantarray ? (undef, $this->{_error}) : undef
      }

      DEBUG_INFO('opened %s socket [%d]', $this->type(), $this->fileno());

      # Bind the socket.

      if (!defined $this->{_socket}->bind($this->{_sock_name})) {
         $this->_perror('Failed to bind %s socket', $this->type());
         return wantarray ? (undef, $this->{_error}) : undef
      }

      # For connection-oriented transports, we either listen or connect.

      if (!$this->connectionless()) {

         if ($listen) {
            if (!defined $this->{_socket}->listen($listen)) {
               $this->_perror('Failed to listen on %s socket', $this->type());
               return wantarray ? (undef, $this->{_error}) : undef
            }
         } else {
            if (!defined $this->{_socket}->connect($this->{_dest_name})) {
               $this->_perror(
                  q{Failed to connect to remote host '%s'},
                  $this->dest_hostname()
               );
               return wantarray ? (undef, $this->{_error}) : undef
            }
         }
      }

      # Flag the socket as non-blocking outside of socket creation or
      # the object instantiation fails on some systems (e.g. MSWin32).

      $this->{_socket}->blocking(FALSE);

      # Add the socket to the global socket list with a reference
      # count to track when to close the socket and the maxMsgSize
      # associated with this new object for connectionless transports.

      if ($this->connectionless()) {
         $SOCKETS->{$this->{_sock_name}} = [
            $this->{_socket},       # Shared Socket object
            1,                      # Reference count
            $this->{_max_msg_size}, # Shared maximum message size
         ];
      }

   } else {

      # Bump up the reference count.
      $SOCKETS->{$this->{_sock_name}}->[_SHARED_REFC]++;

      # Assign the socket to the object.
      $this->{_socket} = $SOCKETS->{$this->{_sock_name}}->[_SHARED_SOCKET];

      # Adjust the shared maxMsgSize if necessary.
      $this->_shared_max_size($this->{_max_msg_size});

      DEBUG_INFO('reused %s socket [%d]', $this->type(), $this->fileno());

   }

   # Return the object and empty error message (in list context)
   return wantarray ? ($this, q{}) : $this;
}

##############################################################################
# SQL::Parser

package SQL::Parser;

# Direct copy of INSERT sub with the DELAYED changes

sub INSERT
{
    my ( $self, $str ) = @_;
    my $col_str;
    $str =~ s/^INSERT\s+DELAYED\s+/INSERT /i;  # allow DELAYED to be optional
    $str =~ s/^INSERT\s+INTO\s+/INSERT /i;     # allow INTO to be optional
    my ( $table_name, $val_str ) = $str =~ m/^INSERT\s+(.+?)\s+VALUES\s+(\(.+?\))$/i;
    if ( $table_name and $table_name =~ m/[()]/ )
    {
        ( $table_name, $col_str, $val_str ) =
          $str =~ m/^INSERT\s+(.+?)\s+\((.+?)\)\s+VALUES\s+(\(.+?\))$/i;
    }
    return $self->do_err('No table name specified!') unless ($table_name);
    return $self->do_err('Missing values list!')     unless ( defined $val_str );
    return undef                                     unless ( $self->TABLE_NAME($table_name) );
    $self->{struct}->{command}     = 'INSERT';
    $self->{struct}->{table_names} = [$table_name];
    if ($col_str)
    {
        return undef unless ( $self->{struct}->{column_defs} = $self->ROW_VALUE_LIST($col_str) );
    }
    else
    {
        $self->{struct}->{column_defs} = [
                                           {
                                             type  => 'column',
                                             value => '*'
                                           }
                                         ];
    }
    $self->{struct}->{values} = [];
    while ( $val_str =~ m/\((.+?)\)(?:,|$)/g )
    {
        my $line_str = $1;
        return undef unless ( $self->LITERAL_LIST($line_str) );
    }
    return 1;
}

# Changes to accept schema.table format

sub TABLE_NAME
{
    my ( $self, $table_name ) = @_;
    if ( $table_name =~ m/\s*(\S+)\s+\S+/s )
    {
        return $self->do_err("Junk after table name '$1'!");
    }
    $table_name =~ s/\s+//s;
    if ( !$table_name )
    {
        return $self->do_err('No table name specified!');
    }
    return $table_name if ( $self->IDENTIFIER($table_name) );
}

sub IDENTIFIER
{
    my ( $self, $id ) = @_;
    if ( $id =~ m/^\?QI(.+)\?$/ )
    {
        return 1;
    }
    return $self->IDENTIFIER($1) && $self->IDENTIFIER($2) if ( $id =~ m/^(.+)\.([^\.]+)$/ );  # check both schema/table
    return 1 if $id =~ m/^".+?"$/s;    # QUOTED IDENTIFIER
    my $err = "Bad table or column name: '$id' ";    # BAD CHARS
    if ( $id =~ /\W/ )
    {
        $err .= "has chars not alphanumeric or underscore!";
        return $self->do_err($err);
    }
    # CSV requires optional start with _
    my $badStartRx = uc( $self->{dialect} ) eq 'ANYDATA' ? qr/^\d/ : qr/^[_\d]/;
    if ( $id =~ $badStartRx )
    {                                                # BAD START
        $err .= "starts with non-alphabetic character!";
        return $self->do_err($err);
    }
    if ( length $id > 128 )
    {                                                # BAD LENGTH
        $err .= "contains more than 128 characters!";
        return $self->do_err($err);
    }
    $id = uc $id;
    if ( $self->{opts}->{reserved_words}->{$id} )
    {                                                # BAD RESERVED WORDS
        $err .= "is a SQL reserved word!";
        return $self->do_err($err);
    }
    return 1;
}

sub replace_quoted_ids
{
    my ( $self, $id ) = @_;
    return $id unless $self->{struct}->{quoted_ids};
    if ($id)
    {
        if    ( $id =~ /^\?QI(\d+)\?$/ )
        {
            return '"' . $self->{struct}->{quoted_ids}->[$1] . '"';
        }
        elsif ( $id =~ /^\?QI(\d+)\?.\?QI(\d+)\?$/ )              # double quoted with schema or table name
        {
            return join '.', map { '"' . $self->{struct}->{quoted_ids}->[$_] . '"' } ($1, $2);
        }
        elsif ( $id =~ /^\?QI(\d+)\?.\?QI(\d+)\?.\?QI(\d+)\?$/ )  # triple quoted with schema AND table name
        {
            return join '.', map { '"' . $self->{struct}->{quoted_ids}->[$_] . '"' } ($1, $2, $3);
        }
        else
        {
            return $id;
        }
    }
    return unless defined $self->{struct}->{table_names};
    my @tables = @{ $self->{struct}->{table_names} };
    for my $t (@tables)
    {
        if    ( $t =~ /^\?QI(\d+)\?$/ )
        {
            $t = '"' . $self->{struct}->{quoted_ids}->[$1] . '"';
        }
        elsif ( $t =~ /^\?QI(\d+)\?.\?QI(\d+)\?$/ )  # double quoted with schema
        {
            $t = join '.', map { '"' . $self->{struct}->{quoted_ids}->[$_] . '"' } ($1, $2);
        }
    }
    $self->{struct}->{table_names} = \@tables;
    delete $self->{struct}->{quoted_ids};
}
