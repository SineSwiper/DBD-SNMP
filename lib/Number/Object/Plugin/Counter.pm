package Number::Object::Plugin::Counter;
 
use sanity;
use base 'Class::Component::Plugin';

use DateTime;
use DateTime::Duration;
use Time::HiRes 'time';

sub new_value :Method :Hook('value.set') {
   my $time = time;  # get the time as soon as possible
   my ($self, $c, $args) = @_;
   
   $c->{history} //= [];
   my $hist = $c->{history};
   my $is_first = @$hist;

   my $timestamp = $is_first ?
      ($self->{time} || $c->{time} || $c->config->{time} || $time) :
      ($args->{time} || $time);
   $timestamp = DateTime->from_epoch( epoch => $timestamp )
      unless ref $timestamp eq 'DateTime';
   
   push @$hist, {
      timestamp  => $timestamp,
      time_delta => ($is_first ? 
         DateTime::Duration->new( seconds => 0 ) :
         $timestamp - $hist->[-1]{timestamp}),
      value      => $args->{value},
      delta      => $is_first ? $c->{history}[-1] : 'N/A',
   };
}

sub last_value :Method {
   my ($self, $c, $args) = @_;
   $c->clone($c->{history}[-1]);
}

sub full_history :Method {
   my ($self, $c, $args) = @_;
   $c->clone($c->{history});
}

sub clear_history :Method {
   my ($self, $c, $args) = @_;
   splice @{$c->{history}}, 0, $args ? scalar @{$c->{history}} : -1;
}
  
1;