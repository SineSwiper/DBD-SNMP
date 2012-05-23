package DateTime::Format::SNMP;

use sanity;
use POSIX qw(strftime);
use DateTime;
use DateTime::Format::Strptime;
use DateTime::Format::Duration;

our $VERSION = '1.00';

my $datetime_format    = '%Y-%m-%d %H:%M:%S.%2N';
my $datetime_tz_format = '%Y-%m-%d %H:%M:%S.%2N %z';
my $interval_format    = '%j %H:%M:%S.%2N';

my $strp_dt = new DateTime::Format::Strptime(
   pattern  => $datetime_format,
   on_error => 'undef',
);
my $strp_tz = new DateTime::Format::Strptime(
   pattern  => $datetime_tz_format,
   on_error => 'undef',
);
my $strp_dur = new DateTime::Format::Duration(
   pattern  => $datetime_tz_format,
);

sub datetime_format {
   my ($self, $format) = @_;
   $datetime_format = $strp->pattern($format) if ($format);
   return $datetime_format;
}
sub datetime_tz_format {
   my ($self, $format) = @_;
   $datetime_tz_format = $strp_tz->pattern($format) if ($format);
   return $datetime_tz_format;
}
sub interval_format {
   my ($self, $format) = @_;
   $interval_format = $strp_dur->pattern($format) if ($format);
   return $interval_format;
}

sub parse_datetime {
   my ($self, $val, $t) = @_;

   unless ($t) {
      for ($val) {
         when (/^\d{1,3}(?:\.\d{1,3}){7,10}$/) { $t = 'o'; }  # 8/11-byte OBJECTID
         when (/^[\x07\x08].{7,10}$/s)         { $t = 'b'; }  # 8/11-byte binary (with year high-byte comparison)
         default                               { $t = 'f'; }  # Default to filtered format
      }
   }

   $val = _bin2dd($val) if ($t eq 'b');  # binary to dotted-decimal

   return $strp_tz->parse_datetime($val) || $strp_dt->parse_datetime($val)
      if ($t eq 'f');

   # From SNMPv2-TC:
   #
   # field  octets  contents                  range
   # -----  ------  --------                  -----
   #   1      1-2   year*                     0..65536
   #   2       3    month                     1..12
   #   3       4    day                       1..31
   #   4       5    hour                      0..23
   #   5       6    minutes                   0..59
   #   6       7    seconds                   0..60
   #                (use 60 for leap-second)
   #   7       8    deci-seconds              0..9
   #   8       9    direction from UTC        '+' / '-'
   #   9      10    hours from UTC*           0..13
   #  10      11    minutes from UTC          0..59
   my @dt = (0, split(/\./, $val));  # make it an one-based array for clarity with above

   # sanity checks
   return undef if (
         $dt[3]  > 12     # month
      || $dt[4]  > 31     # day
      || $dt[5]  > 23     # hour
      || $dt[6]  > 59     # minutes
      || $dt[7]  > 61     # seconds (a 61st second is technically possible)
      || $dt[8]  > 9      # deci-seconds
      || (@dt > 8 && (    # timezone check
            $dt[10] > 13  # TZ hours
         || $dt[11] > 59  # TZ minutes
      ))
   );

   return DateTime->new(
      year       => $dt[1] * 256 + $dt[2],
      month      => $dt[3],
      day        => $dt[4],
      hour       => $dt[5],
      minute     => $dt[6],
      second     => $dt[7],
      nanosecond => $dt[8] * 100_000_000,
      time_zone  => (@dt > 8) ? sprintf('%s%02u%02u', chr($dt[9]), @dt[10,11]) : 'floating'
   );
}
*parse_date        = \&parse_datetime;
*parse_DateAndTime = \&parse_datetime;
*parse_dateandtime = \&parse_datetime;

sub parse_interval {
   my ($self, $val, $t) = @_;
   $t ||= 'f' if ($val =~ /[^\d\.]/);
   
   # filtered format
   return $strp_dur->parse_duration($val) if ($t eq 'f');

   return DateTime::Duration->new(
      # we at least need to get down to seconds, as expressing
      # 248 days as nanoseconds gets rather large...
      seconds    => int($val / 100),
      nanosecond => ($val % 100) * 10_000_000,
   );
}
*parse_duration     = \&parse_interval;
*parse_TIMETICKS    = \&parse_interval;
*parse_TICKS        = \&parse_interval;
*parse_TimeTicks    = \&parse_interval;
*parse_Ticks        = \&parse_interval;
*parse_TimeStamp    = \&parse_interval;
*parse_TimeInterval = \&parse_interval;
*parse_timeticks    = \&parse_interval;
*parse_ticks        = \&parse_interval;
*parse_timestamp    = \&parse_interval;
*parse_timeinterval = \&parse_interval;

sub format_datetime {
   my ($self, $dt, $t, $use_tz) = @_;
   $t ||= 'f';
   $use_tz //= 1;
   return ($use_tz ? $strp_tz : $strp_dt)->format_datetime($dt) if ($t eq 'f');
   
   # From SNMPv2-TC:
   #
   # field  octets  contents                  range
   # -----  ------  --------                  -----
   #   1      1-2   year*                     0..65536
   #   2       3    month                     1..12
   #   3       4    day                       1..31
   #   4       5    hour                      0..23
   #   5       6    minutes                   0..59
   #   6       7    seconds                   0..60
   #                (use 60 for leap-second)
   #   7       8    deci-seconds              0..9
   #   8       9    direction from UTC        '+' / '-'
   #   9      10    hours from UTC*           0..13
   #  10      11    minutes from UTC          0..59
   my @timevars = (
      $dt->year,
      $dt->month,
      $dt->day,
      $dt->hour,
      $dt->minute,
      $dt->second,
      int($dt->nanosecond * 10_000_000),
   );
   if ($use_tz) {
      my $tz = $dt->offset();
      push @timevars, (
         $tz < 0 ? '-' : '+',
         int($tz / 3600),
         int($tz % 3600 / 60),
      );
   }
   my $val = pack('n1C6'.('A1C2' x!! $use_tz), @timevars);
   
   return _dd2bin($val) if ($t eq 'o');
   return $val;
}
*format_date        = \&format_datetime;
*format_DateAndTime = \&format_datetime;
*format_dateandtime = \&format_datetime;

sub format_interval {
   my ($self, $dur, $t) = @_;
   $t ||= 'f';
   return $strp_dur->format_duration($dur) if ($t eq 'f');

   my ($sec, $nano) = $dur->in_units('seconds', 'nanoseconds');
   return $sec * 100 + int($nano / 10_000_000);
}
*parse_duration     = \&parse_interval;
*parse_TIMETICKS    = \&parse_interval;
*parse_TICKS        = \&parse_interval;
*parse_TimeTicks    = \&parse_interval;
*parse_Ticks        = \&parse_interval;
*parse_TimeStamp    = \&parse_interval;
*parse_TimeInterval = \&parse_interval;
*parse_timeticks    = \&parse_interval;
*parse_ticks        = \&parse_interval;
*parse_timestamp    = \&parse_interval;
*parse_timeinterval = \&parse_interval;

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
