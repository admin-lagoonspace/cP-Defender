package Cpanel::Config::ConfigObj::Driver::SentinelGate::META;

use strict;

our $VERSION = '3.2.2';

sub new             { return bless {}, shift; }
sub abstract        { return 'Sentinel Gate Security Suite'; }
sub version         { return $VERSION; }
sub get_driver_name { return 'SentinelGate'; }

1;
