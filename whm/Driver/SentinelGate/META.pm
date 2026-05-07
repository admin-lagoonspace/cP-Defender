package Cpanel::Config::ConfigObj::Driver::SentinelGate::META;

use strict;

our $VERSION = '3.2.2';

sub new             { return bless {}, shift; }
sub abstract        { return 'Sentinel Gate Security Suite'; }
sub version         { return $VERSION; }
sub meta_version    { return 1; }
sub get_driver_name { return 'SentinelGate'; }
sub vendor          { return 'Sentinel Gate'; }
sub url             { return ''; }
sub target          { return '_blank'; }

1;
