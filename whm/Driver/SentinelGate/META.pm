package Cpanel::Config::ConfigObj::Driver::SentinelGate::META;

use strict;

our $VERSION = '3.2.7';

sub new             { return bless {}, shift; }
sub spec_version    { return 1; }
sub meta_version    { return 1; }
sub get_driver_name { return 'SentinelGate'; }
sub showcase        { return; }

sub content {
    my ($locale_handle) = @_;
    my $abstract = 'Sentinel Gate Security Suite for cPanel/WHM.';
    $abstract = $locale_handle->maketext($abstract) if $locale_handle;
    return {
        'vendor'  => 'Sentinel Gate',
        'url'     => 'github.com/admin-lagoonspace/cP-Defender',
        'name'    => {
            'short'  => 'Sentinel Gate',
            'long'   => 'Sentinel Gate Security',
            'driver' => 'SentinelGate',
        },
        'since'   => 'cPanel & WHM version 11.38',
        'abstract' => $abstract,
        'version' => $VERSION,
    };
}

1;
