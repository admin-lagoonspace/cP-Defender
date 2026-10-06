package Cpanel::Config::ConfigObj::Driver::ServerScrub::META;

use strict;

our $VERSION = '3.3.1';

sub new             { return bless {}, shift; }
sub spec_version    { return 1; }
sub meta_version    { return 1; }
sub get_driver_name { return 'ServerScrub'; }
sub showcase        { return; }

sub content {
    my ($locale_handle) = @_;
    my $abstract = 'ServerScrub Security Suite for cPanel/WHM.';
    $abstract = $locale_handle->maketext($abstract) if $locale_handle;
    return {
        'vendor'  => 'ServerScrub',
        'url'     => 'github.com/admin-lagoonspace/cP-Defender',
        'name'    => {
            'short'  => 'ServerScrub',
            'long'   => 'ServerScrub Security',
            'driver' => 'ServerScrub',
        },
        'since'   => 'cPanel & WHM version 11.38',
        'abstract' => $abstract,
        'version' => $VERSION,
    };
}

1;
