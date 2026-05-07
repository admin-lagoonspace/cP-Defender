package Cpanel::Config::ConfigObj::Driver::SentinelGate;

use strict;
use Cpanel::Config::ConfigObj::Driver::SentinelGate::META ();
*VERSION = \$Cpanel::Config::ConfigObj::Driver::SentinelGate::META::VERSION;

our @ISA = qw(Cpanel::Config::ConfigObj::Interface::Config::v1);

sub init {
    my ( $class, $software_obj ) = @_;
    my $defaults = {
        'thirdparty_ns' => 'SentinelGate',
        'meta'          => {},
    };
    my $self = $class->SUPER::base( $defaults, $software_obj );
    return $self;
}

sub enable  { return 1; }
sub disable { return 1; }

sub info {
    my ($self) = @_;
    return $self->meta()->abstract();
}

sub acl_desc {
    return [
        {
            'acl'              => 'all',
            'default_value'    => 1,
            'default_ui_value' => 1,
            'name'             => 'Sentinel Gate Security',
            'acl_subcat'       => 'Third Party Services',
        },
    ];
}

1;
