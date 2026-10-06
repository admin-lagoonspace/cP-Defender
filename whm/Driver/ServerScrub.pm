package Cpanel::Config::ConfigObj::Driver::ServerScrub;

use strict;
use Cpanel::Config::ConfigObj::Driver::ServerScrub::META ();
*VERSION = \$Cpanel::Config::ConfigObj::Driver::ServerScrub::META::VERSION;

our @ISA = qw(Cpanel::Config::ConfigObj::Interface::Config::v1);

sub init {
    my ( $class, $software_obj ) = @_;
    my $self = $class->SUPER::base(
        { 'thirdparty_ns' => 'ServerScrub', 'meta' => {} },
        $software_obj
    );
    return $self;
}

sub enable  { return 1; }
sub disable { return 1; }

sub info {
    my ($self) = @_;
    return $self->meta()->abstract();
}

# acls=all in AppConfig conf — no custom ACL to register
sub acl_desc { return []; }

1;
