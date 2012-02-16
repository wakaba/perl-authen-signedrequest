package Ridge::Response::Role::SignedRequest;
use strict;
use warnings;
our $VERSION = '1.0';

sub set_sjson_content {
    my ($self, $data, $secret) = @_;
    require Authen::SignedRequest;
    my $signed = Authen::SignedRequest->get_signed_request($data, $secret);
    $self->content_type('application/x-www-form-urlencoded');
    $self->content('signed_request=' . $signed);
}

1;
