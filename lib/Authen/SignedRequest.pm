package Authen::SignedRequest;
use strict;
use warnings;
use Carp qw(carp croak);
use Digest::SHA qw(hmac_sha256);
use MIME::Base64::URLSafe;
use JSON::Functions::XS qw(json_bytes2perl perl2json_bytes);

sub get_signed_request {
    croak "No secret key" unless defined $_[2];
    $_[1]->{algorithm} = 'HMAC-SHA256';
    $_[1]->{issued_at} = time;
    my $data = urlsafe_b64encode(perl2json_bytes $_[1]);
    my $signature = urlsafe_b64encode(hmac_sha256($data, $_[2]));
    return $signature . "." . $data;
}

our $SignatureTimeout ||= 60*5;
our $Warn;

sub verify_signed_request {
    croak "No secret key" unless defined $_[2];
    my ($signature, $sdata) = split /\./, $_[1];
    my $data = json_bytes2perl(urlsafe_b64decode $sdata);
    if (not defined $data or not ref $data eq 'HASH') {
        carp "Signed data is not JSON" if $Warn;
        return undef;
    }
    unless ($data->{algorithm} =~ /\A[Hh][Mm][Aa][Cc]-[Ss][Hh][Aa]256\z/) {
        carp "Signature algorithm |$data->{algorithm}| is not supported" if $Warn;
        return undef;
    }
    $signature = urlsafe_b64decode $signature;
    unless ($signature eq hmac_sha256($sdata, $_[2])) {
        carp "Invalid signature" if $Warn;
        return undef;
    }
    if ($SignatureTimeout) {
        if (($data->{issued_at} || 0) + $SignatureTimeout < time) {
            carp "Signature timeout" if $Warn;
            return undef;
        }
    }
    return $data;
}

1;
