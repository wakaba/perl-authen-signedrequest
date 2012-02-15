package test::Authen::SignedRequest;
use strict;
use warnings;
use Path::Class;
use lib file(__FILE__)->dir->parent->subdir('lib')->stringify;
use lib glob file(__FILE__)->dir->parent->subdir('modules', '*', 'lib')->stringify;
use base qw(Test::Class);
use Test::MoreMore;
use Authen::SignedRequest;

sub _roundtrip : Test(4) {
    for (
        [{}, 'hoge'],
        [{abc => "\x{4000}ab\x{100}", 12 => [12, "abxS"]}, 'hoge'],
    ) {
        my $signed = Authen::SignedRequest->get_signed_request($_->[0], $_->[1]);
        my $verified = Authen::SignedRequest->verify_signed_request($signed, $_->[1]);
        eq_or_diff $verified, $_->[0];
        eq_or_diff $_->[0]->{issued_at}, time;
    }
}

sub _get_signed_request_no_key : Test(1) {
    dies_here_ok {
        Authen::SignedRequest->get_signed_request("abc");
    };
}

sub _verify_signed_request_no_key : Test(1) {
    dies_here_ok {
        Authen::SignedRequest->verify_signed_request("abc");
    };
}

sub _verify_signed_request_broken_input : Test(3) {
    for (
        '',
        'abc',
        'xyzaggaeeeeee.gaegfagee',
    ) {
        is +Authen::SignedRequest->verify_signed_request($_, 'abc'), undef;
    }
}

sub _verify_signed_request : Test(2) {
    my $input = 'vlXgu64BQGFSQrY0ZcJBZASMvYvTHu9GQ0YM9rjPSso.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsIjAiOiJwYXlsb2FkIn0';
    {
        local $Authen::SignedRequest::SignatureTimeout;
        my $data = Authen::SignedRequest->verify_signed_request($input, 'secret');
        eq_or_diff $data, {0 => 'payload', algorithm => 'HMAC-SHA256'};
    }
    {
        #local $Authen::SignedRequest::SignatureTimeout; # use default
        my $data = Authen::SignedRequest->verify_signed_request($input, 'secret');
        eq_or_diff $data, undef;
    }
}

__PACKAGE__->runtests;

1;
