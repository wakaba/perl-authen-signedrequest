package test::Ridge::Response::Role::SignedRequest;
use strict;
use warnings;
use Path::Class;
use lib file(__FILE__)->dir->parent->subdir('lib')->stringify;
use lib glob file(__FILE__)->dir->parent->subdir('modules', '*', 'lib')->stringify;
use base qw(Test::Class);
use Test::MoreMore;

{
    package my::mock::ridge::response;
    
    sub content_type {
        if (@_ > 1) {
            $_[0]->{content_type} = $_[1];
        }
        return $_[0]->{content_type};
    }

    sub content {
        if (@_ > 1) {
            $_[0]->{content} = $_[1];
        }
        return $_[0]->{content};
    }
}

{
    package my::ridge::response;
    use Ridge::Response::Role::SignedRequest;
    push our @ISA, qw(my::mock::ridge::response Ridge::Response::Role::SignedRequest);
}

sub _set_sjson_content : Test(3) {
    my $res = bless {}, 'my::ridge::response';
    $res->set_sjson_content({abc => "\x{1000}", abc => [12, undef]}, 'secret key');
    
    is $res->content_type, 'application/x-www-form-urlencoded';
    like $res->content, qr{^signed_request=[^&;=]+$};

    my $signed = [split /=/, $res->content]->[1];
    require Authen::SignedRequest;
    my $result = Authen::SignedRequest->verify_signed_request($signed, 'secret key');
    delete $result->{algorithm};
    delete $result->{issued_at};
    eq_or_diff $result, {abc => "\x{1000}", abc => [12, undef]};
}

__PACKAGE__->runtests;

1;
