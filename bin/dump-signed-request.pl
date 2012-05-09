#!/usr/bin/perl
use strict;
use warnings;
use Path::Class;
use lib file(__FILE__)->dir->parent->subdir('lib')->stringify;
use lib file(__FILE__)->dir->parent->subdir('modules', 'jsonfunctionsxs', 'lib')->stringify;
use Authen::SignedRequest;
use Data::Dumper;

my ($signed, $key) = @ARGV;
$signed =~ s/^signed_request=//;

$Authen::SignedRequest::Warn = 1;
$Authen::SignedRequest::SignatureTimeout = 0 if $ENV{IGNORE_TIMEOUT};

my $data = Authen::SignedRequest->verify_signed_request($signed, $key);

print "Valid: " . ($data ? 'Yes' : 'No') . "\n";
if ($data) {
    print "Data:\n";
    print Dumper $data;
}
