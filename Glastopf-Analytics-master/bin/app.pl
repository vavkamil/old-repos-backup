#!/usr/bin/env perl

use FindBin;
use lib "$FindBin::Bin/../lib";

use MyWeb::App;
MyWeb::App->dance;
