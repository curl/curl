sub checkstunnel {
    my @paths=("/usr/sbin", "/usr/local/sbin", "/sbin", "/usr/bin",
               "/usr/local/bin", split(":", $ENV{'PATH'}));
    for(@paths) {
        if( -x "$_/stunnel") {
            return "$_/stunnel";
        }
    }
}

1;
