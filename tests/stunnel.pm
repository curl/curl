sub checkstunnel {
    my @paths=("/usr/sbin", "/usr/local/sbin", "/sbin", "/usr/bin",
               "/usr/local/bin");
    for(@paths) {
        if( -x "$_/stunnel") {
            return "$_/stunnel";
        }
    }
}

1;
