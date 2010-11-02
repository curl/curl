open(S, '<', $ARGV[0]);

print <<EOF
#include "curl/curl.h"
 
int test[] = {
EOF
    ;
while(<S>) {
    my @a=split(/ +/);
    chomp $a[0];
    chomp $a[3];
    if($a[0] && !$a[3]) {
        printf("%s,\n", $a[0]);
    }
}
print "};\n";
close(S);
