# fetch exports from input header and write them to STDOUT
BEGIN {
    add_symbol("curl_strequal")
    add_symbol("curl_strnequal")
}

function add_symbol(sym_name) {
    sub(" ", "", sym_name)
    exports[++idx] = sym_name
}


/^CURL_EXTERN .* [*]?curl_.*[(]/ {
    sub("[(].*", "")
    sub("^.* ", "")
    sub("^[*]", "")
    add_symbol($0)
}

END {
    printf("Added %d symbols to export list.\n", idx) > "/dev/stderr"
    # sort symbols with shell sort
    increment = int(idx / 2)
    while (increment > 0) {
        for (i = increment+1; i <= idx; i++) {
            j = i
            temp = exports[i]
            while ((j >= increment+1) && (exports[j-increment] > temp)) {
                exports[j] = exports[j-increment]
                j -= increment
            }
            exports[j] = temp
        }
        if (increment == 2)
            increment = 1
        else
            increment = int(increment*5/11)
    }
    # print the array
    if (EXPPREFIX) {
        printf(" (%s)\n", EXPPREFIX)
    }
    while (x < idx - 1) {
        printf(" %s,\n", exports[++x])
    }
    printf(" %s\n", exports[++x])
}

