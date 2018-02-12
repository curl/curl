Long: xattr
Help: Store metadata in extended file attributes
---
When saving output to a file, this option tells curl to store certain file
metadata in extended file attributes. Currently, the URL is stored in the
xdg.origin.url attribute and, for HTTP, the content type is stored in
the mime_type attribute. If the file system does not support extended
attributes, a warning is issued.
