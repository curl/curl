Long: path-as-is
Help: Do not squash .. sequences in URL path
Added: 7.42.0
---
Tell curl to not handle sequences of /../ or /./ in the given URL
path. Normally curl will squash or merge them according to standards but with
this option set you tell it not to do that.
