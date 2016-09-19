# checksrc

This is the tool we use within the curl project to scan C source code and
check that it adheres to our [Source Code Style guide](CODE_STYLE.md).

## Usage

    checksrc.pl [options] [file1] [file2] ...

## Command line options

`-W[file]` whitelists that file and excludes it from being checked. Helpful
when, for example, one of the files is generated.

`-D[dir]` directory name to prepend to file names when accessing them.

`-h` shows the help output, that also lists all recognized warnings

## What does checksrc warn for?

checksrc does not check and verify the code against the entire style guide,
but the script is instead an effort to detect the most common mistakes and
syntax mistakes that contributers make before they get accustomed to our code
style. Heck, many of us regulars do the mistakes too and this script helps us
keep the code in shape.

    checksrc.pl -h

Lists how to use the script and it lists all existing warnings it has and
problems it detects. At the time of this writing, the existing checksrc
warnings are:

- `BADCOMMAND`: There's a bad !checksrc! instruction in the code. See the
   **Ignore certain warnings** section below for details.

- `BANNEDFUNC`: A banned function was used. The funtions sprintf, vsprintf,
   strcat, strncat, gets are **never** allowed in curl source code.

- `BRACEELSE`: '} else' on the same line. The else is supposed to be on the
  following line.

- `BRACEPOS`: wrong position for an open brace (`{`).

- `COMMANOSPACE`: a comma without following space

- `COPYRIGHT`: the file is missing a copyright statement!

- `CPPCOMMENTS`: `//` comment detected, that's not C89 compliant

- `FOPENMODE`: `fopen()` needs a macro for the mode string, use it

- `INDENTATION`: detected a wrong start column for code. Note that this warning
   only checks some specific places and will certainly miss many bad
   indentations.

- `LONGLINE`: A line is longer than 79 columns.

- `PARENBRACE`: `){` was used without sufficient space in between.

- `RETURNNOSPACE`: `return` was used without space between the keyword and the
   following value.

- `SPACEAFTERPAREN`: there was a space after open parenthesis, `( text`.

- `SPACEBEFORECLOSE`: there was a space before a close parenthesis, `text )`.

- `SPACEBEFORECOMMA`: there was a space before a comma, `one , two`.

- `SPACEBEFOREPAREN`: there was a space before an open parenthesis, `if (`,
   where one was not expected

- `SPACESEMILCOLON`: there was a space before semicolon, ` ;`.

- `TABS`: TAB characters are not allowed!

- `TRAILINGSPACE`: Trailing white space on the line

- `UNUSEDIGNORE`: a checksrc inlined warning ignore was asked for but not used,
   that's an ignore that should be removed or changed to get used.

## Ignore certain warnings

Due to the nature of the source code and the flaws of the checksrc tool, there
is sometimes a need to ignore specific warnings. checksrc allows a few
different ways to do this.

### Inline ignore

You can control what to ignore within a specific source file by providing
instructions to checksrc in the source code itself. You need a magic marker
that is `!checksrc!` followed by the instruction. The instruction can ask to
ignore a specific warning N number of times or you ignore all of them until
you mark the end of the ignored section.

Inline ignores are only done for that single specific source code file.

Example

    /* !checksrc! disable LONGLINE all */

This will ignore the warning for overly long lines until it is re-enabled with:

    /* !checksrc! enable LONGLINE */

If the enabling isn't performed before the end of the file, it will be enabled
automatically for the next file.

You can also opt to ignore just N violations so that if you have a single long
line you just can't shorten and is agreed to be fine anyway:

    /* !checksrc! disable LONGLINE 1 */

... and the warning for long lines will be enabled again automatically after
it has ignored that single warning. The number `1` can of course be changed to
any other integer number. It can be used to make sure only the exact intended
instances are ignored and nothing extra.

### Directory wide ignore patterns

This is a method we've transitioned away from. Use inline ignores as far as
possible.

Make a `checksrc.whitelist` file in the directory of the source code with the
false positive, and include the full offending line into this file.
