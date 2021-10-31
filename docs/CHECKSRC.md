# checksrc

This is the tool we use within the curl project to scan C source code and
check that it adheres to our [Source Code Style guide](CODE_STYLE.md).

## Usage

    checksrc.pl [options] [file1] [file2] ...

## Command line options

`-W[file]` skip that file and excludes it from being checked. Helpful
when, for example, one of the files is generated.

`-D[dir]` directory name to prepend to file names when accessing them.

`-h` shows the help output, that also lists all recognized warnings

## What does checksrc warn for?

checksrc does not check and verify the code against the entire style guide,
but the script is instead an effort to detect the most common mistakes and
syntax mistakes that contributors make before they get accustomed to our code
style. Heck, many of us regulars do the mistakes too and this script helps us
keep the code in shape.

    checksrc.pl -h

Lists how to use the script and it lists all existing warnings it has and
problems it detects. At the time of this writing, the existing checksrc
warnings are:

- `ASSIGNWITHINCONDITION`: Assignment within a conditional expression. The
  code style mandates the assignment to be done outside of it.

- `ASTERISKNOSPACE`: A pointer was declared like `char* name` instead of the
   more appropriate `char *name` style. The asterisk should sit next to the
   name.

- `ASTERISKSPACE`: A pointer was declared like `char * name` instead of the
   more appropriate `char *name` style. The asterisk should sit right next to
   the name without a space in between.

- `BADCOMMAND`: There's a bad !checksrc! instruction in the code. See the
   **Ignore certain warnings** section below for details.

- `BANNEDFUNC`: A banned function was used. The functions sprintf, vsprintf,
   strcat, strncat, gets are **never** allowed in curl source code.

- `BRACEELSE`: '} else' on the same line. The else is supposed to be on the
   following line.

- `BRACEPOS`: wrong position for an open brace (`{`).

- `BRACEWHILE`: more than once space between end brace and while keyword

- `COMMANOSPACE`: a comma without following space

- `COPYRIGHT`: the file is missing a copyright statement!

- `CPPCOMMENTS`: `//` comment detected, that is not C89 compliant

- `DOBRACE`: only use one space after do before open brace

- `EMPTYLINEBRACE`: found empty line before open brace

- `EQUALSNOSPACE`: no space after `=` sign

- `EQUALSNULL`: comparison with `== NULL` used in if/while. We use `!var`.

- `EXCLAMATIONSPACE`: space found after exclamations mark

- `FOPENMODE`: `fopen()` needs a macro for the mode string, use it

- `INDENTATION`: detected a wrong start column for code. Note that this
   warning only checks some specific places and will certainly miss many bad
   indentations.

- `LONGLINE`: A line is longer than 79 columns.

- `MULTISPACE`: Multiple spaces were found where only one should be used.

- `NOSPACEEQUALS`: An equals sign was found without preceding space. We prefer
  `a = 2` and *not* `a=2`.

- `NOTEQUALSZERO`: check found using `!= 0`. We use plain `if(var)`.

- `ONELINECONDITION`: do not put the conditional block on the same line as `if()`

- `OPENCOMMENT`: File ended with a comment (`/*`) still "open".

- `PARENBRACE`: `){` was used without sufficient space in between.

- `RETURNNOSPACE`: `return` was used without space between the keyword and the
   following value.

- `SEMINOSPACE`: There was no space (or newline) following a semicolon.

- `SIZEOFNOPAREN`: Found use of sizeof without parentheses. We prefer
  `sizeof(int)` style.

- `SNPRINTF` - Found use of `snprintf()`. Since we use an internal replacement
   with a different return code etc, we prefer `msnprintf()`.

- `SPACEAFTERPAREN`: there was a space after open parenthesis, `( text`.

- `SPACEBEFORECLOSE`: there was a space before a close parenthesis, `text )`.

- `SPACEBEFORECOMMA`: there was a space before a comma, `one , two`.

- `SPACEBEFOREPAREN`: there was a space before an open parenthesis, `if (`,
   where one was not expected

- `SPACESEMICOLON`: there was a space before semicolon, ` ;`.

- `TABS`: TAB characters are not allowed!

- `TRAILINGSPACE`: Trailing whitespace on the line

- `TYPEDEFSTRUCT`: we frown upon (most) typedefed structs

- `UNUSEDIGNORE`: a checksrc inlined warning ignore was asked for but not used,
   that is an ignore that should be removed or changed to get used.

### Extended warnings

Some warnings are quite computationally expensive to perform, so they are
turned off by default. To enable these warnings, place a `.checksrc` file in
the directory where they should be activated with commands to enable the
warnings you are interested in. The format of the file is to enable one
warning per line like so: `enable <EXTENDEDWARNING>`

Currently there is one extended warning which can be enabled:

- `COPYRIGHTYEAR`: the current changeset has not updated the copyright year in
   the source file

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

If the enabling is not performed before the end of the file, it will be enabled
automatically for the next file.

You can also opt to ignore just N violations so that if you have a single long
line you just cannot shorten and is agreed to be fine anyway:

    /* !checksrc! disable LONGLINE 1 */

... and the warning for long lines will be enabled again automatically after
it has ignored that single warning. The number `1` can of course be changed to
any other integer number. It can be used to make sure only the exact intended
instances are ignored and nothing extra.

### Directory wide ignore patterns

This is a method we have transitioned away from. Use inline ignores as far as
possible.

Make a `checksrc.skip` file in the directory of the source code with the
false positive, and include the full offending line into this file.
