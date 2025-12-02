#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
#
# todo-tool.pl - Manage the docs/TODO file
#
# This script helps manage the TODO file by:
# - Removing items (preserves numbering gaps, does NOT renumber)
# - Outputting full description of a specific item
# - Validating numbering consistency
# - Listing items in a section
#
# Usage:
#   todo-tool.pl --remove <item>     Remove an item (e.g., 18.1)
#   todo-tool.pl --out <item>        Output item description (e.g., 1.16)
#   todo-tool.pl --list <section>    List items in a section (e.g., 18)
#   todo-tool.pl --validate          Validate numbering consistency
#   todo-tool.pl --help              Show this help
#

use strict;
use warnings;
use Getopt::Long;
use File::Basename;

my $script_dir = dirname(__FILE__);
my $default_todo = "$script_dir/../docs/TODO";

my $help = 0;
my $remove_item = "";
my $list_section = "";
my $validate = 0;
my $output_item = "";
my $todo_file = $default_todo;

GetOptions(
    "help|h" => \$help,
    "remove=s" => \$remove_item,
    "list=s" => \$list_section,
    "validate" => \$validate,
    "out=s" => \$output_item,
    "file=s" => \$todo_file,
) or die("Error in command line arguments\n");

if($help) {
    print_help();
    exit 0;
}

# Main logic
if($remove_item) {
    remove_item($todo_file, $remove_item);
}
elsif($list_section) {
    list_items($todo_file, $list_section);
}
elsif($validate) {
    validate_numbering($todo_file);
}
elsif($output_item) {
    output_item($todo_file, $output_item);
}
else {
    print "No action specified. Use --help for usage information.\n";
    exit 1;
}

sub print_help {
    print <<'EOF';
todo-tool.pl - Manage the docs/TODO file

Usage:
  todo-tool.pl --remove <item>     Remove an item (e.g., 18.1 or 18.26)
  todo-tool.pl --list <section>    List all items in a section (e.g., 18)
  todo-tool.pl --out <item>        Output full description of an item (e.g., 1.16)
  todo-tool.pl --validate          Validate numbering consistency
  todo-tool.pl --file <path>       Specify TODO file path (default: docs/TODO)
  todo-tool.pl --help              Show this help

Examples:
  # Remove item 18.1 (subsequent items keep their numbers, gaps preserved)
  todo-tool.pl --remove 18.1

  # List all items in section 18
  todo-tool.pl --list 18

  # Output the full description of item 1.16
  todo-tool.pl --out 1.16

  # Validate the TODO file numbering
  todo-tool.pl --validate

  # Use a different TODO file
  todo-tool.pl --file .dump_todo.txt --remove 18.1
EOF
}

sub remove_item {
    my ($file, $item_number) = @_;

    # Parse item number (e.g., "18.1" -> section=18, subitem=1)
    if($item_number !~ /^(\d+)\.(\d+)$/) {
        die "Error: Invalid item number format '$item_number'. Use format like '18.1'\n";
    }

    my $section = $1;
    my $subitem = $2;

    # Read the entire file
    open(my $fh, '<', $file) or die "Cannot open $file: $!\n";
    my @lines = <$fh>;
    close($fh);

    # The TODO file has two parts: TOC (table of contents) and detailed sections
    # We need to remove the item from both parts
    my @removals;  # Array of {start, end} hash refs
    my $found_count = 0;

    # Find all occurrences of the item (TOC and detailed section)
    my $i = 0;
    while($i < scalar @lines) {
        my $line = $lines[$i];

        # Check if this line starts the item we want to remove
        # TOC items have leading space: " 18.1 sync"
        # Detailed items have no leading space: "18.1 sync"
        # Use word boundary \b to ensure exact match (18.1 won't match 18.10)
        if($line =~ /^\s*$section\.$subitem\b/) {
            my $item_start = $i;
            my $item_end = $i;
            my $in_item = 1;

            # Determine if this is a TOC item (has leading whitespace) or detailed item
            my $is_toc = ($line =~ /^\s+/);

            # Find the end of this item
            for(my $j = $i + 1; $j < scalar @lines; $j++) {
                my $next_line = $lines[$j];

                if($is_toc) {
                    # In TOC, next item also has leading space, or we hit a new section or separator
                    if($next_line =~ /^\s+\d+\.\d+\s+/ || $next_line =~ /^=+$/ || $next_line =~ /^\d+\.\s+/) {
                        $item_end = $j - 1;
                        $in_item = 0;
                        last;
                    }
                } else {
                    # In detailed section, items have no leading space
                    if($next_line =~ /^\d+\.\d+\s+/ || $next_line =~ /^=+$/ || $next_line =~ /^\d+\.\s+/) {
                        $item_end = $j - 1;
                        $in_item = 0;
                        last;
                    }
                }
                $item_end = $j;
            }

            # Remove trailing blank lines after the item content
            while($item_end > $item_start && $lines[$item_end] =~ /^\s*$/) {
                $item_end--;
            }

            # For TOC items, only remove the single line (they're typically one-liners)
            # For detailed items, remove ONE leading blank line before the item if it exists
            if(!$is_toc && $item_start > 0 && $lines[$item_start - 1] =~ /^\s*$/) {
                $item_start--;
            }

            push @removals, {start => $item_start, end => $item_end};
            $found_count++;
            $i = $item_end + 1;
        }
        else {
            $i++;
        }
    }

    if($found_count == 0) {
        die "Error: Item $item_number not found in $file\n";
    }

    print "Found $found_count occurrence(s) of item $item_number\n";

    # Remove items in reverse order to maintain line numbers
    for my $removal (reverse @removals) {
        my $start = $removal->{start};
        my $end = $removal->{end};
        print "Removing lines " . ($start + 1) . " to " . ($end + 1) . "\n";
        splice(@lines, $start, $end - $start + 1);
    }

    # Write back to file
    open($fh, '>', $file) or die "Cannot write to $file: $!\n";
    print $fh @lines;
    close($fh);

    print "Successfully removed item $item_number\n";
}

sub list_items {
    my ($file, $section_num) = @_;

    if($section_num !~ /^\d+$/) {
        die "Error: Invalid section number '$section_num'. Use a number like '18'\n";
    }

    open(my $fh, '<', $file) or die "Cannot open $file: $!\n";

    my $in_section = 0;
    my $section_title = "";
    my @items;
    my $found_separator = 0;

    while(my $line = <$fh>) {
        # Look for the separator that marks end of TOC
        if($line =~ /^=+$/) {
            $found_separator = 1;
            last if $in_section;  # Stop if we already found our section in TOC
            next;
        }

        # Only look in the TOC (before the separator)
        if(!$found_separator) {
            # Check for section start (may have leading whitespace in TOC, format " 18. Section Title")
            if($line =~ /^\s*$section_num\.\s+(.+)$/) {
                # Ensure this is a section header, not an item (items have format "18.1")
                if($line !~ /^\s*$section_num\.\d+/) {
                    $in_section = 1;
                    $section_title = $1;
                    chomp($section_title);
                    next;
                }
            }

            # Check for section item (has leading whitespace in TOC)
            if($in_section && $line =~ /^\s+$section_num\.(\d+)\s+(.+)$/) {
                my $item_title = $2;
                chomp($item_title);
                push @items, {num => $1, title => $item_title};
                next;
            }

            # Check if we've left the section (new section starts)
            if($in_section && $line =~ /^(\d+)\.\s+/ && $1 != $section_num) {
                last;
            }
        }
    }

    close($fh);

    if(!$in_section && !@items) {
        print "Section $section_num not found in $file\n";
        return;
    }

    print "Section $section_num";
    print ": $section_title" if $section_title;
    print "\n";
    print "=" x 70 . "\n";

    if(@items) {
        foreach my $item (@items) {
            printf " %s.%-3s %s\n", $section_num, $item->{num}, $item->{title};
        }
        print "\nTotal: " . scalar(@items) . " item(s)\n";
    }
    else {
        print "No items found in this section.\n";
    }
}

sub validate_numbering {
    my ($file) = @_;

    open(my $fh, '<', $file) or die "Cannot open $file: $!\n";

    my %sections;
    my @errors;
    my $line_num = 0;

    while(my $line = <$fh>) {
        $line_num++;

        # Match section items like "18.1 sync"
        if($line =~ /^\s+(\d+)\.(\d+)\s+/) {
            my $section = $1;
            my $subitem = $2;

            if(!exists $sections{$section}) {
                $sections{$section} = [];
            }

            push @{$sections{$section}}, {
                num => $subitem,
                line => $line_num,
                text => $line
            };
        }
    }

    close($fh);

    # Check each section for gaps or duplicates
    foreach my $section (sort {$a <=> $b} keys %sections) {
        my @items = @{$sections{$section}};

        # Sort by item number
        @items = sort {$a->{num} <=> $b->{num}} @items;

        # Check for duplicates
        my %seen;
        foreach my $item (@items) {
            if($seen{$item->{num}}) {
                push @errors, sprintf(
                    "Section %d: Duplicate item %d.%d at line %d",
                    $section, $section, $item->{num}, $item->{line}
                );
            }
            $seen{$item->{num}} = 1;
        }

        # Note: We don't check for gaps since the TODO file intentionally
        # has gaps in numbering (e.g., 1.1, 1.2, 1.3, then 1.10)
    }

    if(@errors) {
        print "Validation errors found:\n";
        foreach my $error (@errors) {
            print "  - $error\n";
        }
        exit 1;
    }
    else {
        print "Validation successful: No numbering errors found.\n";
        print "Total sections checked: " . scalar(keys %sections) . "\n";

        # Show summary
        foreach my $section (sort {$a <=> $b} keys %sections) {
            my $count = scalar @{$sections{$section}};
            print "  Section $section: $count item(s)\n";
        }
    }
}

sub output_item {
    my ($file, $item_number) = @_;

    # Parse item number (e.g., "1.16" -> section=1, subitem=16)
    if($item_number !~ /^(\d+)\.(\d+)$/) {
        print STDERR "Error: Invalid item number format '$item_number'. Use format like '1.16'\n";
        exit 1;
    }

    my $section = $1;
    my $subitem = $2;

    my $fh;
    if(!open($fh, '<', $file)) {
        print STDERR "Error: Cannot open $file: $!\n";
        exit 1;
    }

    my $found = 0;
    my $in_item = 0;
    my @item_lines;

    while(my $line = <$fh>) {
        # Look for the item heading (without leading whitespace in detailed section)
        # Use word boundary \b to ensure exact match (18.1 won't match 18.10)
        if($line =~ /^$section\.$subitem\b\s+(.+)$/) {
            $found = 1;
            $in_item = 1;
            # Print the item heading
            print "$section.$subitem $1\n";
            next;
        }

        # If we're in the item, collect lines until the next item
        if($in_item) {
            # Check for next item or section
            if($line =~ /^\d+\.\d+\s+/ || $line =~ /^\d+\.\s+/) {
                last;
            }
            push @item_lines, $line;
        }
    }

    close($fh);

    if(!$found) {
        print STDERR "Error: Item $item_number not found in $file\n";
        exit 1;
    }

    # Print the description
    print @item_lines;
}
