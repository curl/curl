Short: #
Long: progress-bar
Help: Display transfer progress as a bar
Category: verbose
---
Make curl display transfer progress as a simple progress bar instead of the
standard, more informational, meter.

This progress bar draws a single line of '#' characters across the screen and
shows a percentage if the transfer size is known. For transfers without a
known size, there will be space ship (-=o=-) that moves back and forth but
only while data is being transferred, with a set of flying hash sign symbols on
top.
