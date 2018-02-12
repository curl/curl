Short: #
Long: progress-bar
Help: Display transfer progress as a bar
---
Make curl display transfer progress as a simple progress bar instead of the
standard, more informational, meter.

This progress bar draws a single line of '#' characters across the screen and
shows a percentage if the transfer size is known. For transfers without a
known size, it will instead output one '#' character for every 1024 bytes
transferred.
