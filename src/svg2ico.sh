#!/bin/sh

# requires: imagemagick svg2png

src='curl.svg'

# strip .svg extension
dst="$(basename "${src}" .svg)"

rm -f ./${dst}-*.png "${dst}.ico"

# convert .svg to .png in multiple resolutions
for res in 256 48; do
  convert -background none "${src}" -depth 8 -define png:format=png32 \
    -resize ${res} "${dst}-${res}x${res}.png"
done
for res in 32 16; do
  svg2png --width ${res} "${src}" "${dst}-${res}x${res}.png"
done

# create Windows app icon
convert \
  \( "${dst}-16x16.png" \) \
  \( "${dst}-32x32.png" \) \
  \( "${dst}-48x48.png" \) \
  \( "${dst}-256x256.png" \) \
  -strip "${dst}.ico"

rm -f ./${dst}-*.png
