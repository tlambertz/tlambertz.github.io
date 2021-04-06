#!/bin/sh

# requires exiftran and exiftool. parts of fbida and perl-image-exiftool packets.

# auto-rotate jpgs according to the exif tags before stripping
find content/ -iname "*.jpg" | parallel "exiftran -ai {}"

# strip the exif tags from all jpg files in subdirectories.
find content/ -iname "*.jpg" | parallel "exiftool -overwrite_original -P -all= {}"
