#!/bin/sh

# check if there is any jpg that still has exif tags.
# check is rather crude. Just looking if `file` output contains the string exif.
# using gnu parallel for speed. It exits as soon as one check succeeds.

find -iname "*.jpg" | parallel  --halt now,success=1 "file {} | grep -i exif"
