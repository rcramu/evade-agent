#!/bin/sh
# Named document-assistant when copied. Spawns the reader as a child.
dir=$(dirname "$0")
"$dir/document-reader"
