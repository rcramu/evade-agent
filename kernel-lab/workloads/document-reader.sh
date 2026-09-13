#!/bin/sh
# Lab child process. Name on disk is copied to document-reader.
printf 'architecture note\n' >/tmp/evade-note
cat /tmp/evade-note >/dev/null
