#!/bin/sh
# Laboratory process-name fixture for Table C.1 sink class. No network.
printf 'lab-sink\n' >/tmp/evade-sink.txt
cat /tmp/evade-sink.txt >/dev/null
