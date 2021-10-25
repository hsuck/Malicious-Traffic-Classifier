#!/bin/bash

cat lock_time | awk '{sum += $1; cols += 1} END {print "lock time: " sum / (NR*1000000)}'
cat classify_time | awk '{sum += $1; cols += 1} END {print "classify time: " sum / (NR*1000000)}'
cat log_time | awk '{sum += $1; cols += 1} END {print "log time: " sum / (NR*1000000)}'
