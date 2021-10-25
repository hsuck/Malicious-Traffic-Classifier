#!/bin/bash

cat lock_time_* | awk '{sum += $1} END {print "lock time: " sum / (NR*1000000) " ms"}'
cat classify_time_* | awk '{sum += $1} END {print "classify time: " sum / (NR*1000000) " ms"}'
cat log_time_* | awk '{sum += $1} END {print "log time: " sum / (NR*1000000) " ms"}'
