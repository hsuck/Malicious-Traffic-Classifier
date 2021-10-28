#!/bin/bash

cat dealt_flow_time_* | awk '{sum += $1} END {print "fill zero times: " sum / (NR) }'
cat flow2tensor_time_* | awk '{sum += $1} END {print "flow2tensor_time_: " sum / (NR*1000000) " ms"}'
cat classifier_time_* | awk '{sum += $1} END {print "classifier_time_: " sum / (NR*1000000) " ms"}'
cat predicted_time_* | awk '{sum += $1} END {print "predicted_time_: " sum / (NR*1000000) " ms"}'
cat lock_time_* | awk '{sum += $1} END {print "lock time: " sum / (NR*1000000) " ms"}'
cat log_time_* | awk '{sum += $1} END {print "log time: " sum / (NR*1000000) " ms"}'