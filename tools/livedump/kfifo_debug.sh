#!/bin/bash

get_state() {
	cat /sys/kernel/livedump/state | head -n 1
}

while [ "$(get_state)" != "1" ]; do
	sleep 1
done

starttime="$(date +%s%N)"

echo "state;time_ns;page_fault_pending;page_fault_inserted;page_fault_finished;sweep_pending;sweep_inserted;sweep_finished"
while [ "$(get_state)" != "5" ]; do
	cat /sys/kernel/livedump/kfifo_debug  | cut -f 2 -d ':' | tr -d ' ' | awk -v timestamp="$(date +%s%N)" -v starttime=$starttime 'NR==1{state=$0; next} NR==3{line=$0; next} NR==4{print state ";" timestamp-starttime ";" line ";" $0; ext}' | tr ',' ';'
done
