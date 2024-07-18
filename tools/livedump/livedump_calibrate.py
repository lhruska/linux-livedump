#!/usr/bin/python3

import argparse
import time
import math
import sys
from bcc import BPF
from bcc.utils import printb

debug = False

def sysfs_write(path, val, ignore_fail=False):
    if debug:
        print("Writing {} to {}".format(val, path))
    try:
        with open(path, 'w') as w:
            w.write(val+'\n')
    except:
        if not ignore_fail:
            print("Livedump is not enabled on currently running kernel or invalid input.", file=sys.stderr)
            exit(1)

def sysfs_read(path, ignore_fail=False):
    try:
        with open(path, 'r') as r:
            return r.read().strip()
    except:
        if not ignore_fail:
            print("Livedump is not enabled on currently running kernel.", file=sys.stderr)
            exit(1)

def set_type(t):
    sysfs_write('/sys/kernel/livedump/type', t)

def set_buffer_size(size):
    sysfs_write('/sys/kernel/livedump/buffer_size', str(size))

def set_output(output):
    sysfs_write('/sys/kernel/livedump/output', output)

def set_state(state, ignore_fail=False):
    sysfs_write('/sys/kernel/livedump/state', str(state), ignore_fail)

def get_failed():
    return int(sysfs_read('/sys/kernel/livedump/failed'))

def get_state():
    return int(sysfs_read('/sys/kernel/livedump/state').split('\n')[0])

prog = """
BPF_ARRAY(max_prio, u64, 2);

TRACEPOINT_PROBE(livedump, livedump_handle_page) {
    u32 key = 0;
    u64 *max_val, cur_val, old_val;

    cur_val = args->pend_len;
    max_val = max_prio.lookup(&key);

    if (max_val) {
        old_val = *max_val;
        if (cur_val > old_val) {
            max_prio.update(&key, &cur_val);
        }
    } else {
        max_prio.update(&key, &cur_val);
    }
    return 0;
}

TRACEPOINT_PROBE(livedump, livedump_handle_page_finished) {
    u32 max_key = 0, idx_key = 1;
    u64 set_val = 1;
    u64 *val = max_prio.lookup(&idx_key);
    u64 *max;

    if (val) {
        if (*val > 0)
            return 0;
        else
            max_prio.update(&idx_key, &set_val);
    } else {
        max_prio.update(&idx_key, &set_val);
    }

    max = max_prio.lookup(&max_key);
    if (max) {
        bpf_trace_printk("%lu\\n", *max);
    }


    return 0;
}
"""

parser = argparse.ArgumentParser(description="Comparer of livedump and qemu dump made at the same time.")
parser.add_argument('type', type=str, help="Type of livedump to calibrate.")
parser.add_argument('dummy_output', type=str, help="Temporary output, where incomplete testing dump can be stored.")
parser.add_argument('max_buffer_size', type=int, help="Maximal allowed value to be used during calibration.")
parser.add_argument('--debug', action='store_true', help="Enable debug output.")

args = parser.parse_args()

debug = args.debug

curr_state = get_state()

if curr_state != 0 and curr_state != 5:
    set_state(5, True)
set_type(args.type)
set_output(args.dummy_output)
set_buffer_size(args.max_buffer_size)

# load BPF program
b = BPF(text=prog)
b.attach_tracepoint("livedump:livedump_handle_page", "livedump_handle_page")
b.attach_tracepoint("livedump:livedump_handle_page_finished",
                    "livedump_handle_page_finished")

set_state(1)
time.sleep(1)
set_state(2)
time.sleep(1)
set_state(5)

msg = ""
while 1:
    try:
        (_, _, _, _, _, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    break

actual = int(msg)
minimal = 2 ** math.ceil(math.log2(actual))
recommended = minimal * 4

if get_failed() != 0:
    print("The livedump failed. Please increase maximal buffer size and run calibration again.", file=sys.stderr)
    exit(1)

print(f"Actual:      {actual}")
print(f"Minimal:     {minimal}")
print(f"Recommended: {recommended}")

