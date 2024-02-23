# !/bin/bash
set -e

export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1
# export AFL_NO_UI=1
export AFL_MAP_SIZE=256000
export AFL_DRIVER_DONT_DEFER=1

afl-fuzz -i ./input_dir -o ./output_dir -m none -c ./cmplog/base64 -d -- ./afl/base64 -d @@
# afl-fuzz -i ./input_dir -o ./output_dir -- ./afl/base64 -d @@

# /magma_shared/findings/default/queue /magma_shared/seed_time.dat

