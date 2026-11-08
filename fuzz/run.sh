#!/bin/sh
# Builds the fuzz targets with libFuzzer's coverage instrumentation on
# stable Rust, then runs them.
#
#   fuzz/run.sh                 every target for 60 s, one after another
#   fuzz/run.sh dns_query 600   one target for ten minutes
#   JOBS=8 fuzz/run.sh "" 300   every target at once, 300 s each
#
# cargo-fuzz (`cargo fuzz run dns_query`) does the same with nightly and
# adds AddressSanitizer, which matters little here: the code under test
# has no `unsafe`. Crashes land in fuzz/artifacts/<target>/.
set -eu
cd "$(dirname "$0")"
only="${1:-}"
seconds="${2:-60}"
jobs="${JOBS:-1}"
targets="filter_line filter_list compile explain dns_list dns_query dns_answer config domain metrics_request"
[ -n "$only" ] && targets="$only"

# The seeds are written by a plain build: instrumented code needs
# libFuzzer's runtime linked in, which only the targets have.
cargo run --quiet --release --bin seeds --target-dir target/seeds -- corpus

# An explicit --target keeps these flags off build scripts and proc macros,
# which run on the host and can't link the coverage hooks.
host=$(rustc -vV | sed -n 's/^host: //p')
export RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
-Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table \
-Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing -Cdebug-assertions -Coverflow-checks"
for t in $targets; do
  cargo build --quiet --release --target "$host" --bin "$t"
done

status=0
run() {
  mkdir -p "corpus/$1" "artifacts/$1"
  "target/$host/release/$1" "corpus/$1" -max_total_time="$seconds" -timeout=10 \
    -rss_limit_mb=2048 -max_len=65536 -artifact_prefix="artifacts/$1/" \
    -print_final_stats=1 >"artifacts/$1.log" 2>&1 || return 1
}
if [ "$jobs" -gt 1 ]; then
  for t in $targets; do run "$t" & done
  wait || status=1
else
  for t in $targets; do run "$t" || status=1; done
fi
for t in $targets; do
  execs=$(grep -o 'stat::number_of_executed_units: *[0-9]*' "artifacts/$t.log" | grep -o '[0-9]*$' || echo "?")
  rate=$(grep -o 'stat::average_exec_per_sec: *[0-9]*' "artifacts/$t.log" | grep -o '[0-9]*$' || echo "?")
  cov=$(grep -o 'cov: [0-9]*' "artifacts/$t.log" | tail -1 | grep -o '[0-9]*' || echo "?")
  crashes=$(find "artifacts/$t" -type f | wc -l | tr -d ' ')
  printf '%-16s %12s runs %8s/s  coverage %6s  crashes %s\n' "$t" "$execs" "$rate" "$cov" "$crashes"
  [ "$crashes" = 0 ] || status=1
done
exit $status
