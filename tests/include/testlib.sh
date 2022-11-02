#!/bin/sh
# Usage: . testlib.sh
# Simple shell command language test library.
#
# Tests must follow the basic form:
#
#   begin_test "the thing"
#   (
#        set -e
#        echo "hello"
#        false
#   )
#   end_test
#
# When a test fails its stdout and stderr are shown.
#
# Note that tests must `set -e' within the subshell block or failed assertions
# will not cause the test to fail and the result may be misreported.
#
# Copyright (c) 2011-13 by Ryan Tomayko <http://tomayko.com>
# License: MIT
#
# this is a modified verison of:
# https://github.com/github/glb-director/blob/9e631ff5ed075a6498efc730905b4497cd5bbce7/src/glb-healthcheck/test/lib.sh
#

set -e

if [ $TEST_SUITE != "" ]; then 
  TEST_SUITE="[$TEST_SUITE]"
fi

# Put bin path on PATH
PATH="$(cd $(dirname "$0")/.. && pwd)/bin:$PATH"

# create a temporary work space
TMPDIR="$(cd $(dirname "$0")/.. && pwd)"/tmp
TRASHDIR="$TMPDIR/$(basename "$0")-$$"

# keep track of num tests and failures
tests=0
failures=0

# this runs at process exit
atexit () {
    rm -rf "$TMPDIR"
    if [ $failures -gt 0 ]
    then exit 1
    else exit 0
    fi
}

# create the trash dir
trap "atexit" EXIT
mkdir -p "$TRASHDIR"
cd "$TRASHDIR"

# Mark the beginning of a test. A subshell should immediately follow this
# statement.
begin_test () {
    test_status=$?
    [ -n "$test_description" ] && end_test $test_status
    unset test_status

    tests=$(( tests + 1 ))
    test_description="$1"

    exec 3>&1 4>&2
    out="$TRASHDIR/out"
    err="$TRASHDIR/err"
    exec 1>"$out" 2>"$err"

    # allow the subshell to exit non-zero without exiting this process
    set -x +e
    before_time=$(date '+%s')
}

report_failure () {
  msg=$1
  desc=$2
  failures=$(( failures + 1 ))
  printf "test: %-60s $msg\n" "$desc ..."
  (
      echo "-- stdout --"
      sed 's/^/    /' <"$TRASHDIR/out"
      echo "-- stderr --"
      grep -a -v -e '^\+ end_test' -e '^+ set +x' <"$TRASHDIR/err" |
          sed 's/^/    /'
  ) 1>&2
}

# Mark the end of a test.
end_test () {
    test_status="${1:-$?}"
    ex_fail="${2:-0}"
    after_time=$(date '+%s')
    set +x -e
    exec 1>&3 2>&4
    elapsed_time=$((after_time - before_time))

    if [ "$test_status" -eq 0 ]; then
      if [ "$ex_fail" -eq 0 ]; then
        printf "test: $TEST_SUITE %-75s OK (${elapsed_time}s)\n" "$test_description ..."
      else
        report_failure "OK (unexpected)" "$test_description ..."
      fi
    else
      if [ "$ex_fail" -eq 0 ]; then
        report_failure "FAILED (${elapsed_time}s)" "$test_description ..."
      else
        printf "test: $TEST_SUITE %-75s FAILED (expected, ${elapsed_time}s)\n" "$test_description ..."
      fi
    fi
    unset test_description
}

end_test_exfail () {
  end_test $? 1
}
