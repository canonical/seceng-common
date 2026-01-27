#!/bin/bash

SCRIPT_DIR=$(dirname "$0")

if test "$1" == "json"; then
	if [ -n "$2" ]; then
		cp $SCRIPT_DIR/test.json $2
	else
		cat $SCRIPT_DIR/test.json
	fi
	exit
fi

NUM=1
for ARG in "$@"; do
  echo "$NUM: $ARG"
  NUM=$((NUM + 1))
done

echo "it's working"
echo "this is an error" >&2
