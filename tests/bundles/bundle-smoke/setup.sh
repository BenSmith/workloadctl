#!/bin/sh
mkdir -p /run/bundle-smoke
echo "setup $1 $(date +%s)" > "/run/bundle-smoke/setup.$WORKLOAD_NAME"
