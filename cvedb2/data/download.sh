#!/usr/bin/env bash

set -e

YEAR=`date +'%Y'`

for y in $(seq $YEAR -1 2002); do
  wget -N https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.meta
  wget -N https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.json.gz
done
