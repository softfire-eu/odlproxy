#!/bin/bash

TOKEN=$1

curl -X PUT \
  http://10.200.4.8:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:72664714402125/table/1/ \
  -H 'authorization: Basic YWRtaW46YWRtaW4=' \
  -H 'cache-control: no-cache' \
  -H 'content-type: application/json' \
  -H 'Auth-Secret: 90d82936f887a871df8cc82c1518a43e' \
  -H 'API-Token'
  -d @empty_table_1.json
