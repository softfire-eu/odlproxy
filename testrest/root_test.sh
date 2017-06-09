#!/bin/bash

HOSTNAME_PORT=10.200.4.8:8001
EXPERIMENT_ID=a5cfaf1e81f35fde41bef54e35772f2b
TENANT_ID=fed0b52c7e034d5785880613e78d4411

POST_TOKEN_DATA="{ \"experiment_id\": \""$EXPERIMENT_ID"\", \"tenant_id\": \""$TENANT_ID"\" }"
echo $POST_TOKEN_DATA

curl -X POST \
  http://$HOSTNAME_PORT/SDNproxySetup \
  -H 'cache-control: no-cache' \
  -H 'content-type: application/json' \
  -H 'Auth-Secret: 90d82936f887a871df8cc82c1518a43e' \
  -d $POST_TOKEN_DATA
