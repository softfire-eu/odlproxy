#!/bin/python
import httplib
import json
import logging
import urlparse
import requests

__author__ = 'Massimiliano Romano'

#HOSTNAME_PORT="10.200.4.8:8001"
HOSTNAME_PORT="10.200.4.30:8001"
EXPERIMENT_ID="a5cfaf1e81f35fde41bef54e35772f2b"
TENANT_ID="fed0b52c7e034d5785880613e78d4411"

#ENABLE HTTP LOGGING
httplib.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
req_log = logging.getLogger('requests.packages.urllib3')
req_log.setLevel(logging.DEBUG)
req_log.propagate = True


print("EXPERIMENT_ID={}".format(EXPERIMENT_ID))
print("TENAND_ID={}".format(TENANT_ID))

url = 'http://{HOSTNAME_PORT}/SDNproxySetup'.format(HOSTNAME_PORT=HOSTNAME_PORT)
print("Sending token to ODLProxy ({})...".format(url))
data = '''
{{
    "experiment_id": "{0}",
    "tenant_id": "{1}"
}}
'''

headers = {'user-Auth-Secret': '90d82936f887a871df8cc82c1518a43e', 'Content-Type': 'application/json'}


post_token_data = data.format(EXPERIMENT_ID,TENANT_ID)

response = requests.post(url, data=post_token_data,headers=headers)


assert(response.status_code==200)

r_dict = json.loads(response.text)



table_range = r_dict["user-flow-tables"]
odl_url = r_dict["endpoint_url"]






'''
valid table ids are:
[2,3,4]
[5,6,7]
[8,9,10]
[11,12,13]
[14,15,16]

So I will make some requests touching table > 17
TODO: The experiment can interact with table 17 ?
'''

node_id=None

#add token to headers
headers['API-Token'] = EXPERIMENT_ID


# Get openflow nodes
get_nodes_url = urlparse.urljoin(odl_url, "/restconf/config/opendaylight-inventory:nodes")
#get_nodes_url = odl_url+ "/restconf/config/opendaylight-inventory:nodes"
response = requests.get(get_nodes_url, headers=headers)

assert(response.status_code==200)

nodes_dict = json.loads(response.text)
for node in nodes_dict["nodes"]["node"]:
  node_id = node["id"]
  #now node_id is something like "openflow:72664714402125"
  #for test we get the first node
  break

assert (node_id != None)



for table_id in table_range:
    #GET REQUEST
    #I make a request to table_id and table_id+3
    #I expect that request with table_id+3 returns 403 forbidden
    print(table_id)

    #GET TABLE 1 FLOW 1
    table_x_flow_1_url=urlparse.urljoin(odl_url,"restconf/config/opendaylight-inventory:nodes/node/{NODE_ID}/table/{TABLE_ID}/flow/1")
    #table_x_flow_1_url=odl_url + "restconf/config/opendaylight-inventory:nodes/node/{NODE_ID}/table/{TABLE_ID}/flow/1"

    table_flow_1_url = table_x_flow_1_url.format(NODE_ID=node_id,TABLE_ID=table_id)



    #PUSH TABLE 1 FLOW 1
    flow_1_json='''
    {
      "flow-node-inventory:flow": [
        {
          "id": "1",
          "flow-name": "Foo",
          "match": {
            "ipv4-destination": "10.0.10.2/24",
            "ethernet-match": {
              "ethernet-type": {
                "type": 2048
              }
            }
          },
          "priority": 2,
          "table_id": TABLE_ID,
          "instructions": {
            "instruction": [
              {
                "order": 0,
                "apply-actions": {
                  "action": [
                    {
                      "order": 0,
                      "dec-nw-ttl": {}
                    }
                  ]
                }
              }
            ]
          }
        }
      ]
    }
    '''

    table_x_flow_1_json = flow_1_json.replace("TABLE_ID",str(table_id))

    #put flow 1
    r = requests.put(table_flow_1_url,data=table_x_flow_1_json,headers=headers)
    assert(r.status_code==200 or r.status_code==201)

    #and get flow 1
    r = requests.get(table_flow_1_url,headers=headers)
    assert(r.status_code==200)

    #now try to put a flow to a not owned table
    forbidden_table_id = table_id + 3

    table_flow_1_url = table_x_flow_1_url.format(NODE_ID=node_id,TABLE_ID=forbidden_table_id)
    table_x_flow_1_json = flow_1_json.replace("TABLE_ID",str(forbidden_table_id))

    r = requests.put(table_flow_1_url,data=flow_1_json,headers=headers)
    assert(r.status_code==403)

    r = requests.get(table_flow_1_url,headers=headers)
    assert(r.status_code==403)
















