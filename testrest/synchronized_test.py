#!/bin/python
import httplib
import json
import logging
import threading
import urlparse
import requests

__author__ = 'Claudio Navisse'

#HOSTNAME_PORT="10.200.4.8:8001"
HOSTNAME_PORT="localhost:8001"
EXPERIMENT_ID="a5cfaf1e81f35fde41bef54e35772f2b"
EXPERIMENT_ID2="a5cfaf1e81f35fde41bef54e35772f2z"
#TENANT_ID="fed0b52c7e034d5785880613e78d4411"
TENANT_ID="11d54bf6419c4ec48fd0b267b11108d3"

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

headers = {'Auth-Secret': '90d82936f887a871df8cc82c1518a43e', 'Content-Type': 'application/json', 'Accept':'application/json'}


post_token_data = data.format(EXPERIMENT_ID,TENANT_ID)

def counter():
    #for i in range(0,2):
    response = request()
    #assert (response.status_code == 200)

def counter2():
    # for i in range(0,2):
    response = request2()
    #assert (response.status_code == 500)

def request():
    return requests.post(url, data=post_token_data,headers=headers)

def request2():
    post_token_data2 = data.format(EXPERIMENT_ID2, TENANT_ID)
    return requests.post(url, data=post_token_data2,headers=headers)

thread1 = threading.Thread(target=counter)
thread2 = threading.Thread(target=counter2)

thread1.start()
thread2.start()

thread1.join()
thread2.join()










