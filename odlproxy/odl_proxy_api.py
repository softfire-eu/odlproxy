import os

import bottle
import re

import requests

from odlproxy import OpenstackClient, openstack2_api
from odlproxy.odl import ODLDataRetriever
from odlproxy.utils import get_logger
from bottle import post, get, delete, put
from bottle import request, response, redirect

import json

__author__ = 'Massimiliano Romano'

logger = get_logger(__name__)

_experiments = dict()
_auth_secret = "90d82936f887a871df8cc82c1518a43e"
_api_endpoint = "http://127.0.0.1:8001/"

_mapTable = dict()
_mapTable[0] = { "table": [2,3,4], "assigned": False}
_mapTable[1] = { "table": [5,6,7], "assigned": False}
_mapTable[2] = { "table": [8,9,10], "assigned": False}
_mapTable[3] = { "table": [11,12,13], "assigned": False}
_mapTable[4] = { "table": [14,15,16], "assigned": False}

print(_mapTable)

@get('/SDNproxy/<token>')
def proxy_details_handler(token):
    """Handles experiment details"""

    if check_auth_header(request.headers):
        if token in _experiments:
            response.headers['Content-Type'] = 'application/json'
            response.headers['Cache-Control'] = 'no-cache'
            return json.dumps(_experiments[token])
        else:
            raise bottle.HTTPError(404)
    else:
        raise bottle.HTTPError(403, "Auth-Secret error!")


def get_ports(tenant_id):
    auth_url = os.environ['OS_AUTH_URL']
    user = os.environ['OS_USERNAME']
    password = os.environ['OS_PASSWORD']
    project_id = tenant_id

    conn = openstack2_api.create_connection(auth_url, None, project_id, user, password)

    ports = openstack2_api.list_ports(conn, project_id)


def get_user_flowtables(tenant_id,experiment_id):

    for key, value in _mapTable.iteritems():
        if value["assigned"] == False:
           value["assigned"] = True
           return value["table"]
        else:
            return "ODL Proxy - Max concurrent Experiments reached - Max 5"
    #odl = ODLDataRetriever()

    # Filtrare per le tabelle occupate per tenant

    #return odl.getTable()

    #flows_of_port = []
    #for port in ports:
        # print "port['id'] %d" % port.id
        #flows_of_port = odl.getFlows(port.id)
        # print "flows_of_port %d" % flows_of_port


@post('/SDNproxySetup')
def proxy_creation_handler():
    """Handles experiment/proxy creation
      request:
      {
        "experiment_id": "a5cfaf1e81f35fde41bef54e35772f2b",
        "tenant_id": "fed0b52c7e034d5785880613e78d4411"
      }
      response:
      {
        "endpoint_url": "http:/foo.bar",
        "user-flow-tables": [10,11,12,13,14,15]
      }
    """
    try:
        # parse input data
        try:
            data = request.json
            logger.debug("JSON: %s" % request.json)
        except Exception as e:
            logger.error(e)
            raise ValueError(e)

        if data is None:
            print("ODL Proxy - Cant read json request")
            raise ValueError

        experiment_id = data['experiment_id']
        tenant_id = data["tenant_id"]

        # check for existence
        if experiment_id in _experiments:
            response.status = 500
            return "ODL Proxy - Duplicate experiment!"

        #osClient = OpenstackClient()
        #ports = osClient.get_ports(tenant_id)

        _experiments[experiment_id] = {"tenant": tenant_id, "flow_tables": get_user_flowtables(tenant_id,experiment_id)}

        response.headers['Content-Type'] = 'application/json'
        response.headers['Cache-Control'] = 'no-cache'
        return json.dumps(
            {"user-flow-tables": _experiments[experiment_id]["flow_tables"], "endpoint_url": _api_endpoint})

    except Exception as e:
        logger.error(e)
        response.status = 500


@delete('/SDNproxy/<token>')
def delete_handler(token):
    """delete the mapping between experiment-token and tenant id
    :returns  200 but no body
    """
    if check_auth_header(request.headers):
        if _experiments.pop(token, None) is None:
            response.status = 404
            msg = "Experiment not found!"
        else:
            response.status = 200
            msg = "Experiment successfully deleted!"
        logger.debug(msg)
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({"msg": msg})

    else:
        raise bottle.HTTPError(403, "Auth-Secret error!")


def check_auth_header(headers):
    if "Auth-Secret" in headers.keys():
        auth_secret = headers.get("Auth-Secret")
        logger.debug("'Auth-Secret' header present! value: %s" % auth_secret)
        if auth_secret == _auth_secret:
            return True
    return False

@get('/restconf/<url:path>')
@put('/restconf/<url:path>')
def do_proxy_jsonrpc(url):

    #TODO for headears
    token = request.headers.get('API-Token')
    authorization = request.headers.get('Authorization')
    accept = request.headers.get('Accept')

    if not accept:
        accept = 'application/json'

    if not authorization:
        response.status = 400
        msg = "ODL Proxy - Bad Request! Header Authorization NOT FOUND"
        return json.dumps({"msg": msg})

    if not token:
        response.status = 400
        msg = "ODL Proxy - Bad Request! Header API-Token NOT FOUND"
        return json.dumps({"msg": msg})
    else:
        tables = _experiments[token]["flow_tables"]
        if not tables:
            response.status = 400
            msg = "ODL Proxy - Experiment not found!"
            return json.dumps({"msg": msg})

    regex = 'config/opendaylight-inventory:nodes/node/openflow:([0-9]*)/table/([0-9]*)/flow/([0-9]*)'
    title_search = re.search(regex, url, re.IGNORECASE)

    if title_search:
        nodeId = title_search.group(1)
        tableId = int(title_search.group(2))
        flowId = int(title_search.group(3))

        if tableId in tables:
            #Ok redirect de request to ODL
            #redirect("http://10.200.4.8:" + "8181/" + url)

            headers = {'Accept' : accept,
                       "Authorization": authorization
                       } #request.headers

            urlODL = "http://10.200.4.8:" + "8181/restconf/" + url

            if request.method == "GET":
                resp = requests.get(urlODL, headers=headers)
            elif request.method == "PUT":
                try:
                    dataj = json.loads(request.body.read().decode("utf-8"))
                except Exception as e:
                    response.status = 400
                    msg = "ODL Proxy - Bad Request! " + e
                    return json.dumps({"msg": msg})

                print "code:" + str(dataj)
                resp = requests.get(urlODL, data=dataj, headers=headers)

            print "code:" + str(resp.status_code)
            print "******************"
            print "headers:" + str(resp.headers)
            print "******************"
            print "content:" + str(resp.text)
            print "******************"
            print "content:" + str(resp.content)
        else:
            response.status = 400
            msg = "ODL Proxy - Bad Request! Don`t Modify Table " + tableId
            return json.dumps({"msg": msg})

    else:
        response.status = 404
        msg = "ODL Proxy - Resource Not Found!"
        return json.dumps({"msg": msg})


def start():
    global _mySdnFilter
    #_experiments["test01"] = {"tenant": "123invalid456", "flow_tables": 300}
    logger.info("starting up")
    #_mySdnFilter = WhitelistFilter(["help", "list.methods"])
    bottle.run(host='0.0.0.0', port=8001, reloader=True)