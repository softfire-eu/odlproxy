import os

import bottle

from odlproxy import OpenstackClient, openstack2_api
from odlproxy.odl import ODLDataRetriever
from odlproxy.utils import get_logger
from bottle import post, get, delete, route
from bottle import request, response

import json

__author__ = 'Massimiliano Romano'

logger = get_logger(__name__)

_experiments = dict()
_auth_secret = "90d82936f887a871df8cc82c1518a43e"
_api_endpoint = "http://127.0.0.1:8001/"


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
            print("Cant read json request")
            raise ValueError

        experiment_id = data['experiment_id']
        tenant_id = data["tenant_id"]

        # check for existence
        if experiment_id in _experiments:
            response.status = 500
            return "Duplicate experiment!"


        #osClient = OpenstackClient()
        #ports = osClient.get_ports(tenant_id)

        auth_url = os.environ['OS_AUTH_URL']
        user = os.environ['OS_USERNAME']
        password = os.environ['OS_PASSWORD']
        project_id = os.environ['OS_PROJECT_ID']

        conn = openstack2_api.create_connection(auth_url, None, project_id, user, password)

        openstack2_api.list_ports(conn, project_id)

        odl = ODLDataRetriever()

        flows_of_port = []
        for port in ports:
            flows_of_port = odl.getFlows(port['port_id'])
            # print "flows_of_port %d" % flows_of_port

        #_experiments[experiment_id] = {"tenant": tenant_id, "flow_tables": get_user_flowtables(experiment_id)}

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


def start():
    global _mySdnFilter
    #_experiments["test01"] = {"tenant": "123invalid456", "flow_tables": 300}
    logger.info("starting up")
    #_mySdnFilter = WhitelistFilter(["help", "list.methods"])
    bottle.run(host='0.0.0.0', port=8001, reloader=True)