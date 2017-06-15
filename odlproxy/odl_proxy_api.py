import httplib
import os
import bottle
import re
import logging
import requests
import openstack2_api
import odl
from utils import get_logger
from bottle import post, get, delete, put
from bottle import request, response
import json

__author__ = 'Massimiliano Romano'

logger = get_logger(__name__)

_experiments = dict()
_auth_secret = "90d82936f887a871df8cc82c1518a43e"
#_api_endpoint = "http://localhost:8001/"

_authorization = "Basic YWRtaW46YWRtaW4="

#ENABLE HTTP LOGGING
httplib.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
req_log = logging.getLogger('requests.packages.urllib3')
req_log.setLevel(logging.DEBUG)
req_log.propagate = True

_mapTable = dict()
_mapTable[0] = { "table": [2,3,4]   , "assigned": False, "experiment_id" :""}
_mapTable[1] = { "table": [5,6,7]   , "assigned": False, "experiment_id" :""}
_mapTable[2] = { "table": [8,9,10  ], "assigned": False, "experiment_id" :""}
_mapTable[3] = { "table": [11,12,13], "assigned": False, "experiment_id" :""}
_mapTable[4] = { "table": [14,15,16], "assigned": False, "experiment_id" :""}



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
    logger.debug("ODL PROXY - get_ports for tenant :" + tenant_id)
    auth_url = os.environ['OS_AUTH_URL']
    user = os.environ['OS_USERNAME']
    password = os.environ['OS_PASSWORD']
    project_id = tenant_id

    conn = openstack2_api.create_connection(auth_url, None, project_id, user, password)

    #Trasform object Generetor to List
    return list(openstack2_api.list_ports(conn, project_id))


def get_user_flowtables(tenant_id,experiment_id):
    logger.debug("ODL PROXY - get_user_flowtables for tenant :" + tenant_id + "and experiment_id:" + experiment_id)
    for key, value in _mapTable.iteritems():
        if value["assigned"] == False:
           value["assigned"] = True
           value["experiment_id"] = experiment_id
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
    logger.debug("ODL PROXY - /SDNproxySetup")

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

        #Edit the flow on table 0 to first table on range
        nodes = odl.getAllNodes()
        ports = get_ports(tenant_id)

        # Get flow on table 0
        urlODL = "http://" + os.environ['ODL_HOST'] + ":" + os.environ['ODL_PORT'] + "/restconf/config/opendaylight-inventory:nodes/node/{NODE_ID}/table/0"
        tableExperiment = get_user_flowtables(tenant_id, experiment_id)

        for node in nodes:
            try:
                urlODL = urlODL.format(NODE_ID=node.id)
                headers = {
                           "Authorization": _authorization,
                           "Content-Type": "application/json"
                           }  # request.headers

                resp = requests.get(urlODL, headers=headers)
                dataj = resp.json()
                if 'flow-node-inventory:table' in dataj:
                    tables = dataj['flow-node-inventory:table']
                    for table in tables:
                        if 'flow' in table:
                            flows = table['flow']
                            for flow in flows:
                                if 'id' in flow:
                                    for port in ports:
                                        portId = port.id
                                        flowId = flow['id']
                                        if port.id in flow['id']:
                                            #Edit Flow
                                            flow1Put = flow
                                            flow2Put = flow

                                            # TODO # builDataFirstPut(flow1Put)
                                            # Prepare the first json request
                                            if 'match' in flow:
                                                match =  flow['match']
                                                if 'in-port' in match:
                                                    portOvs = match['in-port'].split(':')[2]

                                            tableDestination = getGoToTAble(flow,tableExperiment[0])

                                            #At the moment only in case table 17 rewrite the flow
                                            if tableDestination == 17:
                                                flow1Put = setGoToTAble(flow1Put,tableExperiment[0])
                                            else:
                                                raise Exception('ODL PROXY - IN FLOW ' + flow['id'] + ' GO TO TABLE NOT 17' )

                                            flow1Put['priority'] = flow['priority'] * 10
                                            flow1Put['id'] = tenant_id + '_' + str(tableExperiment[0]) + '_'+  portOvs
                                            flow1Put['flow-name'] = tenant_id + '_' + str(tableExperiment[0]) + '_' + portOvs

                                            urlODLput1 = urlODL + '/flow/' + flow1Put['flow-name']

                                            flow1TagWrapper = dict()
                                            flow1TagWrapper["flow-node-inventory:flow"] = [flow1Put]

                                            strdata = json.dumps(flow1TagWrapper, ensure_ascii=False)

                                            resp1 = requests.put(urlODLput1, data=strdata, headers=headers)

                                            #logger.debug("ODL PROXY - resp.status_code " + str(resp1.status_code))
                                            #logger.debug("ODL PROXY - resp.headers " + str(resp1.headers))
                                            #logger.debug("ODL PROXY - resp.text " + str(resp1.text))

                                            # TODO # builDataSecondPut(flow2Put)
                                            # Prepare the second json request
                                            flow2Put['priority'] = flow['priority'] * 10
                                            flow2Put['id'] = tenant_id + '_' +str(17) + '_' + portOvs
                                            flow2Put['flow-name'] = tenant_id + '_' + str(17) + '_' + portOvs
                                            flow2Put['table_id'] = tableExperiment[0]
                                            flow2Put = setGoToTAble(flow2Put, 17)

                                            if 'in-port' in flow2Put['match']:
                                                del flow2Put['match']['in-port']

                                            writeMetaData = getWriteMetaData(flow2Put)
                                            flow2Put = deleteWriteMetaData(flow2Put)
                                            flow2Put['match'] = writeMetaData

                                            urlODLnew = urlODL[:-1]
                                            urlODLput2 = urlODLnew + str(tableExperiment[0]) + '/flow/' + flow2Put['flow-name']

                                            flow2TagWrapper = dict()
                                            flow2TagWrapper["flow-node-inventory:flow"] = [flow2Put]

                                            strdata2 = json.dumps(flow2TagWrapper, ensure_ascii=False)
                                            resp2 = requests.put(urlODLput2, data=strdata2, headers=headers)

                                            #logger.debug("ODL PROXY - resp.status_code " + str(resp2.status_code))
                                            #logger.debug("ODL PROXY - resp.headers " + str(resp2.headers))
                                            #logger.debug("ODL PROXY - resp.text " + str(resp2.text))


            except Exception as e:
                response.status = 400
                msg = "ODL Proxy " + str(e)
                return json.dumps({"msg": msg})

        _experiments[experiment_id] = {"tenant": tenant_id, "flow_tables": tableExperiment}

        response.headers['Content-Type'] = 'application/json'
        response.headers['Cache-Control'] = 'no-cache'

        url = "http://{HOSTNAME}:8001/".format(HOSTNAME=os.environ["ODLPROXY_PUBLIC_IP"])

        return json.dumps(
            {"user-flow-tables": _experiments[experiment_id]["flow_tables"], "endpoint_url": url})

    except Exception as e:
        logger.error(e)
        response.status = 500

def getGoToTAble(flow,tables):
    if 'instructions' in flow:
        flow_node_instructions = flow['instructions']
        if 'instruction' in flow_node_instructions:
            instructions = flow_node_instructions['instruction']
            for instruction in instructions:
                if 'go-to-table' in instruction:
                    goToTable = instruction['go-to-table']
                    return goToTable['table_id']

    else:
        return -1

def setGoToTAble(flow,numberTable):
    if 'instructions' in flow:
        flow_node_instructions = flow['instructions']
        if 'instruction' in flow_node_instructions:
            instructions = flow_node_instructions['instruction']
            for instruction in instructions:
                if 'go-to-table' in instruction:
                    goToTable = instruction['go-to-table']
                    goToTable['table_id'] = numberTable
    return flow

def getWriteMetaData(flow):
    if 'instructions' in flow:
        flow_node_instructions = flow['instructions']
        if 'instruction' in flow_node_instructions:
            instructions = flow_node_instructions['instruction']
            for instruction in instructions:
                if 'write-metadata' in instruction:
                    del instruction['order']
                    inst = dict()
                    inst['metadata'] = instruction['write-metadata']
                    return inst

def deleteWriteMetaData(flow):
    if 'instructions' in flow:
        flow_node_instructions = flow['instructions']
        if 'instruction' in flow_node_instructions:
            instructions = flow_node_instructions['instruction']
            count = 0
            for instruction in instructions:
                if 'write-metadata' in instruction:
                    del flow['instructions']['instruction'][count]
                count = count + 1
    return flow

@delete('/SDNproxy/<token>')
def delete_handler(token):
    """delete the mapping between experiment-token and tenant id
    :returns  200 but no body
    """

    if check_auth_header(request.headers):

        # check the headears parameter
        accept = request.headers.get('Accept')
        if not accept:
            accept = 'application/json'

        #        x = _experiments[token]
        #        del _experiments[token]

        if _experiments.pop(token, None) is None:
            response.status = 404
            msg = "Experiment not found!"
        else:
            response.status = 200
            msg = "Experiment successfully deleted!"
            #Clear the table assigned to experimenter

            nodes = odl.getAllNodes()
            for key, value in _mapTable.iteritems():
                if value["experiment_id"] == token:
                    value["assigned"] = False
                    value["experiment_id"] = ""
                    tables = value["table"]
                    
                    break
            headers = {'Accept': accept,
                       "Authorization": _authorization
                       }
            for node in nodes:
                id = node.id
                for table in tables :
                    urlODL = "http://" + os.environ['ODL_HOST'] + ":" + os.environ['ODL_PORT'] + "/restconf/config/opendaylight-inventory:nodes/node/{NODE_ID}/table/{TABLE_ID}"
                    urlODL = urlODL.format(NODE_ID=node.id, TABLE_ID=table)
                    resp = requests.delete(urlODL, headers=headers)

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



# @delete('/restconf/<url:path>')
    # check the headears parameter

    # check the url

    # EXEC

# @put('/restconf/<url:path>')
    # check the headears parameter

    # check the url

    # EXEC

@get('/restconf/<url:path>')
@put('/restconf/<url:path>')
def do_proxy_jsonrpc(url):
    logger.debug("ODL PROXY - /restconf/" + url)

    #TODO for headears
    token = request.headers.get('API-Token')  #Token is experiment id
    accept = request.headers.get('Accept')

    # check the headears parameter
    if not accept:
        accept = 'application/json'

    """
    if not authorization:
        response.status = 400
        msg = "ODL Proxy - Bad Request! Header Authorization NOT FOUND"
        return json.dumps({"msg": msg})
    """

    if not token:
        response.status = 400
        msg = "ODL Proxy - Bad Request! Header API-Token NOT FOUND"
        return json.dumps({"msg": msg})
    else:
        if token in _experiments.keys():
            tables = _experiments[token]["flow_tables"]
        else:
            response.status = 400
            msg = "ODL Proxy - Experiment not found!"
            return json.dumps({"msg": msg})

    nodesregex = 'config/opendaylight-inventory:nodes'
    node_search = re.search(nodesregex, url, re.IGNORECASE)
    flowregex = 'config/opendaylight-inventory:nodes/node/openflow:([0-9]*)/table/([0-9]*)/flow/([0-9]*)'
    flow_search = re.search(flowregex, url, re.IGNORECASE)
    urlODL = "http://" + os.environ['ODL_HOST'] + ":" + os.environ['ODL_PORT'] + "/restconf/" + url

    if flow_search:
        nodeId = flow_search.group(1)
        tableId = int(flow_search.group(2))
        flowId = int(flow_search.group(3))

        if tableId in tables:
            headers = {'Accept' : accept,
                       "Authorization": _authorization,
                       "Content-Type": "application/json"
                       } #request.headers

            if request.method == "GET":
                resp = requests.get(urlODL, headers=headers)
            elif request.method == "PUT":
                try:

                    #dataj = json.loads(json.dumps(request.body.read().decode("utf-8"),ensure_ascii=True))

                    dataj = json.loads(request.body.read().decode("utf-8"))
                    if 'flow-node-inventory:flow' in dataj:
                        flow_node = dataj['flow-node-inventory:flow']
                        for f_n in flow_node:
                            if f_n['table_id'] in tables:
                                 if 'instructions' in f_n:
                                     flow_node_instructions = f_n['instructions']
                                     if 'instruction' in flow_node_instructions:
                                        instructions = flow_node_instructions['instruction']
                                        for instruction in instructions:
                                            if 'go-to-table' in instruction:
                                                goToTable = instruction['go-to-table']
                                                tableDestination = goToTable['table_id']
                                                if tableDestination in tables or tableDestination == 17 :
                                                    print("go-to-table in range of experiment")
                                                else:
                                                    response.status = 403
                                                    strTables = ','.join(str(e) for e in tables)
                                                    msg = "ODL Proxy - Forbidden can not modify table: " + str(
                                                        tableDestination) + " you can only access tables " + strTables
                                                    return json.dumps({"msg": msg})

                            else:
                                response.status = 403
                                strTables = ','.join(str(e) for e in tables)
                                msg = "ODL Proxy - Forbidden can not modify table: " + str(
                                    f_n['table_id']) + " you can only access tables " + strTables
                                return json.dumps({"msg": msg})
									
                except Exception as e:
                    response.status = 400
                    msg = "ODL Proxy - Bad Request! " + str(e)
                    return json.dumps({"msg": msg})

                    # print "code:" + str(dataj)
                dataj = json.dumps(dataj, ensure_ascii=False)
                resp = requests.put(urlODL, data=dataj, headers=headers)

            logger.debug("ODL PROXY - /restconf/" + url + " resp.status_code " +  str(resp.status_code))
            logger.debug("ODL PROXY - /restconf/" + url + " resp.headers " + str(resp.headers))
            logger.debug("ODL PROXY - /restconf/" + url + " resp.text " + str(resp.text))
            #logger.debug("ODL PROXY - /restconf/" + url + " resp.content " + str(resp.content))

            response.status = resp.status_code
            return resp.text

        else:
            response.status = 403
            strTables = ','.join(str(e) for e in tables)
            msg = "ODL Proxy - Forbidden can not modify table: " + str(tableId) + " you can only access tables " + strTables
            return json.dumps({"msg": msg})

    elif node_search:
        headers = {'Accept': accept,
                   "Authorization": _authorization
                   }  # request.headers
        resp = requests.get(urlODL, headers=headers)
        logger.debug("ODL PROXY - /restconf/" + url + " resp.status_code " + str(resp.status_code))
        logger.debug("ODL PROXY - /restconf/" + url + " resp.headers " + str(resp.headers))
        logger.debug("ODL PROXY - /restconf/" + url + " resp.text " + str(resp.text))

        response.status = resp.status_code
        return resp.json()

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