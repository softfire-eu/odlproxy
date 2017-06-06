import os

from odlproxy import odl_proxy_api
from odlproxy.odl import ODLDataRetriever
from odlproxy.utils import get_logger
import openstack2_api

__author__ = 'Massimiliano Romano'

from openstackOLD import  OpenstackClient
#from http_proxy import ProxyFilter


logger = get_logger(__name__)


def set_env():
    # SET ENV VARS
    '''
    os.environ['OS_USERNAME'] = "admin"
    os.environ['OS_PASSWORD'] = "admin"
    os.environ['OS_AUTH_URL'] = "http://10.200.4.64:5000/v2.0/"
    os.environ['OS_TENANT_NAME'] = "demo"


    os.environ['OS_USERNAME'] = "openbaton"
    os.environ['OS_PASSWORD'] = "openbaton"
    os.environ['OS_AUTH_URL'] = "http://172.16.21.25:5000/v2.0/"
    #os.environ['OS_TENANT_ID'] = "101732d86697496385264a795dc282ef"
    os.environ['OS_PROJECT_ID'] = "101732d86697496385264a795dc282ef"
    '''

    os.environ['OS_USERNAME'] = "admin"
    os.environ['OS_USERNAME_ID'] = "ca81dc60f6c84f39b6728ca29f053e5f"

    os.environ['OS_PASSWORD'] = "admin"
    #os.environ['DOMAIN_ID'] = "default"
    os.environ['OS_AUTH_URL'] = "http://10.200.4.8/identity/v2.0/"
    os.environ['OS_TENANT_ID'] = "11d54bf6419c4ec48fd0b267b11108d3"
    os.environ['OS_PROJECT_ID'] = "11d54bf6419c4ec48fd0b267b11108d3"

    # ODL ENV
    os.environ['ODL_HOST'] = "10.200.4.8"
    os.environ['ODL_PORT'] = "8181"
    os.environ['ODL_USER'] = "admin"
    os.environ['ODL_PASS'] = "admin"

    # ODL USED TABLES
    # 0 1 2 3 4 10



def odlproxy_main():
    logger.info("starting up")
    #print 'odlproxy started...'
    #bottle.run(host='0.0.0.0', port=8001, reloader=True)

    set_env()



    odl_proxy_api.start()


    '''
    print 'odlproxy started...'
    address='localhost'
    port=8070
    server_name='CherryProxy/0.12'
    debug=False
    log_level=20
    options=None
    parent_proxy=None

    #proxy = ProxyFilter("blabla")
    proxy = ProxyFilter(address,port,server_name,debug,log_level,options,parent_proxy)
    '''


    '''
    os_client = OpenstackClient()
    tenant_id="xxxx"
    #os_client.get_networks()
    tenant_ports = os_client.get_ports(tenant_id)

    print "retrieved %d ports" % len(tenant_ports)

    first_port=tenant_ports[0]


    odl_data_retriever = ODLDataRetriever()
    odl_data_retriever.getFlows(first_port['port_id_11'])

    '''
    return "ciaone"



if __name__ == '__main__':
    odlproxy_main()


