from odlproxy import odl_proxy_api
from odlproxy.odl import ODLDataRetriever
from odlproxy.utils import get_logger

__author__ = 'Massimiliano Romano'

from openstack import  OpenstackClient
#from http_proxy import ProxyFilter


logger = get_logger(__name__)


def odlproxy_main():
    logger.info("starting up")
    #print 'odlproxy started...'
    #bottle.run(host='0.0.0.0', port=8001, reloader=True)

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


