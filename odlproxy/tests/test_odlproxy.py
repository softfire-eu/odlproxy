from odlproxy import OpenstackClient
from odlproxy.odl import ODLDataRetriever

__author__ = 'Massimiliano Romano'

from unittest import TestCase
import os


class TestODLProxy(TestCase):

    #def __init__(self):
    #    self.set_env()

    def set_env(self):
        #SET ENV VARS
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
        os.environ['OS_PASSWORD'] = "admin"
        os.environ['OS_AUTH_URL'] = "http://10.200.4.8:5000/v2.0/"
        #os.environ['OS_TENANT_ID'] = "demo"
        os.environ['OS_PROJECT_ID'] = "50a7599c4e9148debaa114d4d72fc560"

        #ODL ENV
        os.environ['ODL_HOST'] = "10.200.4.8"
        os.environ['ODL_PORT'] = "8181"
        os.environ['ODL_USER'] = "admin"
        os.environ['ODL_PASS'] = "admin"

        #ODL USED TABLES
        #0 1 2 3 4 10

    def test_port(self) :
        self.set_env()

        osClient = OpenstackClient()
        ports = osClient.get_ports(os.environ['OS_PROJECT_ID'])
        odl = ODLDataRetriever()
        flows_of_port = []
        for port in ports:
            flows_of_port = odl.getFlows(port['port_id'])
            #print "flows_of_port %d" % flows_of_port


    def t_est_os_odl(self):
        osClient = os.OpenstackClient()
        osClient.get_ports()
        odl = ODLDataRetriever()
        odl.getFlows()

    def t_est_is_string(self):
        s = odlproxy.odlproxy_main()


        self.assertTrue(isinstance(s, basestring))