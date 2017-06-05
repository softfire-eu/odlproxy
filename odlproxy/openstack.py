from neutronclient.common.exceptions import ConnectionFailed

__author__ = 'Massimiliano Romano'

import os_client_config
import os
from neutronclient.v2_0 import client

class OpenstackClient():

    def get_credentials(self):
        d = {}
        d['username'] = os.environ['OS_USERNAME']
        d['password'] = os.environ['OS_PASSWORD']
        d['auth_url'] = os.environ['OS_AUTH_URL']
        #d['tenant_name'] = os.environ['OS_TENANT_NAME']
        d['project_id'] = os.environ['OS_PROJECT_ID']
        #d['tenant_id'] = os.environ['OS_TENANT_ID']
        return d

    def get_networks(self):
        credentials = self.get_credentials()
        neutron = client.Client(**credentials)
        netw = neutron.list_networks()

        self.print_values(netw, 'networks')

    def get_ports(self,tenant_id):
        credentials = self.get_credentials()
        neutron = client.Client(**credentials)

        get_ports_params = {}
        get_ports_params['tenant_id'] = os.environ['OS_PROJECT_ID']

        try:
            ports = neutron.list_ports(**get_ports_params)
        except ConnectionFailed as e:
            print e
            return

        ports = ports['ports']

        filtered_ports = []
        for port in ports:
            fp = {}
            fp['port_id'] = port['id']
            fp['port_id_11'] = port['id'][0:11]
            fp['mac'] = port['mac_address']

            filtered_ports.append(fp)

        #self.print_values(ports, 'ports')

        return filtered_ports


    def get_client(self):
        neutron = os_client_config.make_client(
            'neutron',
            auth_url='https://example.com',
            username='example-openstack-user',
            password='example-password',
            project_name='example-project-name',
            region_name='example-region-name')


    def print_values(self, val, type):
        if type == 'ports':
            val_list = val['ports']
        if type == 'networks':
            val_list = val['networks']
        if type == 'routers':
            val_list = val['routers']
        for p in val_list:
            for k, v in p.items():
                print("%s : %s" % (k, v))
            print('\n')


    def print_values_server(self,val, server_id, type):
        if type == 'ports':
            val_list = val['ports']

        if type == 'networks':
            val_list = val['networks']
        for p in val_list:
            bool = False
            for k, v in p.items():
                if k == 'device_id' and v == server_id:
                    bool = True
            if bool:
                for k, v in p.items():
                    print("%s : %s" % (k, v))
                print('\n')



    '''
    def test_is_string(self):
        s = odlproxy.odlproxy_main()
        self.assertTrue(isinstance(s, basestring))
    '''


