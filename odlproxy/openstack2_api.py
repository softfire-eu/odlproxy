import os
from openstack import connection
from openstack import profile
from utils import get_logger
#from novaclient.client import Client

logger = get_logger(__name__)

def create_connection(auth_url, region, project_name, username, password):
    logger.debug("ODL PROXY - create_connection to Openstack")
    prof = profile.Profile()
    #prof.set_region(profile.Profile.ALL, region)

    return connection.Connection(

        auth_url=auth_url,
        project_id=project_name,
        username=username,
        password=password

        # Do not include project and domain together
        # Username or user_id must be present
        # To use v3 you must use user_id
    )

def list_ports(conn,tenant_id):
    logger.debug("ODL PROXY - list_ports from Openstack")

    #get_ports_params = {}
    #get_ports_params['project_id'] = os.environ['OS_PROJECT_ID']
    #for port in conn.network.ports(**get_ports_params)

    #for port in conn.network.ports(project_id= tenant_id):
    #print(port)

    #Port filtered to project_id
    return conn.network.ports(project_id= tenant_id)



def list_networks(conn):
    logger.debug("ODL PROXY - list_networks from Openstack")

    for network in conn.network.networks():
        print(network)

# def get_VM (server_id,tenant_id):
#     credentials = get_nova_credentials_v2(tenant_id)
#     nova_client = Client(**credentials)
#
#     server = nova_client.servers.get(server_id)
#     print_server(server)
#
#     print(nova_client.servers.list())
#
#     return server
#
# def get_nova_credentials_v2(tenant_id):
#     d = {}
#     d['version'] = '2.0'
#     d['username'] = os.environ['OS_USERNAME']
#     d['password'] = os.environ['OS_PASSWORD']
#     d['auth_url'] = os.environ['OS_AUTH_URL']
#     d['project_id'] = tenant_id
#
#     #d['project_id'] = 'demo'
#     return d
#
# def print_server(server):
#     print("-"*35)
#     print("server id: %s" % server.id)
#     print("server name: %s" % server.name)
#     print("server image: %s" % server.image)
#     print("server flavor: %s" % server.flavor)
#     print("server key name: %s" % server.key_name)
#     print("user_id: %s" % server.user_id)
#     print("-"*35)