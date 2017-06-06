import os

from openstack import connection
from openstack import profile
from openstack import utils

def get_ports(conn):
    return None

def create_connection(auth_url, region, project_name, username, password):
    prof = profile.Profile()
    #prof.set_region(profile.Profile.ALL, region)

    return connection.Connection(

        auth_url=auth_url,
        project_id=project_name,
        username=username,
        password=password

    )


def list_ports(conn,tenant_id):
    print("List Ports:")

    #get_ports_params = {}
    #get_ports_params['project_id'] = os.environ['OS_PROJECT_ID']
    #for port in conn.network.ports(**get_ports_params)

    for port in conn.network.ports(project_id= tenant_id):
        print(port)

def list_networks(conn):
    print("List Networks:")

    for network in conn.network.networks():
        print(network)