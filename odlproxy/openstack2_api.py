from openstack import connection
from openstack import profile
from utils import get_logger

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
    print("List Ports:")

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