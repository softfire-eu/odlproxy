from openstack import connection
from openstack import profile

def create_connection(auth_url, region, project_name, username, password):
    prof = profile.Profile()
    #prof.set_region(profile.Profile.ALL, region)

    return connection.Connection(

        auth_url=auth_url,
        project_id=project_name,
        username=username,
        password=password

        # non inserire project e domain insieme
        # username o user_id devo essere presenti
        # per acceddere con v3 si deve usare user_id
    )


def list_ports(conn,tenant_id):
    print("List Ports:")

    #get_ports_params = {}
    #get_ports_params['project_id'] = os.environ['OS_PROJECT_ID']
    #for port in conn.network.ports(**get_ports_params)

    #for port in conn.network.ports(project_id= tenant_id):
    #print(port)

    #Port filtered to project_id
    return conn.network.ports(project_id= tenant_id)

def list_networks(conn):
    print("List Networks:")

    for network in conn.network.networks():
        print(network)