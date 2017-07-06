import os
import odl_proxy_api
import sys
import ConfigParser
import odl_proxy_listner
from concurrent.futures import ThreadPoolExecutor
import utils

__author__ = 'Massimiliano Romano'

logger = utils.get_logger(__name__)
_configfile_path="/etc/odlproxy/odlproxy.ini"

def print_usage():
    print("python odlproxy_main.py --configfile /etc/odlproxy/odlproxy.ini")
    print("     or")
    print("python odlproxy_main.py")
    print("     application search for /etc/odlproxy/odlproxy.ini as default")

def parse_args_and_set_env():
    args = sys.argv
    #args[0] is odlproxy_main.py
    if len(args) == 2:
        print_usage()
        return

    if len(args) == 3:

        if args[1] != "--configfile":
            print_usage()
            return

        configfile_path=args[2]

    logger.info("Using configfile : " + _configfile_path )

    config = ConfigParser.ConfigParser()
    config.read(_configfile_path)

    os.environ['OS_USERNAME'] =     config.get("OPENSTACK", "OS_USERNAME")
    os.environ['OS_USERNAME_ID'] =  config.get("OPENSTACK", "OS_USERNAME_ID")
    os.environ['OS_PASSWORD'] =     config.get("OPENSTACK", "OS_PASSWORD")
    os.environ['OS_AUTH_URL'] =     config.get("OPENSTACK", "OS_AUTH_URL")
    os.environ['OS_TENANT_ID'] =    config.get("OPENSTACK", "OS_TENANT_ID")
    os.environ['OS_PROJECT_ID'] =   config.get("OPENSTACK", "OS_PROJECT_ID")

    os.environ['ODL_HOST'] = config.get("ODL", "ODL_HOST")
    os.environ['ODL_PORT'] = config.get("ODL", "ODL_PORT")
    os.environ['ODL_USER'] = config.get("ODL", "ODL_USER")
    os.environ['ODL_PASS'] = config.get("ODL", "ODL_PASS")

    os.environ['ODLPROXY_PUBLIC_IP'] = config.get("ODLPROXY", "PUBLIC_IP")
    os.environ['ODLPROXY_AUTH_SECRET'] = config.get("ODLPROXY", "AUTH_SECRET")

    os.environ['RABBIT_HOST'] = config.get("RABBIT", "RABBIT_HOST")
    os.environ['RABBIT_PORT'] = config.get("RABBIT", "RABBIT_PORT")
    os.environ['RABBIT_USER'] = config.get("RABBIT", "RABBIT_USER")
    os.environ['RABBIT_PASS'] = config.get("RABBIT", "RABBIT_PASS")

    # SET ENV VARS
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
    '''

def odlproxy_main():
    logger.info("Starting ODL Proxy")
    parse_args_and_set_env()
    #    odl_proxy_api.start()
    pool = ThreadPoolExecutor(3)
    pool.submit(odl_proxy_api.start)
    pool.submit(odl_proxy_listner.listenerNotifications())
    #print( 'primo' + str(future.done()))
    #sleep(5)
    #print('secondo' + str(future.done()))
    #print(future.result())

if __name__ == '__main__':
    odlproxy_main()


