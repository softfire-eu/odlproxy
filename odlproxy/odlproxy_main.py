import os

import odl_proxy_api
from utils import get_logger

__author__ = 'Massimiliano Romano'

logger = get_logger(__name__)


def set_env():
    # SET ENV VARS

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


def odlproxy_main():
    #logger.info("starting up")
    set_env()
    odl_proxy_api.start()


if __name__ == '__main__':
    odlproxy_main()


