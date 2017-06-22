import os


import pika
import odl_proxy_api
import sys
import ConfigParser
from concurrent.futures import ThreadPoolExecutor
from time import sleep
from utils import get_logger

__author__ = 'Massimiliano Romano'

logger = get_logger(__name__)

def print_usage():
    print("python odlproxy_main.py --configfile /etc/odlproxy/odlproxy.ini")
    print("     or")
    print("python odlproxy_main.py")
    print("     application search for /etc/odlproxy/odlproxy.ini as default")

def parse_args_and_set_env():
    args = sys.argv
    #args[0] is odlproxy_main.py

    configfile_path="/etc/odlproxy/odlproxy.ini"

    if len(args) == 2:
        print_usage()
        return

    if len(args) == 3:

        if args[1] != "--configfile":
            print_usage()
            return

        configfile_path=args[2]

    print("using configfile "+configfile_path)

    config = ConfigParser.ConfigParser()
    config.read(configfile_path)
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

def nova_callback(ch, method, properties, body):
    """
    Method used by method nova_amq() to filter messages by type of message.

    :param ch: refers to the head of the protocol
    :param method: refers to the method used in callback
    :param properties: refers to the proprieties of the message
    :param body: refers to the message transmitted
    """

    print '---------------------------------------------------------'
    print 'called callback...'
    print "routing key=%s" % method.routing_key
    print "exchange=%s" % method.exchange

    print body
    #payload = json.loads(body)

def listenerNotifications():
    logger.info("create listener to rabbit")

    '''
    #transport_url = 'rabbit://stackrabbit:stackqueue@10.200.4.8:5672/'

    #control_exchange = 'nova'

    #    transport = oslo_messaging.get_notification_transport(cfg.CONF,transport_url )
    #    targets = [
        oslo_messaging.Target(topic='nova')
        #oslo_messaging.Target(topic='notifications_bis')
    ]
    endpoints = [
        olsoMessagingHandler.NotificationEndpoint(),
        olsoMessagingHandler.ErrorEndpoint()
    ]

    server = oslo_messaging.get_notification_listener(transport, targets,
                                                      endpoints ,allow_requeue=True, executor='eventlet')
    server.start()
    server.wait()
    '''

    connection = pika.BlockingConnection(pika.ConnectionParameters(host=os.environ['RABBIT_HOST'],
                                                                   port=int(os.environ['RABBIT_PORT']),
                                                                   credentials=pika.PlainCredentials(username=os.environ['RABBIT_USER'],
                                                                                                     password=os.environ['RABBIT_PASS'])
                                                                   ))

    channel = connection.channel()

    result = channel.queue_declare(exclusive=True)
    queue_name = result.method.queue

    print "queue_name: %s" % queue_name

    # channel.exchange_declare(exchange='heat', type='topic')
    # using routing_key
    # channel.queue_bind(exchange='openstack', queue=queue_name, routing_key='notifications.#')
    # channel.queue_bind(exchange='openstack', queue=queue_name, routing_key='notifications.#')
    # get all messages on heat
    # channel.queue_bind(exchange='heat', queue=queue_name, routing_key='#')

    channel.queue_bind(exchange='nova', queue=queue_name, routing_key='notifications.#')

    # channel.queue_bind(exchange='ceilometer', queue=queue_name, routing_key='#')

    channel.basic_consume(nova_callback, queue=queue_name, no_ack=True)
    channel.start_consuming()
    print 'consuming started'


def odlproxy_main():
    #logger.info("starting up")
    parse_args_and_set_env()
    #    odl_proxy_api.start()

    pool = ThreadPoolExecutor(3)
    pool.submit(odl_proxy_api.start)
    pool.submit(listenerNotifications())
    #print( 'primo' + str(future.done()))
    #sleep(5)
    #print('secondo' + str(future.done()))
    #print(future.result())





if __name__ == '__main__':
    odlproxy_main()



