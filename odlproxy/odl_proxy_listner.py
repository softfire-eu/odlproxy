import pika
import json
import os
import sys
import ConfigParser
import odl_proxy_api
from utils import get_logger

logger = get_logger(__name__)

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

    oslo_message = json.loads(body)
    print oslo_message
    event = oslo_message['event_type']
    tenant_id = oslo_message['_context_tenant']
    if event == "compute.instance.create.end":
        #create the flow
        server_id_create = oslo_message['payload']['instance_id']
        odl_proxy_api.createFlowFromVM(server_id_create,tenant_id)
        print "server_id_create : " +  server_id_create
        print "create"
    elif event == "compute.instance.delete.end":
        #delete the flow
        # TODO prendere il server ID corretto
        server_id_delete = oslo_message['payload']['instance_id']
        odl_proxy_api.deleteFlowFromVM(server_id_delete,tenant_id)
        print "server_id_delete : " + server_id_delete
        print "delete"


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

def odlListener_main():
    print odl_proxy_api
    print sys
    print ConfigParser
    print "odlListener_main"

if __name__ == '__main__':
    print __name__
    odlListener_main()
else:
    print __name__