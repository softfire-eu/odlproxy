import pika
import json
import os
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
    try:
        logger.info("--------------------------------------------------------- ")
        logger.info("called callback... ")
        logger.info("routing key=%s" % method.routing_key)
        logger.info("exchange=%s" % method.exchange)

        oslo_message = json.loads(body)

        if oslo_message['oslo.message']:
            oslo_message = oslo_message['oslo.message']

        logger.info("payload %s", oslo_message)

        event = oslo_message['event_type']
        logger.info("event %s", event)

        tenant_id = oslo_message['_context_tenant']
        logger.info("tenant_id %s", tenant_id)

        if event == "compute.instance.create.end":
            #create the flow
            logger.info("event_type : " +event )
            server_id_create = oslo_message['payload']['instance_id']
            odl_proxy_api.createFlowFromVM(server_id_create,tenant_id)
            logger.info("server_id_create : " +  server_id_create)
        elif event == "compute.instance.delete.end":
            #delete the flow
            logger.info("event_type : " + event)
            server_id_delete = oslo_message['payload']['instance_id']
            odl_proxy_api.deleteFlowFromVM(server_id_delete,tenant_id)
            logger.info("server_id_delete : " + server_id_delete)

    except Exception as e:
        msg = "ODL Proxy " + str(e)
        return msg

def listenerNotifications():
    logger.info("Create listener to rabbit")

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

    channel.queue_bind(exchange='nova', queue=queue_name, routing_key='notifications.#')

    logger.info("queue_name: " + queue_name)
    logger.info("exchange : nova")
    logger.info("routing_key : notifications.#")

    channel.basic_consume(nova_callback, queue=queue_name, no_ack=True)
    channel.start_consuming()
    logger.info("consuming started")



