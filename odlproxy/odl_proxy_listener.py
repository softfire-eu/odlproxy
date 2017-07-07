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
        message = dict()
        logger.info("Message arrived Payload %s", oslo_message)

        #oslo_message =  {u'oslo.message': u'{"_context_domain": null, "_context_roles": ["_member_"], "_context_quota_class": null, "event_type": "compute.instance.delete.end", "_context_request_id": "req-4b6783f0-2e2a-46bc-998c-d21f3c119164", "_context_service_catalog": [{"endpoints": [{"adminURL": "http://172.16.21.103:8776/v2/bd40adcf1c5940ad8a4d8f471ac049f3", "region": "regionOne", "internalURL": "http://172.16.21.103:8776/v2/bd40adcf1c5940ad8a4d8f471ac049f3", "publicURL": "http://172.16.21.31:8776/v2/bd40adcf1c5940ad8a4d8f471ac049f3"}], "type": "volumev2", "name": "cinderv2"}, {"endpoints": [{"adminURL": "http://172.16.21.103:8776/v1/bd40adcf1c5940ad8a4d8f471ac049f3", "region": "regionOne", "internalURL": "http://172.16.21.103:8776/v1/bd40adcf1c5940ad8a4d8f471ac049f3", "publicURL": "http://172.16.21.31:8776/v1/bd40adcf1c5940ad8a4d8f471ac049f3"}], "type": "volume", "name": "cinder"}], "timestamp": "2017-07-07 08:27:50.301284", "_context_user": "002dc8c847524a3687f26d8f24bf2b04", "_unique_id": "506aa70a8cda41cabcec9cf22b434e93", "_context_resource_uuid": null, "_context_instance_lock_checked": false, "_context_is_admin_project": true, "_context_user_id": "002dc8c847524a3687f26d8f24bf2b04", "payload": {"state_description": "", "availability_zone": "nova", "terminated_at": "2017-07-07T08:27:49.603815", "ephemeral_gb": 0, "instance_type_id": 1, "deleted_at": "2017-07-07T08:28:17.000000", "reservation_id": "r-04qx9ybd", "instance_id": "d2e4fa5d-e93a-473a-ab43-af56f19d2af2", "display_name": "test1", "hostname": "test1", "state": "deleted", "progress": "", "launched_at": "2017-07-06T16:58:34.000000", "metadata": {}, "node": "overcloud-compute-1.localdomain", "ramdisk_id": "", "access_ip_v6": null, "disk_gb": 1, "access_ip_v4": null, "kernel_id": "", "host": "overcloud-compute-1.localdomain", "user_id": "002dc8c847524a3687f26d8f24bf2b04", "image_ref_url": "http://172.16.21.171:9292/images/bb397756-0a31-410a-97de-b9f9a92d902c", "cell_name": "", "root_gb": 1, "tenant_id": "bd40adcf1c5940ad8a4d8f471ac049f3", "created_at": "2017-07-06 16:58:55+00:00", "memory_mb": 512, "instance_type": "m1.tiny", "vcpus": 1, "image_meta": {"min_disk": "1", "container_format": "bare", "min_ram": "0", "disk_format": "qcow2", "base_image_ref": "bb397756-0a31-410a-97de-b9f9a92d902c"}, "architecture": null, "os_type": null, "instance_flavor_id": "2d84fe56-4d6a-4a71-be7e-13a1d5f47000"}, "_context_project_name": "test1", "_context_read_deleted": "no", "_context_user_identity": "002dc8c847524a3687f26d8f24bf2b04 bd40adcf1c5940ad8a4d8f471ac049f3 - - -", "_context_auth_token": "6d6c7ecfe5004498a6b521c77af74f9c", "_context_show_deleted": false, "_context_tenant": "bd40adcf1c5940ad8a4d8f471ac049f3", "priority": "INFO", "_context_read_only": false, "_context_is_admin": false, "_context_project_id": "bd40adcf1c5940ad8a4d8f471ac049f3", "_context_project_domain": null, "_context_timestamp": "2017-07-07T08:28:14.438479", "_context_user_domain": null, "_context_user_name": "admin", "publisher_id": "compute.overcloud-compute-1.localdomain", "message_id": "ab961304-e81e-46c6-89c8-57b60355deac", "_context_remote_address": "172.16.21.108"}', u'oslo.version': u'2.0'}
        #logger.info("payload %s", oslo_message)

        if 'oslo.message' in oslo_message:
            message = json.loads(oslo_message['oslo.message'])
        else:
            message = oslo_message

        logger.info("Message used Payload %s", message)

        event = message['event_type']
        logger.info("event %s", event)

        tenant_id = message['_context_tenant']
        logger.info("tenant_id %s", tenant_id)

        if event == "compute.instance.create.end":
            #create the flow
            server_id_create = message['payload']['instance_id']
            odl_proxy_api.createFlowFromVM(server_id_create,tenant_id)
            logger.info("server_id_create : " +  server_id_create)

        elif event == "compute.instance.delete.end":
            #delete the flow
            server_id_delete = message['payload']['instance_id']
            odl_proxy_api.deleteFlowFromVM(server_id_delete,tenant_id)
            logger.info("server_id_delete : " + server_id_delete)

    except Exception as e:
        msg = "ODL Proxy " + str(e)
        logger.info(msg)
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



