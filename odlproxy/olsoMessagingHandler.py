from oslo_config import cfg
import oslo_messaging

class NotificationEndpoint(object):
    print 'NotificationEndpoint'
    #_filter_rule = oslo_messaging.NotificationFilter(
    #_  publisher_id='^compute.*')
    def info(self, ctxt, publisher_id, event_type, payload, metadata):
         print payload

    def warn(self, ctxt, publisher_id, event_type, payload, metadata):
        print payload


class ErrorEndpoint(object):
    print 'ErrorEndpoint'
    #_filter_rule = oslo_messaging.NotificationFilter(
    #_   event_type='^instance\..*\.start$',
    #_   context={'ctxt_key': 'regexp'})

    def error(self, ctxt, publisher_id, event_type, payload, metadata):
        print payload




