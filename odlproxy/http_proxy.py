__author__ = 'Massimiliano Romano'

from cherryproxy import CherryProxy


class ProxyFilter(CherryProxy):
    def __init__(self, address='localhost', port=8070, server_name='CherryProxy/0.12', debug=False, log_level=20, options=None, parent_proxy=None):
        print "ProxyFilter initialized"


    #Called to analyse/filter/modify the request received from the client,
    #after reading the full request with its body if there is one,
    #before it is sent to the server.
    def filter_request(self):
        print "filter_request() invoked"

        reject = True
        if reject:
            self.set_reponse()

    def filter_request_headers(self):
        print "filter_request_haeders invoked"


