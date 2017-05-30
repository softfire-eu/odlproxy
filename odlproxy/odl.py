from odlclient.client import ODL
from odlclient.main import _get_odl_client
from odlproxy import odl_printer

__author__ = 'Massimiliano Romano'

class ODLDataRetriever():

    def __init__(self):
        self._odl_client = ODL.get_client_with_env()
        self._odl_client.debug=True

    def getFlows(self,port_id):

        odl = self._odl_client
        nodes = odl.nodes.list_all()

        for node in nodes:
            #print node.id
            print "---tables of %s:"%node.id
            tables = node.tables

            empty_tables_counter=0


            table0=None

            for table in tables:
                if len(table.flows)!=0:
                    print "table[id=%d] has %d flows"%(table.id,len(table.flows))
                else:
                    empty_tables_counter+=1
                if table.id==0:
                    table0=table

            print "There are %d empty tables"%empty_tables_counter

            print "table0"
            flow_of_port_x = flows_starting_with(table0.flows,port_id)
            f = table0.flows
            show(node, 0)

            return
            #flows = odl.flows.list_all(node.id)






        '''
        node = nodes.get("myNodeId")
        for table in node.tables:
            print table
            for flow in table.flows:
                print flow

        print "foreach exited"
        '''


def flows_starting_with(flows,filter_string):
    flows_of_port = []
    for flow in flows:
        if flow.id.startswith(filter_string):
            #do something
            flows_of_port.append(flow)

    return flows_of_port

def show(node, table_id):
    t = [t for t in node.tables if t.id == table_id][0]
    columns = ['id', 'flow_count', 'flow_hash_id_map',
               'aggregate_flow_statistics', 'flow_table_statistics']
    odl_printer.print_desc(columns, t, formatter=odl_printer._flow_formatter)

