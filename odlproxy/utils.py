import logging
import logging.config
import json
import os
from collections import OrderedDict

CONFIG_FILE_PATH = './odl-proxy-log.ini'

_logger = dict()

def get_logger(name):
    logging.config.fileConfig(CONFIG_FILE_PATH, disable_existing_loggers=False)
    if _logger.get(name) is None:
        _logger[name] = logging.getLogger("odlproxy.%s" % name)#

    return _logger[name]

def make_jsonrpc_error(responseid, code, message, version="2.0"):
    return dict(id=responseid, error=dict(message=message, code=code), jsonrpc=version)


def make_jsonrpc_response(responseid, result, version="2.0"):
    return dict(id=responseid, jsonrpc=version, result=result)

def readMapExperiments(file_path):
    if os.path.isfile(file_path):
        with open(file_path) as json_data:
            #file = json.load(json_data)

            file = json.load(json_data, object_pairs_hook=OrderedDict)

            return file
    else:
        return None
def writeMapExperiments(map,file_path):

    with open(file_path, 'w') as outfile:
        json.dump(map, outfile)
