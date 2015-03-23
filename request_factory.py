#!/usr/bin/python

import sys
import time
import os
from os.path import join, basename
import logging
from collections import defaultdict
import argparse
import json

'''
    This method should return a list of IDS each representing a unit of work,
    that could be processed by worker.

    return:
        list of ids
'''
def get_available_request_ids():
    to_ret = []
    return to_ret

'''
    This method returns request data corresponding to the provided id.

    return:
        data corresponding to the id.
'''
def get_request_data(target_id):
    to_ret = None

'''
    This method return data that could be used to setup client.

    return:
        data which could be used by client to setup itself for processing.
'''
def get_setup_data():
    to_ret = None

'''
    This method handles result for corresponding request id.
    return:
        True/False depending on whether the response is valid or not.
'''
def process_client_result(request_id, result_data):
    

