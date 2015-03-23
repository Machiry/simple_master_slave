#!/usr/bin/python

import sys
import time
import os
from os.path import join, basename
import logging
from collections import defaultdict
import argparse
import json

from threading import Lock
from urlparse import urlparse, parse_qs
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
form request_factory import *

import IPython


logging.basicConfig(format='%(levelname)s:%(asctime)s:%(message)s',
                    level=logging.DEBUG)



def main():
    start_service_apks("", "")


def start_service_apks(apk_fps, results_dir):

    class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        pass

    server = ThreadedHTTPServer(('', 8888), RequestHandler)
    #get all available IDs
    server.available_req_ids = get_available_request_ids()
    server.completed_ids = []
    server.timeout_ids = []
    server.processing = {}
    server.error_ids = []

    while True:
        server.handle_request()




class RequestHandler(BaseHTTPRequestHandler):

    ip2requestids = {}
    ip2tentativereqs = {}


    def send_complete_response(self, resp_code, resp_msg):
        self.send_response(resp_code)
        if resp_msg:
            content_len = len(resp_msg)
            self.send_header('Content-Length', '%d' % content_len)
            self.end_headers()
            self.wfile.write(resp_msg)

    def read_post_data(self):
        try:
            length = int(self.headers.getheader('content-length'))
            logging.debug('Reading %s bytes from data' % length)
            data = self.rfile.read(length)
            return data
        except:
            return None

    def do_POST(self):
        '''
        commands handled: result-ready
        '''
        _parse_res = urlparse(self.path)
        command, query_string = _parse_res.path, _parse_res.query
        ip = self.client_address[0]

        if command == '/result-success':            

            target_req_id = query_string.split('=', 1)[1]
    
            resp_code = 404
            resp_msg = 'Invalid Request id'
            self.server.lock.acquire()
            
            if target_req_id in self.processing and (self.processing[target_req_id] == ip):
                target_data = self.read_post_data()
                del self.processing[target_req_id]
                self.completed_ids.append(target_req_id)
                #handle response
                process_client_result(target_req_id,target_data)
                resp_code = 200
                resp_msg = 'OK'
            else:
                logger.error('Improper request id %s in result from %s' % (target_req_id,ip))
            self.server.lock.release()

            self.send_complete_response(resp_code, resp_msg)

        elif command == '/result-timeout':
            #handle time out.
            target_req_id = query_string.split('=', 1)[1]
            
        elif command == '/result-error':
            #handle error
        else:
            logging.warning('Received NOT handled POST cmd "%s" from %s' % (command, ip))
            resp_code, resp_msg = 400, 'command %s not handled\n' % command
            self.send_complete_response(resp_code, resp_msg)

    def do_GET(self):
        '''
        This is the get request handler. 
        This handles client requests.
        '''

        _parse_res = urlparse(self.path)
        command, query_string = _parse_res.path, _parse_res.query
        ip = self.client_address[0]

        '''
            ping command handler.
        '''
        if command == '/ping':
            logging.info('Received a ping from %s' % ip)
            resp_code, resp_msg = 200, 'OK'
            self.send_complete_response(resp_code, resp_msg)

        '''
            sleep command handler.
        '''
        elif command == '/sleep':
            logging.info('Received a sleep cmd from %s' % ip)
            logging.info('Starting sleeping..(ip: %s)' % ip)
            time.sleep(5)
            logging.info('Done sleeping! (ip: %s)' % ip)
            resp_code, resp_msg = 200, 'SLEEP'
            self.send_complete_response(resp_code, resp_msg)

        '''
            Data required for client to setup it self.
        '''
        elif command == '/get-setup-data':
            setup_data = get_setup_data()
            logging.info('Received a /get-setup-data from %s.' % (ip))
            try:
                self.send_complete_response(200,script_data)
            except:
                logging.error('Unable to get setup data to be sent to %s' % (ip))
                self.send_complete_response(404,"")

        '''
            Next request id to process.
        '''
        elif command == '/get-request':
            to_ret = None
            self.server.lock.acquire()
            #see if you can get a free request id for client to process.
            if len(self.server.available_req_ids) > 0:
                to_ret = self.server.available_req_ids[0]
                del self.server.available_req_ids[0]
                if not (ip in self.ip2tentativereqs):
                    self.ip2tentativereqs[ip] = []
                self.ip2tentativereqs[ip].append(to_ret)
            self.server.lock.release()
    
            if to_ret != None:
                #cool, we have request for worker to process.                
                logging.info('Received a /get-request from %s. Returning: %s' % (ip, to_ret))
                self.send_complete_response(200, to_ret)
            else:           
                logging.error('No more requests to process for %s' % (ip))
                self.send_complete_response(404,"")

        '''
            Get request data corresponding to the provided request id.
        '''
        elif command == '/get-request-data':
            original_target_request_id = query_string.split('=', 1)[1]
            logging.info('Received a request from %s with %s' % (ip, target_request_id))

            self.server.lock.acquire()
            target_request_id = original_target_request_id
            #if this id is already requested for.
            if (ip in self.ip2tentativereqs) and (target_request_id in self.ip2tentativereqs[ip]):
                del self.ip2tentativereqs[ip][self.ip2tentativereqs[ip].index(target_request_id)]
                if len(self.ip2tentativereqs[ip]) == 0:
                    del self.ip2tentativereqs[ip]                 
            else:
                #else, we got a request id not assigned to client.
                target_request_id = None

            self.server.lock.release()
            if target_request_id != None:
                resp_code = 200
                self.processing[target_request_id] = ip
                file_data = get_request_data(target_request_id)
                #send request data to requesting worker.
                self.send_complete_response(resp_code, file_data)
                logging.info('Sent data to %s..' % (ip)))
            else:
                self.send_complete_response(404,"")
                logging.error('Wrong request id %s received from %s' % (ip,original_target_request_id))
            
        else:
            logging.warning('Cannot handle cmd "%s" from %s' % (command, ip))
            resp_code, resp_msg = 400, 'command %s not handled\n' % command
            self.send_complete_response(resp_code, resp_msg)

if __name__ == '__main__':
    main()
