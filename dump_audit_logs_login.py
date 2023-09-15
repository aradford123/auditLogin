#!/usr/bin/env python
from __future__ import print_function
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from requests.auth import HTTPBasicAuth
import json
import time
import sys
#from dateutil import parser
from argparse import ArgumentParser
from config import DNAC_IP, DNAC_USER,DNAC_PASS
from collections import Counter


HEADERS= {'Content-Type' : 'application/json'}
class DNAC:
    def __init__(self, dnac_ip, username, password, port=443):
        self.dnac_ip = dnac_ip
        self.port = port
        self.base = 'https://{}:{}'.format(self.dnac_ip, self.port)
        self.session = {}
        self.login(self.dnac_ip, self.port, username, password)

    def login(self, dnac_ip, port, username, password):
        """Login to dnac"""
        url = self.base + '/api/system/v1/auth/token'

        result = requests.post(url=url, auth=HTTPBasicAuth(username, password), verify=False)
        result.raise_for_status()

        token = result.json()["Token"]
        self.session[dnac_ip] = token

    def get(self, mount_point, headers={}):
        """GET request"""
        url = self.base + "/{}".format(mount_point)
       # print (url)
        headers = {'x-auth-token' : self.session[self.dnac_ip], 'accept': 'application/json'}
        response = requests.get(url, headers= headers, verify=False)
        response.raise_for_status()
        data = response.json()
        return data

    def post(self, mount_point, payload, headers={}):
        """POST request"""
        url = url = self.base + "/{}".format(mount_point)
        headers = {'Content-Type': 'application/json', 'x-auth-token': self.session[self.dnac_ip]}
        response = requests.post(url=url, data=json.dumps(payload), headers=headers, verify=False)
        response.raise_for_status()
        data = response.json()
        return data
    def put(self, mount_point, payload, headers={}):
        """POST request"""
        url = url = self.base + "{}".format(mount_point)
        headers = {'Content-Type': 'application/json', 'x-auth-token': self.session[self.dnac_ip]}
        response = requests.put(url=url, data=json.dumps(payload), headers=headers, verify=False)
        response.raise_for_status()
        data = response.json()
        return data

    def delete(self, mount_point ):
        """POST request"""
        url = url = self.base + "{}".format(mount_point)
        headers = {'x-auth-token': self.session[self.dnac_ip]}

        response = requests.delete(url=url, headers=headers, verify=False)
        response.raise_for_status()
        return response

def msec_to_gmt(msec):
    if msec == None:
        return "1970-01-01 00:00:00"
    epoc = msec /1000
    return time.strftime('%Y-%m-%d %H:%M:%S%z', time.localtime(epoc))

def get_summary(dnac,start,end):
    result=dnac.get("dna/data/api/v1/event/event-series/audit-log/summary?name=LOGIN_USER_EVENT&startTime={}&endTime={}".format(start,end))
    return result

def print_summary(result):
    r = result
    start= r['minTimestamp']
    end = r['maxTimestamp']
    print("Total: {}, first: {}({}), last: {}({})".format(r['count'], 
                                                        msec_to_gmt(start), 
                                                        start,
                                                        msec_to_gmt(end),
                                                        end))
def process_all(dnac,summary):
    total_records = []  
    LIMIT = 25
    count = summary['count']
    starttime = summary['minTimestamp']
    endtime = summary['maxTimestamp']
    print(count)
    for start in range(0, count+1, LIMIT):
        print("{:.1f}% complete".format(100*start/count))
        records = dnac.get("dna/data/api/v1/event/event-series/audit-logs?name=LOGIN_USER_EVENT&startTime={}&endTime={}&offset={}&limit={}".format(starttime,endtime,start,LIMIT))
        total_records.extend(records)
    print(len(total_records))
    summarise(total_records)

def summarise(total_records):
    summary={}
    users = [ record['userId'] for record in total_records]
    results = Counter(users)
    print(results)

if __name__ == "__main__":
    aparser = ArgumentParser(description='Select options.')
    aparser.add_argument('--dnac', type=str, required=False, default=DNAC,
                        help="dnac")
    aparser.add_argument('--password', type=str, required=False, default=DNAC_PASS,
                        help="dnac password")

    args = aparser.parse_args()
    if args.dnac:
        DNAC_IP = args.dnac
    dnac = DNAC(DNAC_IP, DNAC_USER, DNAC_PASS)


    endtime = int(time.time() * 1000)
    starttime = endtime - (24 * 3600 * 1000)
    result = get_summary(dnac,starttime,endtime)
    print_summary(result[0])
    process_all(dnac, result[0])
