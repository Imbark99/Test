#!/usr/bin/python3
import os
import re
import csv
import time
import json
import codecs
import socket
import os.path
import netaddr
import argparse
import requests
import ipaddress
import urllib.request as urllib
import urllib.request as urlRequest
import urllib.parse as urlParse

from dotenv import load_dotenv


# Setup API Key
while os.getenv('API_KEY') is None:
    load_dotenv()
    if os.getenv('API_KEY'):
        api_key = os.getenv('API_KEY')
    else:
        with open('.env', 'w') as outfile:
            setKey = "3cfd8e8efc2d74288fcebb908af4fc370e989df5aa86e9a49f082a00e125717d47123b1c8609aa74"
            outfile.write(f'API_KEY={setKey}')




def get_cat(x):
    return {
        0: 'BLANK',
        3: 'Fraud_Orders',
        4: 'DDoS_Attack',
        5: 'FTP_Brute-Force',
        6: 'Ping of Death',
        7: 'Phishing',
        8: 'Fraud VoIP',
        9: 'Open_Proxy',
        10: 'Web_Spam',
        11: 'Email_Spam',
        12: 'Blog_Spam',
        13: 'VPN IP',
        14: 'Port_Scan',
        15: 'Hacking',
        16: 'SQL Injection',
        17: 'Spoofing',
        18: 'Brute_Force',
        19: 'Bad_Web_Bot',
        20: 'Exploited_Host',
        21: 'Web_App_Attack',
        22: 'SSH',
        23: 'IoT_Targeted',
    }.get(
        x,
        'UNK CAT, ***REPORT TO MAINTAINER***OPEN AN ISSUE ON GITHUB w/ IP***')



def check_ip(IP, days):
    if ipaddress.ip_address(IP).is_private is False:
        headers = {
            'Key': "3cfd8e8efc2d74288fcebb908af4fc370e989df5aa86e9a49f082a00e125717d47123b1c8609aa74",
            'Accept': 'application/json',
        }

        params = {
            'maxAgeInDays': days,
            'ipAddress': IP,
            'verbose': ''
        }

        r = requests.get('https://api.abuseipdb.com/api/v2/check',
                         headers=headers, params=params)
        response = r.json()
        if 'errors' in response:
            print(f"Error: {response['errors'][0]['detail']}")
            exit(1)
        return response['data']
    else:
        return (f"{IP} is private. No Resuls")
