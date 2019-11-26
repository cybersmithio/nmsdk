#!/usr/bin/python3
#
# THIS IS NOT SUPPORTED BY ANYONE.
#

import argparse
import os
import json
import sys
import time
import requests
import urllib3
from tenable.sc import TenableSC


#Right now, host and port are ignored
class NMSDK(object):
    def __init__(self):
        self.debug = False
        self.username = None
        self.password = None
        self.host = None
        self.port = None
        self.connection = None
        self.auth_token = None
        self.quiet = False

    def enable_debug(self):
        self.debug = True
        print("Debugging is enabled.")

    def disable_debug(self):
        self.debug = False

    def enable_quiet(self):
        self.quiet = True
        self.debug = False

    def disable_quiet(self):
        print("Quiet is disabled.")
        self.quiet = False

    def set_username(self, value):
        try:
            self.username = str(value)
            return True
        except:
            return False

    def set_password(self, value):
        try:
            self.password = str(value)
            return True
        except:
            return False

    def set_host(self, value):
        try:
            self.host = str(value)
            return True
        except:
            return False

    def set_port(self, value):
        try:
            self.port = str(value)
            return True
        except:
            return False

    # If the connection succeeds, return True, otherwise False
    def connect(self):
        if self.debug:
            print("Opening connection")

        if self.host is not None and self.port is not None:
            url = "https://" + str(self.host) + ":" + str(self.port)+ "/session/"
            if self.debug:
                print("Attempting connection to",url)
            if self.username is not None and self.password is not None:
                payload = {"username": str(self.username),"password": str(self.password)}

                response = requests.post(url, data=payload, verify=False)
                try:
                    if self.debug:
                        print("Response:",response.text)
                    response_data = json.loads(response.text)
                except:
                    print("Unable to parse JSON response")
                    return False

                try:
                    if self.debug:
                        print("Token:", response_data["token"])
                    self.auth_token = str(response_data["token"])
                except:
                    print("Did not get authorization token")
                    return False

                if self.debug:
                    print("Authorization successful!")
                return True
        else:
            print("Not enough information to open connection. Host: '"+str(self.host)+"' Port:'"+str(self.port)+"'")
        return False

    def list_scans(self):
        if self.auth_token is None:
            if self.debug:
                print("No connection.  Cannot list scans.")
        url = "https://" + str(self.host) + ":" + str(self.port) + "/scans"
        headers = {"X-Cookie": "token="+self.auth_token}

        response = requests.get(url, headers=headers, verify=False)

        try:
            if self.debug:
                print("Response:", response.text)
            response_data = json.loads(response.text)
        except:
            print("Unable to parse JSON response")
            return False

        try:
            if self.debug:
                print("Scans:", response_data["scans"])
                for i in response_data["scans"]:
                    print("Scan data:", i)
            return response_data["scans"]
        except:
            print("Did not get a list of scans")
            return False

        return False


    def web_post(self, page, payload):
        url = "https://" + str(self.host) + ":" + str(self.port) + str(page)
        headers = {"X-Cookie": "token="+self.auth_token}
        response = requests.post(url, data=payload, headers=headers, verify=False)

        try:
            if self.debug:
                print("Response:", response.text)
            response_data = json.loads(response.text)
            return response_data
        except:
            print("Unable to parse JSON response")
            return False

    def web_get(self, page):
        url = "https://" + str(self.host) + ":" + str(self.port) + str(page)
        headers = {"X-Cookie": "token="+self.auth_token}
        response = requests.get(url, headers=headers, verify=False)

        try:
            if self.debug:
                print("Response:", response.text)
            response_data = json.loads(response.text)
            return response_data
        except:
            print("Unable to parse JSON response")
            return False

    def web_download(self, page):
        url = "https://" + str(self.host) + ":" + str(self.port) + str(page)
        headers = {"X-Cookie": "token="+self.auth_token}
        try:
            response = requests.get(url, headers=headers, verify=False)
            return response.text
        except:
            return False

    def export_scan(self, scan_id):
        if self.auth_token is None:
            if self.debug:
                print("No connection.  Cannot list scans.")
        if self.quiet is False:
            print("Requesting export of scan ID",scan_id)

        file_token = self.initiate_scan_export(scan_id)

        if file_token is False:
            return False

        retry_count = 0
        while self.is_download_ready(file_token) is False:
            time.sleep(5)
            retry_count += 1
            if retry_count > 120:
                if self.debug:
                    print("File taking too long to download.")
                return False

        if self.download_file(scan_id, file_token) is True:
            if self.quiet is False:
                print("Export of scan ID", scan_id, "was successful")
            return True
        return False

    def initiate_scan_export(self, scan_id):
        if self.auth_token is None:
            if self.debug:
                print("No connection.  Cannot list scans.")
        if self.debug:
            print("Initialing export of scan ID", scan_id)

        response_data = self.web_post("/scans/" + str(scan_id) + "/export", {"format": "nessus"})
        if response_data is False:
            return False

        try:
            if self.debug:
                print("File download token:", response_data["token"])
            return response_data["token"]
        except:
            print("Did not get a download token")
            return False


    def is_download_ready(self, token):
        if self.auth_token is None:
            if self.debug:
                print("No connection.  Cannot check download status.")
            return False
        if self.debug:
            print("Checking status of download with token",token)

        response_data = self.web_get("/tokens/"+str(token)+"/status")
        if response_data is False:
            return False

        try:
            if self.debug:
                print("File download status:", response_data["status"])
        except:
            print("Did not get a download token")
            return False

        if response_data["status"] == "ready":
            return True

        return False

    def download_file(self, scan_id, token):
        if self.auth_token is None:
            if self.debug:
                print("No connection.  Cannot check download status.")
            return False
        if self.debug:
            print("Downloading file with token", token)

        response_data = self.web_download("/tokens/" + str(token) + "/download")
        if response_data is False:
            return False

        try:
            with open(str(scan_id)+".nessus","w") as nessus_file:
                nessus_file.write(response_data)
        except:
            print("Problem writing file",sys.exc_info())
            return False

        return True



######################
###
### Program start
###
######################

if __name__ == '__main__':
    # Get the arguments from the command line
    parser = argparse.ArgumentParser(description="This is an SDK.  If you are running in standalone, this will allow testing of features.")
    parser.add_argument('--username',help="The username",nargs=1,action="store")
    parser.add_argument('--password',help="The password",nargs=1,action="store")
    parser.add_argument('--host',help="The host of the web service.",nargs=1,action="store",default=[None])
    parser.add_argument('--port',help="The port of the web service. (Default is 8834)",nargs=1,action="store",default=["8834"])
    parser.add_argument('--debug',help="Turn on debugging",action="store_true")
    parser.add_argument('--quiet',help="Turn off normal output",action="store_true")
    parser.add_argument('--tsc_username',help="The Tenable.sc username",nargs=1,action="store")
    parser.add_argument('--tsc_password',help="The Tenable.sc password",nargs=1,action="store")
    parser.add_argument('--tsc_host',help="The host for Tenable.sc.",nargs=1,action="store",default=[None])
    parser.add_argument('--tsc_port',help="The port for Tenable.sc. (Default is 443)",nargs=1,action="store",default=["443"])
    parser.add_argument('--import_repo',help="The Tenable.sc repository ID where the scans should be imported into",nargs=1,action="store")
    args=parser.parse_args()

    urllib3.disable_warnings()

    connector = NMSDK()

    if args.debug:
        connector.enable_debug()

    if args.quiet:
        connector.enable_quiet()

    # Try pulling credentials from environment, but if there are command line variables they will override.
    if os.getenv('USERNAME') is not None:
        connector.set_username(os.getenv('USERNAME'))

    if os.getenv('PASSWORD') is not None:
        connector.set_password(os.getenv('PASSWORD'))

    try:
        if args.username[0] != "":
            connector.set_username(args.username[0])
            connector.set_password(args.password[0])
    except:
        pass

    try:
        if args.port[0] != "":
            connector.set_port(args.port[0])
    except:
        pass

    tsc_host = None
    tsc_port = None
    tsc_username = None
    tsc_password = None
    if os.getenv('TSC_USERNAME') is not None:
        tsc_username = os.getenv('TSC_USERNAME')

    if os.getenv('TSC_PASSWORD') is not None:
        tsc_password = os.getenv('TSC_PASSWORD')

    try:
        if args.tsc_username[0] != "":
            tsc_username = args.tsc_username[0]
            tsc_password = args.tsc_password[0]
    except:
        pass

    try:
        if args.host[0] != "":
            connector.set_host(args.host[0])
    except:
        pass


    try:
        if args.tsc_host[0] != "":
            tsc_host = args.tsc_host[0]
    except:
        pass

    try:
        if args.tsc_port[0] != "":
            tsc_port = args.tsc_port[0]
    except:
        pass

    try:
        import_repo = int(args.import_repo[0])
    except:
        print("Invalid repo ID")
        exit(-1)

    # Create the connection to whatever platform has been specified.
    conn = connector.connect()
    sc = TenableSC(tsc_host, port=tsc_port)
    sc.login(tsc_username, tsc_password)

    if conn is False:
        print("Unable to connect.")
        exit(-1)

    scan_list = connector.list_scans()
    if scan_list is False:
        print("Could not get scan list.")
        exit(-1)

    for scan in scan_list:
        if connector.export_scan(scan['id']) is True:
            print("Uploading file to Tenable.sc repo ID",import_repo)
            with open(str(scan['id'])+".nessus") as nessus_file:
                response = sc.scan_instances.import_scan(nessus_file, import_repo)
                print("Response: ", response)

    sc.logout




