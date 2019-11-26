#!/usr/bin/python3
#
# THIS IS NOT SUPPORTED BY ANYONE.
#

import argparse
import os
import urllib3
from tenable.sc import TenableSC
from nmsdk import NMSDK


######################
###
### Program start
###
######################

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




