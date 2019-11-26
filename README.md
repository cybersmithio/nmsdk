# Overview 
THIS PROJECT IS NOT SUPPORTED BY *ANYONE*.

This is an example script to pull scan data out of NM and push into SC.  

# Requirements
This requires Python 3 and several libraries to be installed.

To install all the required libraries with pip, type:
```
pip install pytenable requests
```

# Help
To get help on the command line, type:
```
python3 transfer.py --help
```

# Example to run
```
export NMHOST=192.168.255.10
export NMPORT=8834
export NMUSER=admin
export NMPASS=password
export SCHOST=192.168.255.20
export SCPORT=443
export SCUSER=secmanager
export SCPASS=password
export SCREPO=1
python3 transfer.py --username $NMUSER --password $NMPASS \
  --host $NMHOST --port $NMPORT \
  --tsc_username $SCUSER --tsc_password $SCPASS \
  --tsc_host $SCHOST --tsc_port $SCPORT --import_repo $SCREPO
```

#Internals
The transfer.py script uses a module called nmsdk, which has various methods used to get the data from NM.
The general workflow is:

* Create a NM connector object: 

```nm_connector = NMSDK()```

* Set the credentials to talk with NM: 
```
nm_connector.set_username("admin")
nm_connector.set_password("password")
```

* Set the IP and port for the NM:
```
nm_connector.set_host("192.168.255.10")
nm_connector.set_port("8834")
```

* Initiate the connection to NM:

```nm_connector.connect()```

* Get a list of all the scans in NM:

```scan_list = connector.list_scans()```

* Export all the scans into .nessus files with code like this:

```
for scan in scan_list:
    connector.export_scan(scan['id'])
```
