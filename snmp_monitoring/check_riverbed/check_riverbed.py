#!/usr/bin/env python
from snimpy.manager import Manager as M
from snimpy.manager import load
import argparse
import socket
import time
import logging
import subprocess
import pygerduty
import os
import datetime
from collections import defaultdict

"""
========
OVERVIEW
========

This script monitors server hardware for all Riverbed devices. It replaces the monitoring previously performed by Nimsoft SNMPget. 

The script uses the following process:
    1. Check textfile for exclusions
    2. Load MIBs
    3. Check PagerDuty for open incidents
    4. Query Devices

=======
DETAILS
=======

1. Check textile for exclusions: Exclusions can be added to the snmp_exclusions file. 
If this script later detects a hardware issue, it will first check it against the exclusions list 
before sending it to PagerDuty. Exclusions are stored in the same format as the PD incident key. 
The easiest way to add a new exclusion is to open the incident in PD, copy the incident key, 
then add that to the text file.

2. Load MIBs: This script uses the Snimpy module for all SNMP processing. This module requires 
that you first load all required MIBs before you start querying devices. The mibs are all located 
in the 'mibs' directory.

3. Check PagerDuty for open incidents: The pygerduty module is used to connect to PagerDuty's API
and pull the list of all open incidents. This list is used to ensure "resolve" commands are only sent to
PD for incidents which are currently open. We cannot send "resolve" commands for every "OK" check, 
because that would be well over PD's API rate limit.

4. Query Devices: The script loops through the list returned from Salt and goes through the following process:
            > Try to connect to SNMP agent
            > Test hardware sensors (such as fans, temperature, disks, etc)
                Compare actual value against allowed values.
                    If OK:
                        Call sendToPagerDuty("resolve"...) This will check against open PD incidents and send a "resolve" if it 
                        finds a match. Otherwise, no action is taken. 
                    If not OK:
                        Call sendToPagerDuty("trigger"...) This will use pygerduty to send a "trigger" to PD. 
                        If it is a new issue, a new incident will be created. Else, it will be added to the existing incident.         
"""

#SET LOGGING INFO
if not os.path.exists('/var/log/snmp_monitoring/'):
    os.mkdir('/var/log/snmp_monitoring/')
logging.basicConfig(filename='/var/log/snmp_monitoring/check_riverbed.log',format='%(asctime)s: %(levelname)s: %(message)s',level=logging.DEBUG)
docroot = "/opt/spot/snmp_monitoring/check_riverbed/"
open_alarms = []

#COUNTERS
totalStats = [0,0,0]
deviceCount = 0

#SET GRAPHITE INFO
#CARBON_SERVER = '{{ salt['pillar.get']('globals:graphite') }}'
#CARBON_SERVER = 'chivlxstg104'
CARBON_PORT = 2003

open_alarms = []

def sendToGraphite(path, value):
    timestamp = int(time.time())
    message = '%s %s %d\n' % (path, value, timestamp)

    logging.debug('GRAPH    {0}'.format(message.strip()))
    sock = socket.socket()
    sock.connect((CARBON_SERVER, CARBON_PORT))
    sock.sendall(message)
    sock.close()
    return;

def sendToPagerDuty(type,key,desc,det):
    SPOT_API_TOKEN="<Your PagerDuty API token>"
    SERVICE_API_TOKEN="<Your PagerDuty service API token>"
    try:
        pager = pygerduty.PagerDuty(api_token=SPOT_API_TOKEN)
        if type == "trigger":
            if checkForExclusion(key) is False:
                incident = pager.trigger_incident(service_key=SERVICE_API_TOKEN, incident_key=key, description=desc, details=det)
                logging.info('<Your PagerDuty domain>\tPAGER\tCreating Alarm: {0}'.format(key))
                return incident
            else:
                logging.info('<Your PagerDuty domain>\tPAGER\tAlarm Excluded: {0}'.format(key))
                return 'Excluded'
        elif type == "resolve":
            if checkForAlarm(key):
                logging.info('<Your PagerDuty domain>\tPAGER\tResolving Open Incident: {0}'.format(key))
                incident = pager.resolve_incident(service_key=SERVICE_API_TOKEN, incident_key=key, description=desc, details=det)
                return incident
    except Exception as inst:
        msg = 'Exception occurred while sending incident to PagerDuty; Exception = "{0}"'.format(inst)
        logging.warning('PAGER\t\tERROR\t{0}'.format(msg))
        return 'exception'

# Uses pygerduty to get current list of all open incidents for PD. We need this information
# to decide when "resolve" messages are needed.
def getCurrentAlarms():
    SPOT_API_TOKEN="<Your PagerDuty API token>"
    pager = pygerduty.PagerDuty(api_token=SPOT_API_TOKEN)
    for incident in pager.incidents.list(status="triggered,acknowledged"):
        open_alarms.append(incident.incident_key)
        logging.info('PAGER\tOPEN INCIDENTS\t{0}'.format(incident.incident_key))

def checkForAlarm(key):
    if key in open_alarms:
        return True
    return False

def checkForExclusion(key):
    result = False
    with open(docroot+'riverbed_exclusions','r') as f:
        for line in f:
            if line[:-1] == key:
                result = True
                return result
    return result

def touch(fname):
    if os.path.exists(fname):
        os.utime(fname, None)
    else:
        open(fname, 'a').close()

# Most query* functions follow the same format. They use snimpy to request a list of all hw components (such as HDDs) on the device, then 
# loop through that list and grab all relevant info (such as condition, SMART status, serial #) for each component. Those results are 
# then compared against a list of acceptable values (make sure status is 'ok'). If any non-acceptable results are found 
# (status = "predictive failure"), the relevant information is added to a message and sent to PagerDuty (via sendToPagerDuty()).
# If things are OK, sendToPagerDuty() is still used, but only to determine if a "resolve" needs to be sent to PD. 

def queryHealth(device,host):
    total,ok,failed = 0,0,0
    total += 1
    allowed_status = ['Healthy']
    systemHealth = device.health
    systemSerial = device.serialNumber
    details = 'Health = {0}; Serial = {1}'.format(systemHealth, systemSerial)
    
    current_check = "Health"
    if str(systemHealth) not in allowed_status:
        failed += 1
        msg = 'ERROR: {0} Check: {1}'.format(current_check, details)
        incident = sendToPagerDuty("trigger","snmp/{1}/{0}".format(host,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
        logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
    else:
        ok += 1
        msg = 'OK: {0} Check: {1}'.format(current_check, details)
        logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
        sendToPagerDuty("resolve","snmp/{1}/{0}".format(host,current_check.lower()),"No {0} issues detected".format(current_check),msg)
    return total,ok,failed

def queryStats(device,host):
    systemTemperature = device.systemTemperature
    cpuLoad1 = device.cpuLoad1
    cpuLoad5 = device.cpuLoad5
    cpuLoad15 = device.cpuLoad15
    cpuUtil1 = device.cpuUtil1

    sendToGraphite('storage.riverbed.{0}.{1}'.format(host,'systemTemperature'),systemTemperature)
    sendToGraphite('storage.riverbed.{0}.{1}'.format(host,'cpuLoad1'),cpuLoad1)
    sendToGraphite('storage.riverbed.{0}.{1}'.format(host,'cpuLoad5'),cpuLoad5)
    sendToGraphite('storage.riverbed.{0}.{1}'.format(host,'cpuLoad15'),cpuLoad15)
    sendToGraphite('storage.riverbed.{0}.{1}'.format(host,'cpuUtil1'),cpuUtil1)

def queryDevice(hostname,comm,ver):
    global deviceCount

    #Connect to device
    try:
        device = M(host=hostname,community=comm,version=ver,timeout=30,retries=3)
        desc = device.sysDescr
        msg = 'Successfully connected to {0}.'.format(hostname)
        sendToPagerDuty("resolve","snmp/connect/{0}".format(hostname),"SNMP agent is responding on {0}".format(hostname),msg)
    except Exception as inst:
        msg = 'Exception occurred while connecting to {0}. Exception = "{1}"'.format(hostname,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,inst))
        t = datetime.datetime.now().timetuple()
        #only generate alarm during the day
        if (t[3]>=7) and (t[3]<=19):
            incident = sendToPagerDuty("trigger","snmp/connect/{0}".format(hostname),"Unable to query SNMP on {0}".format(hostname),msg)
        return

    deviceCount += 1 
    deviceResults = [0,0,0]

    #Perform checks, load results into list

    next_check = "queryHealth"
    try:
        deviceResults[0:3] = queryHealth(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

    #Uncomment if you would like to send stats to Graphite
    #next_check = "queryStats"
    #try:
    #    queryStats(device,hostname)
    #except Exception as inst:
    #    msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
    #    logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))
    
    for i in range(len(totalStats)):
        totalStats[i]+=deviceResults[i]
    logging.info('{0}\tSTATS\t(Checked,OK,Error) || Health({1},{2},{3})'.format(hostname,*deviceResults))

def main():
    logging.info('***************************************************************************')
    logging.info('Starting Script')
    deviceCount = 0

    #Prepare stats file
    touch(docroot + 'riverbed_exclusions')

    #Load required MIBs
    load(docroot + "mibs/SNMPv2-MIB")
    load(docroot + "mibs/riverbed-rbt.mib")
    load(docroot + "mibs/WW-MIB.txt")

    #Check PagerDuty for open incidents
    try:
        getCurrentAlarms()
    except Exception as inst:
        msg = 'Exception occurred while querying PagerDuty for open incidents; Exception = "{0}"'.format(inst)
        logging.warning('PAGER\tERROR\r{0}'.format(msg))

    script_start = time.time()
    try:
        deviceList = ['<Your riverbed device name>']
        comm = "public"
        ver = 2
        for line in deviceList:
            if line[0:1] != "#":
                deviceCount += 1
                start = time.time()
                hostname = line
                queryDevice(hostname,comm,ver)
                end = time.time()
                print '{0} - {1} - {2} sec. {3} total sec.'.format(deviceCount,hostname,(end-start),(end-script_start))
    except Exception as inst:
        msg = 'Exception occurred in main function. Exception = "{0}"'.format(inst)
        logging.warning('MAIN\tERROR\t{0}'.format(msg))

    logging.info('TOTAL\tSTATS\t(Checked,OK,Error) || Health({1},{2},{3}) || Devices({0})'.format(deviceCount,*totalStats))
    logging.info('Script Complete')


if __name__ == "__main__":
    main()
