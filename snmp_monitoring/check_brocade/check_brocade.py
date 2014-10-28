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

This script monitors server hardware for all Brocade devices. It replaces the monitoring previously performed by Nimsoft SNMPget. 

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
logging.basicConfig(filename='/var/log/snmp_monitoring/check_brocade.log',format='%(asctime)s: %(levelname)s: %(message)s',level=logging.DEBUG)
docroot = "/opt/spot/snmp_monitoring/check_brocade/"
open_alarms = []

#COUNTERS
totalStats = [0,0,0,0,0,0]
deviceCount = 0
open_alarms = []

def sendToPagerDuty(type,key,desc,det):
    SPOT_API_TOKEN="<Your PagerDuty API>"
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
    SPOT_API_TOKEN="<Your PagerDuty API>"
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
    with open(docroot+'brocade_exclusions','r') as f:
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

def querySensors(device,host):
    total,ok,failed = 0,0,0
    for index in device.connUnitSensorIndex:
        total += 1
        allowed_status = ['ok(3)']
        sensorIndex = device.connUnitSensorIndex[index]
        sensorName = device.connUnitSensorName[index]
        sensorStatus = device.connUnitSensorStatus[index]
        sensorInfo = device.connUnitSensorInfo[index]
        sensorMessage = device.connUnitSensorMessage[index]
        sensorType = device.connUnitSensorType[index]
        sensorCharacteristic = device.connUnitSensorCharacteristic[index]
        
        details = 'Status = {0}; Name = {1}; Info = {2}; Message = {3}; Type = {4}; Characteristic = {5}'.format(sensorStatus, sensorName, sensorInfo, sensorMessage, sensorType, sensorCharacteristic)

        current_check = "Sensor"
        if str(sensorStatus) not in allowed_status:
            failed += 1
            msg = 'ERROR: {0} Check: {1}'.format(current_check, details)
            incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,sensorIndex,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
            logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
        else:
            ok += 1
            msg = 'OK: {0} Check: {1}'.format(current_check, details)
            logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,sensorIndex,current_check.lower()),"No {0} issues detected".format(current_check),msg)
    return total,ok,failed

def queryFRUs(device,host):
    total,ok,failed = 0,0,0
    for index in device.fruObjectNum:
        total += 1
        allowed_status = ['on(3)']
        fruClass = device.fruClass[index]
        fruStatus = device.fruStatus[index]
        fruSupplierID = device.fruSupplierId[index]
        fruSupplierPartNum = device.fruSupplierPartNum[index]
        fruSupplierSerialNum = device.fruSupplierSerialNum[index]
        
        details = 'Status = {0}; Class = {1}; SupplierID = {2}; PartNum = {3}; SerialNum = {4}'.format(fruStatus, fruClass, fruSupplierID, fruSupplierPartNum, fruSupplierSerialNum)
       
        current_check = "FRU"
        if str(fruStatus) not in allowed_status:
            failed += 1
            msg = 'ERROR: {0} Check: {1}'.format(current_check, details)
            incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
            logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
        else:
            ok += 1
            msg = 'OK: {0} Check: {1}'.format(current_check, details)
            logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No {0} issues detected".format(current_check),msg) 

    return total,ok,failed

# Not currently running this because it returns the same information as querySensors.
def querySwSensors(device,host):
    total,ok,failed = 0,0,0
    for index in device.swSensorIndex:
        swSensorType = device.swSensorType[index]
        swSensorStatus = device.swSensorStatus[index]
        swSensorValue = device.swSensorValue[index]
        swSensorInfo = device.swSensorInfo[index]

        details = 'Status = {0}; Type = {1}; Value = {2}; Info = {3}'.format(swSensorStatus, swSensorType, swSensorValue, swSensorInfo)
        print details

    return total,ok,failed

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
    deviceResults = [0,0,0,0,0,0]

    #Perform checks, load results into list

    next_check = "querySensors"
    try:
        deviceResults[0:3] = querySensors(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

    next_check = "queryFRUs"
    try:
        deviceResults[3:6] = queryFRUs(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

    for i in range(len(totalStats)):
        totalStats[i]+=deviceResults[i]
    logging.info('{0}\tSTATS\t(Checked,OK,Error) || Sensor({1},{2},{3}) || FRU({4},{5},{6})'.format(hostname,*deviceResults))

def main():
    logging.info('***************************************************************************')
    logging.info('Starting Script')
    deviceCount = 0

    #Prepare exclusions file
    touch(docroot + 'brocade_exclusions')

    #Load required MIBs
    load(docroot + 'mibs/SNMPv2-MIB')
    load(docroot + 'mibs/RFC1155-SMI.txt')
    load(docroot + 'mibs/BRCD_REG.mib')
    load(docroot + 'mibs/BRCD_TC.mib')
    load(docroot + 'mibs/FA.mib')
    load(docroot + 'mibs/FCMGMT-MIB.mib')
    load(docroot + 'mibs/SW.mib')
    load(docroot + 'mibs/HA.mib')

    #Check PagerDuty for open incidents
    try:
        getCurrentAlarms()
    except Exception as inst:
        msg = 'Exception occurred while querying PagerDuty for open incidents; Exception = "{0}"'.format(inst)
        logging.warning('PAGER\tERROR\r{0}'.format(msg))

    script_start = time.time()
    try:
        deviceFile = open(docroot+'brocade_devices','r')
        comm = "public"
        ver = 2
        for line in deviceFile:
            if line[0:1] != "#":
                deviceCount += 1
                start = time.time()
                hostname = line[:-1]
                queryDevice(hostname,comm,ver)
                end = time.time()
                print '{0} - {1} - {2} sec. {3} total sec.'.format(deviceCount,hostname,(end-start),(end-script_start))
    except Exception as inst:
        msg = 'Exception occurred in main function. Exception = "{0}"'.format(inst)
        logging.warning('MAIN\tERROR\t{0}'.format(msg))

    logging.info('TOTAL\tSTATS\t(Checked,OK,Error) || Sensor({1},{2},{3}) || FRU({4},{5},{6}) || Devices({0})'.format(deviceCount,*totalStats))
    logging.info('Script Complete')


if __name__ == "__main__":
    main()
