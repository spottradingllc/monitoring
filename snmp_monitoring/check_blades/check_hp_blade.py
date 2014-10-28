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

This script monitors server hardware for all HP BladeCenters. It replaces the monitoring previously performed by Nimsoft SNMPget. 

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
            > Test hardware sensors (fans, temperature, power supplies, power enclosures, enclosures, managers, blades
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
logging.basicConfig(filename='/var/log/snmp_monitoring/check_hp_blade.log',format='%(asctime)s: %(levelname)s: %(message)s',level=logging.INFO)
docroot = "/opt/spot/snmp_monitoring/check_blades/"
open_alarms = []

#COUNTERS
totalStats = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
deviceCount = 0

def sendToPagerDuty(type,key,desc,det):
    SPOT_API_TOKEN="<Your PagerDuty API Token>"
    SERVICE_API_TOKEN="<Your PagerDuty service token>"
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
    SPOT_API_TOKEN="<Your PagerDuty token>"
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
    with open(docroot+'hp_blade_snmp_exclusions','r') as f:
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
def queryFans(device,host):
    total,ok,failed = 0,0,0
    for index in device.cpqRackCommonEnclosureFanIndex:
        total += 1
        allowed_condition = ['ok(2)']
        fanCondition = device.cpqRackCommonEnclosureFanCondition[index]
        fanEncSerial = device.cpqRackCommonEnclosureFanEnclosureSerialNum[index]
        fanLocation = device.cpqRackCommonEnclosureFanLocation[index]
        fanPartNum = device.cpqRackCommonEnclosureFanPartNumber[index]
        fanSparePartNum = device.cpqRackCommonEnclosureFanSparePartNumber[index]
        fanPresent = device.cpqRackCommonEnclosureFanPresent[index]
        
        current_check = "Fan"
        if str(fanCondition) not in allowed_condition:
            failed += 1
            msg = 'Error for {0} Sensor: Condition = {1}; Location = {2}; EnclosureSerial = {3}; Present = {4}; PartNum = {5}; SparePartNum = {6}'.format(current_check,fanCondition,fanLocation,fanEncSerial,fanPresent,fanPartNum,fanSparePartNum)
            incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
            logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
        else:
            ok += 1
            msg = 'OK for {0} Sensor: Condition = {1}; Location = {2}; EnclosureSerial = {3}; Present = {4}; PartNum = {5}; SparePartNum = {6}'.format(current_check,fanCondition,fanLocation,fanEncSerial,fanPresent,fanPartNum,fanSparePartNum)
            logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)
        
        #print 'FAN: {0} - {1} - {2} - {3} - {4} - {5}'.format(fanCondition, fanEncSerial, fanLocation, fanPartNum, fanSparePartNum, fanPresent)
    return total,ok,failed

def queryTemp(device,host):
    total,ok,failed = 0,0,0
    for index in device.cpqRackCommonEnclosureTempSensorIndex:
        total += 1
        allowed_condition = ['ok(2)','other(1)']
        tempSerial = device.cpqRackCommonEnclosureTempSensorEnclosureSerialNum[index]
        tempLocation = device.cpqRackCommonEnclosureTempLocation[index]
        tempCurrent = device.cpqRackCommonEnclosureTempCurrent[index]
        tempThreshold = device.cpqRackCommonEnclosureTempThreshold[index]
        tempCondition = device.cpqRackCommonEnclosureTempCondition[index]
        
        current_check = "Temperature"
        if str(tempCondition) not in allowed_condition:
            failed += 1
            msg = 'Error for {0} Sensor: Condition = {1}; Location = {2}; Current = {3}; Threshold = {4}; Serial = {5}'.format(current_check,tempCondition,tempLocation,tempCurrent,tempThreshold,tempSerial)
            incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
            logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
        else:
            ok += 1
            msg = 'OK for {0} Sensor: Condition = {1}; Location = {2}; Current = {3}; Threshold = {4}; Serial = {5}'.format(current_check,tempCondition,tempLocation,tempCurrent,tempThreshold,tempSerial)
            logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)

        #print 'TEMP: {0} - {1} - {2} - {3} - {4}'.format(tempSerial,tempLocation,tempCurrent,tempThreshold,tempCondition)
    return total,ok,failed

def queryPower(device,host):
    total,ok,failed = 0,0,0
    for index in device.cpqRackPowerSupplyIndex:
        total += 1
        allowed_condition = ['ok(2)']
        allowed_status = ['noError(1)']
        allowed_line_status = ['noError(1)']
        powerPosition = device.cpqRackPowerSupplyPosition[index]
        powerStatus = device.cpqRackPowerSupplyStatus[index]
        powerInputLineStatus = device.cpqRackPowerSupplyInputLineStatus[index]
        powerPresent = device.cpqRackPowerSupplyPresent[index]
        powerCondition = device.cpqRackPowerSupplyCondition[index]
        powerEnclosureSerialNum = device.cpqRackPowerSupplyEnclosureSerialNum[index]
        powerSerialNum = device.cpqRackPowerSupplySerialNum[index]
        powerPartNumber = device.cpqRackPowerSupplyPartNumber[index]
        powerSparePartNumber = device.cpqRackPowerSupplySparePartNumber[index]
        
        current_check = "PowerSupply"
        if (str(powerCondition) not in allowed_condition) or (str(powerStatus) not in allowed_status) or (str(powerInputLineStatus) not in allowed_line_status):
            failed += 1
            msg = 'Error for {0} Sensor: Condition = {1}; Status = {2}; InputLineStatus = {3}; Present = {4}; EnclosureSerial = {5}; Serial = {6}; PartNumber = {7}; SparePartNumber = {8}'.format(current_check,powerCondition,powerStatus,powerInputLineStatus,powerPresent,powerEnclosureSerialNum,powerSerialNum,powerPartNumber,powerSparePartNumber)
            incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
            logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
        else:
            ok += 1
            msg = 'OK for {0} Sensor: Condition = {1}; Status = {2}; InputLineStatus = {3}; Present = {4}; EnclosureSerial = {5}; Serial = {6}; PartNumber = {7}; SparePartNumber = {8}'.format(current_check,powerCondition,powerStatus,powerInputLineStatus,powerPresent,powerEnclosureSerialNum,powerSerialNum,powerPartNumber,powerSparePartNumber)
            logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)

        #print 'POWER: {0} - {1} - {2} - {3} - {4} - {5} - {6} - {7} - {8}'.format(powerPosition,powerStatus,    powerInputLineStatus,   powerPresent,   powerCondition, powerEnclosureSerialNum,    powerSerialNum, powerPartNumber,    powerSparePartNumber)
    return total,ok,failed

def queryEnclosure(device,host,any_alarm):
    total,ok,failed = 0,0,0
    for index in device.cpqRackCommonEnclosureIndex:
        total += 1
        allowed_condition = ['ok(2)']
        enclosureCondition = device.cpqRackCommonEnclosureCondition[index]
        enclosureModel = device.cpqRackCommonEnclosureModel[index]
        enclosurePartNumber = device.cpqRackCommonEnclosurePartNumber[index]
        enclosureSparePartNumber = device.cpqRackCommonEnclosureSparePartNumber[index]
        enclosureSerialNum = device.cpqRackCommonEnclosureSerialNum[index]
        enclosureFWRev = device.cpqRackCommonEnclosureFWRev[index]
        enclosureName = device.cpqRackCommonEnclosureName[index]
        
        current_check = "Enclosure"
        if str(enclosureCondition) not in allowed_condition:
            failed += 1
            msg = 'Error for {0} Sensor: Condition = {1}; Name = {2}; Model = {3}; Serial = {4}; PartNumber = {5}; SparePartNumber = {6}; FirmwareRev = {7}'.format(current_check,enclosureCondition,enclosureName,enclosureModel,enclosureSerialNum,enclosurePartNumber,enclosureSparePartNumber,enclosureFWRev)
            logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            if any_alarm == False:
                incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
            else:
                logging.warning('{0}\tNot generating Enclosure alarm because we already generated alarm for this device. This prevents creating redundant alarms for the same issue.'.format(host))
        else:
            ok += 1
            msg = 'OK for {0} Sensor: Condition = {1}; Name = {2}; Model = {3}; Serial = {4}; PartNumber = {5}; SparePartNumber = {6}; FirmwareRev = {7}'.format(current_check,enclosureCondition,enclosureName,enclosureModel,enclosureSerialNum,enclosurePartNumber,enclosureSparePartNumber,enclosureFWRev)
            logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)
        
        #print 'ENCLOSURE: {0} - {1} - {2} - {3} - {4} - {5} - {6}'.format(enclosureCondition,enclosureModel,enclosurePartNumber,enclosureSparePartNumber,enclosureSerialNum,enclosureFWRev,enclosureName)
    return total,ok,failed

def queryEnclosureManager(device,host):
    total,ok,failed = 0,0,0
    for index in device.cpqRackCommonEnclosureManagerIndex:
        total += 1
        allowed_condition = ['ok(2)']
        managerPresent = device.cpqRackCommonEnclosureManagerPresent[index]
        managerRedundant = device.cpqRackCommonEnclosureManagerRedundant[index]
        managerCondition = device.cpqRackCommonEnclosureManagerCondition[index]
        managerEnclosureSerialNum = device.cpqRackCommonEnclosureManagerEnclosureSerialNum[index]
        managerFWRev = device.cpqRackCommonEnclosureManagerFWRev[index]
        managerEnclosureName = device.cpqRackCommonEnclosureManagerEnclosureName[index]
        managerPartNumber = device.cpqRackCommonEnclosureManagerPartNumber[index]
        managerSparePartNumber = device.cpqRackCommonEnclosureManagerSparePartNumber[index]
        managerSerialNum = device.cpqRackCommonEnclosureManagerSerialNum[index]
        managerRole = device.cpqRackCommonEnclosureManagerRole[index]
        
        current_check = "EnclosureManager"
        if str(managerCondition) not in allowed_condition:
            failed += 1
            msg = 'Error for {0} Sensor: Condition = {1}; Role = {2}; Redundant = {3}; EnclosureSerial = {4}; Serial = {5}; PartNumber = {6}; SparePartNumber = {7}; FirmwareRev = {8}'.format(current_check,managerCondition, managerRole, managerRedundant, managerEnclosureSerialNum, managerSerialNum, managerPartNumber, managerSparePartNumber, managerFWRev)
            incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
            logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
        else:
            ok += 1
            msg = 'OK for {0} Sensor: Condition = {1}; Role = {2}; Redundant = {3}; EnclosureSerial = {4}; Serial = {5}; PartNumber = {6}; SparePartNumber = {7}; FirmwareRev = {8}'.format(current_check,managerCondition, managerRole, managerRedundant, managerEnclosureSerialNum, managerSerialNum, managerPartNumber, managerSparePartNumber, managerFWRev)
            logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)
        
        #print 'MANAGER: {0} - {1} - {2} - {3} - {4} - {5} - {6} - {7} - {8} - {9}'.format(managerPresent,managerRedundant,managerCondition,managerEnclosureSerialNum,managerFWRev,managerEnclosureName,managerPartNumber,managerSparePartNumber,managerSerialNum,managerRole)
    return total,ok,failed

def queryPowerEnclosure(device,host,psu_alarm):
    total,ok,failed = 0,0,0
    for index in device.cpqRackPowerEnclosureIndex:
        total += 1
        allowed_condition = ['ok(2)']
        powerEncName = device.cpqRackPowerEnclosureName[index]
        powerEncMgmtBoardSerialNum = device.cpqRackPowerEnclosureMgmtBoardSerialNum[index]
        powerEncRedundant = device.cpqRackPowerEnclosureRedundant[index]
        powerEncLoadBalanced = device.cpqRackPowerEnclosureLoadBalanced[index]
        powerEncCondition = device.cpqRackPowerEnclosureCondition[index]
        
        current_check = "PowerEnclosure"
        if str(powerEncCondition) not in allowed_condition:
            failed += 1
            msg = 'Error for {0} Sensor: Condition = {1}; Name = {2}; Redundant = {3}; LoadBalanced = {4}; MgmtBoardSerial = {5}'.format(current_check, powerEncCondition, powerEncName,powerEncRedundant, powerEncLoadBalanced, powerEncMgmtBoardSerialNum)
            logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            if psu_alarm == False:
                incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
            else:
                logging.warning('{0}\tNot generating Power Enclosure alarm because we already generated alarm for a power supply. This prevents creating redundant alarms for the same issue.'.format(host))
        else:
            ok += 1
            msg = 'OK for {0} Sensor: Condition = {1}; Name = {2}; Redundant = {3}; LoadBalanced = {4}; MgmtBoardSerial = {5}'.format(current_check, powerEncCondition, powerEncName,powerEncRedundant, powerEncLoadBalanced, powerEncMgmtBoardSerialNum)
            logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)
       
        #print 'PWR ENCLOSURE: {0} - {1} - {2} - {3} - {4}'.format(powerEncName,powerEncMgmtBoardSerialNum,powerEncRedundant,powerEncLoadBalanced,powerEncCondition) 
    return total,ok,failed

def queryBlades(device,host):
    total,ok,failed = 0,0,0
    for index in device.cpqRackServerBladeIndex:
        allowed_status = ['ok(2)']
        bladePresent = device.cpqRackServerBladePresent[index]
        bladeName = device.cpqRackServerBladeName[index]
        bladeStatus = device.cpqRackServerBladeStatus[index]
        bladeFaultMinor = device.cpqRackServerBladeFaultMinor[index]
        bladeFaultMajor = device.cpqRackServerBladeFaultMajor[index]
        bladeFaultString = device.cpqRackServerBladeFaultDiagnosticString[index]
        bladeSerial = device.cpqRackServerBladeSerialNum[index]
        bladeProductID = device.cpqRackServerBladeProductId[index]
        bladePartNum = device.cpqRackServerBladePartNumber[index]
        bladeSparePartNum = device.cpqRackServerBladeSparePartNumber[index]

        if str(bladePresent) == 'present(3)':
            total += 1
            current_check = "Blade"
            if str(bladeStatus) not in allowed_status:
                failed += 1
                msg = 'Error for {0} Sensor: Status = {1}; Name = {2}; MinorFault = {3}; MajorFault = {4}; FaultDiagString = {5}; Serial = {6}; ProductId = {7}; PartNumber = {8}; SparePartNumber = {9}'.format(current_check, bladeStatus, bladeName, bladeFaultMinor, bladeFaultMajor, bladeFaultString, bladeSerial, bladeProductID, bladePartNum, bladeSparePartNum)
                incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
                logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            else:
                ok += 1
                msg = 'OK for {0} Sensor: Status = {1}; Name = {2}; MinorFault = {3}; MajorFault = {4}; FaultDiagString = {5}; Serial = {6}; ProductId = {7}; PartNumber = {8}; SparePartNumber = {9}'.format(current_check, bladeStatus, bladeName, bladeFaultMinor, bladeFaultMajor, bladeFaultString, bladeSerial, bladeProductID, bladePartNum, bladeSparePartNum)
                logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
                sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)
            
            #print 'BLADE: {0} - {1} - {2} - {3} - {4} - {5} - {6} - {7} - {8} - {9} - {10}'.format(host,bladePresent,bladeName,bladeStatus,bladeFaultMinor,bladeFaultMajor,bladeFaultString,bladeSerial,bladeProductID,bladePartNum,bladeSparePartNum)
    return total,ok,failed

def queryDevice(hostname,comm,ver):
    global deviceCount

    #Connect to device
    try:
        device = M(host=hostname,community=comm,version=ver,timeout=30,retries=1)
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
    deviceResults = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    psu_alarm = False
    any_alarm = False

    #Perform checks, load results into list

    next_check = "queryFans"
    try:
        deviceResults[0:3] = queryFans(device,hostname)
        if deviceResults[2] > 0: any_alarm = True
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

    next_check = "queryTemp"
    try:
        deviceResults[3:6] = queryTemp(device,hostname)
        if deviceResults[5] > 0: any_alarm = True
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))
   
    next_check = "queryPower"
    try:
        deviceResults[6:9] = queryPower(device,hostname)
        if deviceResults[8] > 0: psu_alarm, any_alarm = True, True
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

    next_check = "queryEnclosureManager"
    try:
        deviceResults[12:15] = queryEnclosureManager(device,hostname)
        if deviceResults[14] > 0: any_alarm = True
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

    next_check = "queryPowerEnclosure"
    try:
        deviceResults[15:18] = queryPowerEnclosure(device,hostname,psu_alarm)
        if deviceResults[17] > 0: any_alarm = True
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))    
    
    next_check = "queryBlades"
    try:
        deviceResults[18:21] = queryBlades(device,hostname)
        if deviceResults[20] > 0: any_alarm = True
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))
   
    next_check = "queryEnclosure"
    try:
        deviceResults[9:12] = queryEnclosure(device,hostname,any_alarm)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

    for i in range(len(totalStats)):
        totalStats[i]+=deviceResults[i]
    logging.info('{0}\tSTATS\t(Checked,OK,Error) || Fan({1},{2},{3}) || Temp({4},{5},{6}) || PSU({7},{8},{9}) || Enclosure({10},{11},{12}) || Mgr({13},{14},{15}) || PowerEnc({16},{17},{18}) || Blades({19},{20},{21}))'.format(hostname,*deviceResults))

def main():
    logging.info('***************************************************************************')
    logging.info('Starting Script')
    deviceCount = 0

    #Prepare stats file
    touch(docroot + 'hp_blade_snmp_exclusions')

    #Load required MIBs
    load(docroot + "mibs/SNMPv2-MIB")
    load(docroot + "mibs/CPQHOST.MIB")
    #We need to use a customized CPQRACK-MIB (cpqrack_spot.mib) because of issues in the official MIB. 
    #This script will only work with this version of the MIB. Some unused indices needed
    #to be removed from some object definitions. See https://github.com/vincentbernat/snimpy/issues/12
    #for details.
    load(docroot + "mibs/cpqrack_spot.mib")

    #Check PagerDuty for open incidents
    try:
        getCurrentAlarms()
    except Exception as inst:
        msg = 'Exception occurred while querying PagerDuty for open incidents; Exception = "{0}"'.format(inst)
        logging.warning('PAGER\tERROR\r{0}'.format(msg))

    script_start = time.time()
    try:
        deviceFile = open(docroot+'device_list','r')
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

    logging.info('TOTAL\tSTATS\t(Checked,OK,Error) || Fan({1},{2},{3}) || Temp({4},{5},{6}) || PSU({7},{8},{9}) || Enclosure({10},{11},{12}) || Mgr({13},{14},{15}) || PowerEnc({16},{17},{18}) || Blades({19},{20},{21})|| Devices({0})'.format(deviceCount,*totalStats))
    logging.info('Script Complete')


if __name__ == "__main__":
    main()
