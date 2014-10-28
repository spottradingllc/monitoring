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
import shutil

"""
========
OVERVIEW
========

This script monitors server hardware for all nPulse devices. It replaces the monitoring previously performed by Nimsoft SNMPget. 

The script uses the following process:
    1. Check textfile for exclusions
    2. Load MIBs
    3. Check PagerDuty for open incidents
    4. Query Devices

=======
DETAILS
=======

1. Check textfile for exclusions: Exclusions can be added to the snmp_exclusions file. 
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

4. Query Devices: The script loops through the list defined in the Main function and goes through the following process:
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
logging.basicConfig(filename='/var/log/snmp_monitoring/check_npulse.log',format='%(asctime)s: %(levelname)s: %(message)s',level=logging.DEBUG)
docroot = "/opt/spot/snmp_monitoring/check_npulse/"
open_alarms = []

#COUNTERS
totalStats = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
deviceCount = 0
open_alarms = []

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
    with open(docroot+'npulse_exclusions','r') as f:
        for line in f:
            if line[:-1] == key:
                result = True
                return result
    return result

def writeStats(host,stats):
    filename = '{0}current_stats_{1}'.format(docroot,host) 
    f = open(filename,'a')
    for key, value in stats.iteritems():
        if value != 'NOT FOUND':
            f.write('{0}:{1}:{2}\n'.format(host,key,value))
    f.close()

def getPrevious(host,stat):
    filename = '{0}previous_stats_{1}'.format(docroot,host)
    f = open(filename,'r')
    for line in f:
        hostname,metric,value = line.split(':')
        if (hostname==host) and (stat==metric):
            return int(value)
    return 0

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
    for index in device.fanNumber:
        total += 1
        allowed_status = ['ok(1)','unknown(0)']
        fanRpms = device.fanRpms[index]
        fanStatus = device.fanStatus[index]
        fanNumber = device.fanNumber[index]
        details = 'Status = {0}; RPMs = {1}; Number = {2}'.format(fanStatus, fanRpms, fanNumber)

        current_check = "Fan"
        if str(fanStatus) not in allowed_status:
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

def querySystemDisks(device,host):
    total,ok,failed = 0,0,0
    #Discover number of channels (required because something is screwed up in the npulse MIBs)
    run = True
    counter = 1
    while run == True:
        try:
            test = device.systemDiskName[counter]
            counter += 1
        except Exception as inst:
            #print '{0} instances detected'.format(str(counter-1))
            run = False

    for index in range(1,counter):
        total += 1
        allowed_status = ['healthy(1)']
        diskName = device.systemDiskName[index]
        diskHealth = device.systemDiskHealth[index]
        diskSerial = device.systemDiskSerial[index]
        details = 'Name = {0}; Health = {1}; Serial = {2}'.format(diskName, diskHealth, diskSerial)
        
        current_check = "SystemDisk"
        if str(diskHealth) not in allowed_status:
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

# This function requires that you pass a list of channels to monitor. This is specified in the Main function. 
def queryChannels(device,host,channels):
    total,ok,failed = 0,0,0
    
    #Discover number of channels (required because something is screwed up in the npulse MIBs)
    run = True
    counter = 1
    while run == True:
        try:
            test = device.channelNumber[counter]
            counter += 1
        except Exception as inst:
            #print '{0} instances detected'.format(str(counter-1))   
            run = False

    for index in range(1,counter):
        total += 1
        allowed_status = ['linkUp(1)']
        channelNumber = device.channelNumber[index]
        channelLink = device.channelLink[index]
        channelDrops = device.channelDrops[index]
        channelErrors = device.channelErrors[index]
        details = 'Number = {0}; Link = {1}; Drops = {2}; Errors = {3}'.format(channelNumber, channelLink, channelDrops, channelErrors)
        
        current_check = "ChannelLink"

        # Only process channels we care about
        if str(channelNumber) in channels:
            # Write number of drops to file
            writeStats(host,{"Channel {0} Drops".format(channelNumber):channelDrops})       
 
            # Check for channel status
            if str(channelLink) not in allowed_status:
                failed += 1
                msg = 'ERROR: {0} Check: {1}'.format(current_check, details)
                incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
                logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            else:
                ok += 1
                msg = 'OK: {0} Check: {1}'.format(current_check, details)
                logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
                sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)   
            # Check for channel drops
            prevChannelDrops = getPrevious(host,'Channel {0} Drops'.format(channelNumber))
            delta = channelDrops - prevChannelDrops
            if delta > 0:
                msg = 'ERROR: Channel drop(s) detected on {0}. Drops have increased by {1} on Channel {2}. Current:{3}; Previous:{4}'.format(host, delta, channelNumber, channelDrops, prevChannelDrops)
                logging.warning('{0}\t{1}\t{2}'.format(host,'DROPS',msg))
                incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"Channel drops detected on {0}".format(host,),msg)
            else:
                msg = 'OK: No channel drops detected on {0}. Drops have increased by {1} on Channel {2}. Current:{3}; Previous:{4}'.format(host, delta, channelNumber, channelDrops, prevChannelDrops)
                logging.debug('{0}\t{1}\t{2}'.format(host,'DROPS',msg))
                sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No channel drops detected",msg)

    return total,ok,failed

def queryRaid(device,host):
    c_total,c_ok,c_failed = 0,0,0 #controllers
    d_total,d_ok,d_failed = 0,0,0 #disks
    v_total,v_ok,v_failed = 0,0,0 #volumes
    
    #CONTROLLERS
    #Discover number of instances (required because something is screwed up in the npulse MIBs)
    run = True
    counter = 1
    while run == True:
        try:
            test = device.raidControllerIndex[counter]
            counter += 1
        except Exception as inst:
            #print '{0} instances detected'.format(str(counter-1))
            run = False   
  
    for index in range(1,counter):
        c_total+=1
        allowed_status = ['optimal(1)']
        contIndex = device.raidControllerIndex[index]
        contStatus = device.raidControllerStatus[index]
        contTemperature = device.raidControllerTemperature[index]
        contSerial = device.raidControllerSerial[index]
        details = 'Index = {0}; Status = {1}; Temperature = {2}; Serial = {3}'.format(contIndex, contStatus, contTemperature, contSerial)
        
        current_check = "RaidController"
        if str(contStatus) not in allowed_status:
            c_failed += 1
            msg = 'ERROR: {0} Check: {1}'.format(current_check, details)
            incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
            logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
        else:
            c_ok += 1
            msg = 'OK: {0} Check: {1}'.format(current_check, details)
            logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)      

    #DISKS
    #Discover number of instances (required because something is screwed up in the npulse MIBs)
    run = True
    counter = 1
    while run == True:
        try:
            test = device.raidDiskController[counter]
            counter += 1
        except Exception as inst:
            #print '{0} instances detected'.format(str(counter-1))
            run = False

    for index in range(1,counter):
        d_total+=1
        allowed_state = ['Online']
        allowed_smart_status = ['healthy(1)']
        diskState = device.raidDiskState[index]
        diskSmartStatus = device.raidDiskSmartStatus[index]
        diskSerial = device.raidDiskSerialNumber[index]
        details = 'State = {0}; SmartStatus = {1}; Serial = {2}'.format(diskState, diskSmartStatus, diskSerial)
        
        current_check = "RaidDisk"
        if (str(diskState) not in allowed_state) or (str(diskSmartStatus) not in allowed_smart_status):
            d_failed += 1
            msg = 'ERROR: {0} Check: {1}'.format(current_check, details)
            incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
            logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
        else:
            d_ok += 1
            msg = 'OK: {0} Check: {1}'.format(current_check, details)
            logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)  
    
    #VOLUMES
    #Discover number of instances (required because something is screwed up in the npulse MIBs)
    run = True
    counter = 1
    while run == True:
        try:
            test = device.raidVolumeController[counter]
            counter += 1
        except Exception as inst:
            #print '{0} instances detected'.format(str(counter-1))
            run = False

    for index in range(1,counter):
        v_total+=1
        allowed_status = ['Optimal']
        volName = device.raidVolumeName[index]
        volLevel = device.raidVolumeLevel[index]
        volStatus = device.raidVolumeStatus[index]
        volSize = device.raidVolumeSize[index]
        details = 'Name = {0}; Status = {1}; Level = {2}; Size = {3}'.format(volName, volStatus, volLevel, volSize)
        
        current_check = "RaidVolume"
        if str(volStatus) not in allowed_status:
            v_failed += 1
            msg = 'ERROR: {0} Check: {1}'.format(current_check, details)
            incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
            logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
        else:
            v_ok += 1
            msg = 'OK: {0} Check: {1}'.format(current_check, details)
            logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)  

    return c_total,c_ok,c_failed,d_total,d_ok,d_failed,v_total,v_ok,v_failed

def queryDevice(hostname,comm,ver,channels):
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
    deviceResults = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

    #Create stats file (for calculating deltas)
    current = '{0}current_stats_{1}'.format(docroot,hostname)
    previous = '{0}previous_stats_{1}'.format(docroot,hostname)
    touch(current)
    touch(previous)

    #Perform checks, load results into list

    next_check = "queryFans"
    try:
        deviceResults[0:3] = queryFans(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))
    
    next_check = "queryChannels"
    try:
        deviceResults[3:6] = queryChannels(device,hostname,channels)
        os.rename(current,previous)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg)) 
    
    next_check = "queryRaid"
    try:
        deviceResults[6:15] = queryRaid(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))   
 
    next_check = "querySystemDisks"
    try:
        deviceResults[15:18] = querySystemDisks(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

    for i in range(len(totalStats)):
        totalStats[i]+=deviceResults[i]
    logging.info('{0}\tSTATS\t(Checked,OK,Error) || Fan({1},{2},{3}) || Channel({4},{5},{6}) || Ctrlr({7},{8},{9}) || Disk({10},{11},{12}) || Volume({13},{14},{15}) || SysDisk ({16},{17},{18})'.format(hostname,*deviceResults))

def main():
    logging.info('***************************************************************************')
    logging.info('Starting Script')
    deviceCount = 0

    #Prepare stats file
    touch(docroot + 'npulse_exclusions')

    #Load required MIBs
    load(docroot + "mibs/SNMPv2-MIB")
    load(docroot + "mibs/NET-SNMP-MIB.txt")
    load(docroot + "mibs/NET-SNMP-TC.txt")
    load(docroot + "mibs/NPULSE-MIB.dat")
    # Using modified version of npulse mib because the official version has issues and will not work with snimpy.
    load(docroot + "mibs/NPULSE-HAMMERHEAD-MIB-SPOT.my")

    #Check PagerDuty for open incidents
    try:
        getCurrentAlarms()
    except Exception as inst:
        msg = 'Exception occurred while querying PagerDuty for open incidents; Exception = "{0}"'.format(inst)
        logging.warning('PAGER\tERROR\r{0}'.format(msg))

    script_start = time.time()
    try:
        #define hosts and channels to monitor on each host
        deviceList = {'cme-npulse':['0','1','2','3'], 
                      'mahnpulse01':['0','1'], 
                      'nsdnpulse01':['0','1','2'], 
                      'ny4npulse02':['0','1','2','3']}
        comm = "public"
        ver = 2
        for device,channels in deviceList.iteritems():
            if device[0:1] != "#":
                deviceCount += 1
                start = time.time()
                hostname = device
                queryDevice(hostname,comm,ver,channels)
                end = time.time()
                print '{0} - {1} - {2} sec. {3} total sec.'.format(deviceCount,hostname,(end-start),(end-script_start))
    except Exception as inst:
        msg = 'Exception occurred in main function. Exception = "{0}"'.format(inst)
        logging.warning('MAIN\tERROR\t{0}'.format(msg))

    logging.info('TOTAL\tSTATS\t(Checked,OK,Error) || Fan({1},{2},{3}) || Channel({4},{5},{6}) || Ctrlr({7},{8},{9}) || Disk({10},{11},{12}) || Volume({13},{14},{15}) || SysDisk ({16},{17},{18}) || Devices({0})'.format(deviceCount,*totalStats))
    logging.info('Script Complete')


if __name__ == "__main__":
    main()
