#!/usr/bin/env python
from snimpy.manager import Manager as M
from snimpy.manager import load
import argparse
import socket
import time
import logging
import subprocess
import datetime
from collections import defaultdict
import os
import pygerduty

#SET LOGGING INFO
if not os.path.exists('/var/log/snmp_monitoring/'):
    os.mkdir('/var/log/snmp_monitoring/')
logging.basicConfig(filename='/var/log/snmp_monitoring/check_arista_hw.log',format='%(asctime)s: %(levelname)s: %(message)s',level=logging.INFO)
docroot = "/opt/spot/snmp_monitoring/check_arista/"

#COUNTERS
totalStats = [0,0,0,0,0,0,0,0,0,0,0,0]
deviceCount = 0

#SET GRAPHITE INFO
CARBON_SERVER = '{{ salt['pillar.get']('globals:haproxy') }}'
CARBON_PORT = 2003

def sendToGraphite(path, value):
    timestamp = int(time.time())
    message = '%s %s %d\n' % (path, value, timestamp)

    #print 'DEBUG	GRAPH	{0}'.format(message.strip())
    sock = socket.socket()
    sock.connect((CARBON_SERVER, CARBON_PORT))
    sock.sendall(message)
    sock.close()
    return;

def sendToPagerDuty(type,key,desc,det):
    #print 'Send to PD: {0}; {1}; {2}; {3}'.format(type,key,desc,det)
    SPOT_API_TOKEN="<Your PagerDuty API token>"
    SERVICE_API_TOKEN="Your PagerDuty service API token"
    pager = pygerduty.PagerDuty(api_token=SPOT_API_TOKEN)
    if type == "trigger":
        if checkForExclusion(key) is False:
            incident = pager.trigger_incident(service_key=SERVICE_API_TOKEN, incident_key=key, description=desc, details=det)
            writeToFile(key)
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

def writeToFile(key):
    with open(docroot+'arista_snmp_alarms_current','a') as f:
        f.write('{0}\n'.format(key))

def checkForAlarm(key):
    result = False
    with open(docroot+'arista_snmp_alarms_previous','r') as f:
        for line in f:
            if line[:-1] == key:
                result = True
                return result
    return result

def logPreviousAlarms():
    logging.info('PREVIOUS ALARMS\tPrinting previous alarms from file')
    with open(docroot+'arista_snmp_alarms_previous','r') as f:
        for line in f:
            logging.info('PREVIOUS ALARMS\t{0}'.format(line))
    logging.info('PREVIOUS ALARMS\tOutput complete')

def checkForExclusion(key):
    result = False
    with open(docroot+'arista_snmp_exclusions','r') as f:
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

def querySensors(device,hostname):
    # define counters for reporting stats
    t_total,t_ok,t_failed = 0,0,0
    p_total,p_ok,p_failed = 0,0,0
    f_total,f_ok,f_failed = 0,0,0
    o_total,o_ok,o_failed = 0,0,0

    # loop through sensors, determine type, process
    for index in device.entPhySensorType:
        name = str(device.entPhysicalDescr[index])
        type = str(device.entPhySensorType[index])
        value = device.entPhySensorValue[index]
        status = str(device.entPhySensorOperStatus[index])
        unit = str(device.entPhySensorUnitsDisplay[index])

        # Send values to graphite
        graphite_sensor = name.replace(' ','_')
        path = 'network.arista.{0}.{1}.{2}'.format(unit,hostname,graphite_sensor)
        graphite_value = value
        if unit == 'Celsius':
            graphite_value = graphite_value / 10
        sendToGraphite(path,graphite_value)

        if unit == 'Celsius':
            t_total += 1
            value = value/10
            threshold = 'UNDEFINED'
            if name == "Rear temp sensor": threshold = 31
            if name == "Fan controller 1 sensor": threshold = 31
            allowed_status = ['ok(1)']
            if (status not in allowed_status) or ((threshold != 'UNDEFINED') and (value >= threshold)):
                t_failed +=1
                msg = 'Error for Temperature Sensor({0}): Value = {1} {2}; Threshold = {3}; OperStatus = {4}; ID = {5}'.format(name,value,unit,threshold,status,index)
                logging.warning('{0}\tTEMP\t{1}'.format(hostname,msg))
                sendToPagerDuty("trigger","snmp/temperature/{0}/{1}".format(hostname,index),"Temperature issue detected on {0}".format(hostname),msg)
            else:
                t_ok +=1
                msg = 'OK for Temperature Sensor({0}): Value = {1} {2}; Threshold = {3}; OperStatus = {4}; ID = {5}'.format(name,value,unit,threshold,status,index)
                logging.debug('{0}\tTEMP\t{1}'.format(hostname,msg))
                sendToPagerDuty("resolve","snmp/temperature/{0}/{1}".format(hostname,index),"No issues detected",msg)
        elif unit == "Amperes":
            p_total +=1
            threshold = 'UNDEFINED'
            allowed_status = ['ok(1)']
            if (status not in allowed_status) or ((threshold != 'UNDEFINED') and (value >= threshold)):
                p_failed += 1
                msg = 'Error for Power Sensor({0}): Value = {1} {2}; Threshold = {3}; OperStatus = {4}; ID = {5}'.format(name,value,unit,threshold,status,index)
                logging.warning('{0}\tPSU\t{1}'.format(hostname,msg))
                sendToPagerDuty("trigger","snmp/power/amps/{0}/{1}".format(hostname,index),"Power issue detected on {0}".format(hostname),msg)
            else:
                p_ok +=1
                msg = 'OK for Power Sensor({0}): Value = {1} {2}; Threshold = {3}; OperStatus = {4}; ID = {5}'.format(name,value,unit,threshold,status,index)
                logging.debug('{0}\tPSU\t{1}'.format(hostname,msg))
                sendToPagerDuty("resolve","snmp/power/amps/{0}/{1}".format(hostname,index),"No issues detected",msg)
        elif unit == "Volts":
            p_total +=1
            threshold = 'UNDEFINED'
            allowed_status = ['ok(1)']
            if (status not in allowed_status) or ((threshold != 'UNDEFINED') and (value >= threshold)):
                p_failed += 1
                msg = 'Error for Power Sensor({0}): Value = {1} {2}; Threshold = {3}; OperStatus = {4}; ID = {5}'.format(name,value,unit,threshold,status,index)
                logging.warning('{0}\tPSU\t{1}'.format(hostname,msg))
                sendToPagerDuty("trigger","snmp/power/volts/{0}/{1}".format(hostname,index),"Power issue detected on {0}".format(hostname),msg)
            else:
                p_ok +=1
                msg = 'OK for Power Sensor({0}): Value = {1} {2}; Threshold = {3}; OperStatus = {4}; ID = {5}'.format(name,value,unit,threshold,status,index)
                logging.debug('{0}\tPSU\t{1}'.format(hostname,msg))
                sendToPagerDuty("resolve","snmp/power/volts/{0}/{1}".format(hostname,index),"No issues detected",msg)
        elif unit == "RPM":
            f_total +=1
            threshold = 'UNDEFINED'
            allowed_status = ['ok(1)']
            if (status not in allowed_status) or ((threshold != 'UNDEFINED') and (value >= threshold)):
                f_failed += 1
                msg = 'Error for Fan Sensor({0}): Value = {1} {2}; Threshold = {3}; OperStatus = {4}; ID = {5}'.format(name,value,unit,threshold,status,index)
                logging.warning('{0}\tFAN\t{1}'.format(hostname,msg))
                sendToPagerDuty("trigger","snmp/fan/{0}/{1}".format(hostname,index),"Fan issue detected on {0}".format(hostname),msg)
            else:
                f_ok +=1
                msg = 'OK for Fan Sensor({0}): Value = {1} {2}; Threshold = {3}; OperStatus = {4}; ID = {5}'.format(name,value,unit,threshold,status,index)
                logging.debug('{0}\tFAN\t{1}'.format(hostname,msg))
                sendToPagerDuty("resolve","snmp/fan/{0}/{1}".format(hostname,index),"No issues detected",msg)
        else:
            o_total +=1
            allowed_status = ['ok(1)']
            if status not in allowed_status:
                o_failed += 1
                msg = 'Error for Sensor({0}): Value = {1} {2}; OperStatus = {3}; ID = {4}'.format(name,value,unit,status,index)
                logging.warning('{0}\tOTHER\t{1}'.format(hostname,msg))
                sendToPagerDuty("trigger","snmp/other/{0}/{1}".format(hostname,index),"Sensor issue detected on {0}".format(hostname),msg)
            else:
                o_ok +=1
                msg = 'OK for Sensor({0}): Value = {1} {2}; OperStatus = {3}; ID = {4}'.format(name,value,unit,status,index)
                logging.debug('{0}\tOTHER\t{1}'.format(hostname,msg))
                sendToPagerDuty("resolve","snmp/other/{0}/{1}".format(hostname,index),"No issues detected",msg)

    return t_total,t_ok,t_failed,p_total,p_ok,p_failed,f_total,f_ok,f_failed,o_total,o_ok,o_failed

def queryDevice(hostname,comm,ver):
    global deviceCount
    #Connect to device
    try:
        device = M(host=hostname,community=comm,version=ver,timeout=5,retries=3)
        desc = device.sysDescr
        msg = 'Successfully connected to {0}.'.format(hostname)
        sendToPagerDuty("resolve","snmp/connect/{0}".format(hostname),"SNMP agent is responding on {0}".format(hostname),msg)
    except Exception as inst:
        msg = 'Exception occurred while connecting to {0}. Exception = "{1}"'.format(hostname,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,inst))
        t = datetime.datetime.now().timetuple()
        #only generate alarm during the day
        if (t[3]>=7) and (t[3]<=19):
            print 'sending alarm...'
            incident = sendToPagerDuty("trigger","snmp/connect/{0}".format(hostname),"Unable to query SNMP on {0}".format(hostname),msg)
        return

    deviceCount += 1
    deviceResults = [0,0,0,0,0,0,0,0,0,0,0,0]
    #Perform checks, load results into list
    next_check = "querySensors"
    try:
        deviceResults[0:11] = querySensors(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

    logging.info('{0}\tSTATS\t(Checked,OK,Error) || Temp({1},{2},{3}) || PSU({4},{5},{6}) || FAN({7},{8},{9}) || Other({10},{11},{12})'.format(hostname,*deviceResults))
    for i in range(len(totalStats)):
        totalStats[i]+=deviceResults[i]

def main():
    logging.info('***************************************************************************')
    logging.info('Starting Script')

    #Prepare stats file
    touch(docroot + 'arista_snmp_alarms_current')
    touch(docroot + 'arista_snmp_exclusions')
    os.rename(docroot+'arista_snmp_alarms_current',docroot+'arista_snmp_alarms_previous')
    touch(docroot + 'arista_snmp_alarms_current')

    #Parse previous alarms file and output to log file for debugging
    try:
        logPreviousAlarms()
    except Exception as inst:
        msg = 'Exception occurred while parsing previous alarms file. Exception: {0}'.format(inst)
        logging.warning(msg)

    #Load required MIBs
    load(docroot + "mibs/ENTITY-MIB.my")
    load(docroot + "mibs/SNMPv2-MIB")
    load(docroot + "mibs/ENTITY-SENSOR-MIB.my")
    load(docroot + "mibs/ARISTA-SMI-MIB.mib")
    load(docroot + "mibs/ARISTA-ENTITY-SENSOR.txt")

    script_start = time.time()
    try:
        deviceFile = open(docroot+'arista_devices','r')
        comm = "public"
        ver = 2
        for line in deviceFile:
            if line[0:1] != "#":
                start = time.time()
                hostname = line[:-1]
                queryDevice(hostname,comm,ver)
                end = time.time()
                print '{0} - {1} - {2} sec. {3} total sec.'.format(deviceCount,hostname,(end-start),(end-script_start))
    except Exception as inst:
        msg = 'Exception occurred in main function. Exception = "{0}"'.format(inst)
        logging.warning('MAIN\tERROR\t{0}'.format(msg))

    logging.info('TOTAL\tSTATS\t(Checked,OK,Error) || Temp({1},{2},{3}) || PSU({4},{5},{6}) || FAN({7},{8},{9}) || Other({10},{11},{12}) || Devices({0})'.format(deviceCount,*totalStats))
    logging.info('Script Complete')


if __name__ == "__main__":
    main()
