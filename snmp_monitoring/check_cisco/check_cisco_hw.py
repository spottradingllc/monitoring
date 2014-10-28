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

#SET LOGGING INFO
if not os.path.exists('/var/log/snmp_monitoring/'):
    os.mkdir('/var/log/snmp_monitoring/')
logging.basicConfig(filename='/var/log/snmp_monitoring/check_cisco_hw.log',format='%(asctime)s: %(levelname)s: %(message)s',level=logging.INFO)
docroot = "/opt/spot/snmp_monitoring/check_cisco/"

#COUNTERS
totalStatsIOS = [0,0,0,0,0,0,0,0,0]
totalStatsNXOS = [0,0,0,0,0,0,0,0,0,0,0,0]
totalStatsASA = [0,0,0,0,0,0]
totalStatsPTP = [0,0,0]
iosCount = 0
nxosCount = 0
asaCount = 0
ptpCount = 0

def sendToPagerDuty(type,key,desc,det):
    #print 'Send to PD: {0}; {1}; {2}; {3}'.format(type,key,desc,det)
    SPOT_API_TOKEN="<Your PagerDuty API token>"
    SERVICE_API_TOKEN="<Your PagerDuty service API token>"
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
    with open(docroot+'cisco_snmp_alarms_current','a') as f:
        f.write('{0}\n'.format(key))

def checkForAlarm(key):
    result = False
    with open(docroot+'cisco_snmp_alarms_previous','r') as f:
        for line in f:
            if line[:-1] == key:
                result = True
                return result
    return result

def logPreviousAlarms():
    logging.info('PREVIOUS ALARMS\tPrinting previous alarms from file')
    with open(docroot+'cisco_snmp_alarms_previous','r') as f:
        for line in f:
            logging.info('PREVIOUS ALARMS\t{0}'.format(line))
    logging.info('PREVIOUS ALARMS\tOutput complete')

def checkForExclusion(key):
    result = False
    with open(docroot+'cisco_snmp_exclusions','r') as f:
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

def queryFans(device,host):
    total,ok,failed = 0,0,0
    for index in device.ciscoEnvMonFanStatusDescr:
        total += 1
        expected = 'normal(1)'
        fanDescr = device.ciscoEnvMonFanStatusDescr[index]
        fanState = device.ciscoEnvMonFanState[index]

        if str(fanState) != expected:
            failed+=1
            msg = 'Error for Fan({0}): State = {1}; Description = {2}'.format(index,fanState,fanDescr)
            logging.warning('{0}\tFAN\t{1}'.format(host,msg))
            incident = sendToPagerDuty("trigger","snmp/fan/{0}/{1}".format(host,index),"Fan issue detected on {0}".format(host),msg)
        else:
            ok+=1
            msg = 'OK for Fan({0}): State = {1}; Description = {2}'.format(index,fanState,fanDescr)
            logging.debug('{0}\tFAN\t{1}'.format(host,msg))
            sendToPagerDuty("resolve","snmp/fan/{0}/{1}".format(host,index),"No fan issues detected",msg)
    return total,ok,failed

def queryFansNXOS(device,host):
    total,ok,failed = 0,0,0
    for index in device.cefcFanTrayOperStatus:
        total += 1
        allowed_status = 'up(2)'
        fanDescr = device.entPhysicalDescr[index]
        fanStatus = device.cefcFanTrayOperStatus[index]

        if str(fanStatus) not in allowed_status:
            failed+=1
            msg = 'Error for Fan({0}): Status = {1}; Description = {2}'.format(index,fanStatus,fanDescr)
            logging.warning('{0}\tFAN\t{1}'.format(host,msg))
            incident = sendToPagerDuty("trigger","snmp/fan/{0}/{1}".format(host,index),"Fan issue detected on {0}".format(host),msg)
        else:
            ok+=1
            msg = 'OK for Fan({0}): Status = {1}; Description = {2}'.format(index,fanStatus,fanDescr)
            logging.debug('{0}\tFAN\t{1}'.format(host,msg))
            sendToPagerDuty("resolve","snmp/fan/{0}/{1}".format(host,index),"No fan issues detected",msg)
    return total,ok,failed

def queryPowerNXOS(device,host):
    total,ok,failed = 0,0,0
    for index in device.cefcFRUPowerOperStatus:
        total += 1
        allowed_oper_status = ['on(2)']
        powerOperStatus = str(device.cefcFRUPowerOperStatus[index])
        powerAdminStatus = str(device.cefcFRUPowerAdminStatus[index])
        powerDescr = str(device.entPhysicalDescr[index])

        if powerOperStatus not in allowed_oper_status:
            failed+=1
            msg = 'Error for PSU({0}): OperStatus = {1}; AdminStatus = {2}; Description = {3}'.format(index,powerOperStatus,powerAdminStatus,powerDescr)
            logging.warning('{0}\tPSU\t{1}'.format(host,msg))
            incident = sendToPagerDuty("trigger","snmp/power/{0}/{1}".format(host,index),"Power supply issue detected on {0}".format(host),msg)
        else:
            ok+=1
            msg = 'OK for PSU({0}): OperStatus = {1}; AdminStatus = {2}; Description = {3}'.format(index,powerOperStatus,powerAdminStatus,powerDescr)
            logging.debug('{0}\tPSU\t{1}'.format(host,msg))
            sendToPagerDuty("resolve","snmp/power/{0}/{1}".format(host,index),"No power supply issues detected",msg)
    return total,ok,failed

def queryModuleNXOS(device,host):
    total,ok,failed = 0,0,0
    for index in device.cefcModuleOperStatus:
        total += 1
        allowed_oper_status = ['ok(2)']
        operStatus = str(device.cefcModuleOperStatus[index])
        adminStatus = str(device.cefcModuleAdminStatus[index])
        descr = str(device.entPhysicalDescr[index])

        if operStatus not in allowed_oper_status:
            failed+=1
            msg = 'Error for Module({0}): OperStatus = {1}; AdminStatus = {2}; Description = {3}'.format(index,operStatus,adminStatus,descr)
            logging.warning('{0}\tMODULE\t{1}'.format(host,msg))
            incident = sendToPagerDuty("trigger","snmp/module/{0}/{1}".format(host,index),"Module issue detected on {0}".format(host),msg)
        else:
            ok+=1
            msg = 'OK for Module({0}): OperStatus = {1}; AdminStatus = {2}; Description = {3}'.format(index,operStatus,adminStatus,descr)
            logging.debug('{0}\tMODULE\t{1}'.format(host,msg))
            sendToPagerDuty("resolve","snmp/module/{0}/{1}".format(host,index),"No fan issues detected",msg)
    return total,ok,failed

def querySensorNXOS(device,host):
    total,ok,failed = 0,0,0
    ids = defaultdict(list)
    for index in device.entSensorThresholdSeverity:
        id = index[0]
        instance = index[1]
        ids[id].append(instance)

    for x in ids.items():
        sensor = x[0]
        thresholds = x[1]
        descr = str(device.entPhysicalDescr[sensor]).replace('\n',' ')
        value = str(device.entSensorValue[sensor])
        status = str(device.entSensorStatus[sensor])
        unit = str(device.entSensorType[sensor])
        for t in thresholds:
            total+=1
            z = (int(sensor),int(t))
            severity = str(device.entSensorThresholdSeverity[z])
            threshold = str(device.entSensorThresholdValue[z])
            breached = str(device.entSensorThresholdEvaluation[z])
            if breached == 'true(1)':
                failed+=1
                msg = 'Error for Sensor({0}): Desc = {1}; Value = {2} {3}; Threshold = {4}; Breached = {5}; Severity = {6}; Status = {7}'.format(sensor,descr,value,unit,threshold,breached,severity,status)
                logging.warning('{0}\tSENSOR\t{1}'.format(host,msg))
                incident = sendToPagerDuty("trigger","snmp/sensor/{0}/{1}".format(host,sensor),"Sensor issue detected on {0}".format(host),msg)
            else:
                ok+=1
                msg = 'OK for Sensor({0}): Desc = {1}; Value = {2} {3}; Threshold = {4}; Breached = {5}; Severity = {6}; Status = {7}'.format(sensor,descr,value,unit,threshold,breached,severity,status)
                logging.debug('{0}\tSENSOR\t{1}'.format(host,msg))
                sendToPagerDuty("resolve","snmp/sensor/{0}/{1}".format(host,sensor),"No sensor issues detected",msg)
    return total,ok,failed

def queryTemp(device,host):
    total,ok,failed = 0,0,0
    for index in device.ciscoEnvMonTemperatureStatusDescr:
        total+=1
        expected = 'normal(1)'
        tempDescr = device.ciscoEnvMonTemperatureStatusDescr[index]
        tempStatus = device.ciscoEnvMonTemperatureStatusValue[index]
        tempThreshold = device.ciscoEnvMonTemperatureThreshold[index]
        tempState = device.ciscoEnvMonTemperatureState[index]

        if str(tempState) != expected:
            failed+=1
            msg = 'Error for Temperature Sensor({0}): State = {1}; Current = {2}; Threshold = {3}; Description = {4}'.format(index,tempState,tempStatus,tempThreshold,tempDescr)
            logging.warning('{0}\tTEMP\t{1}'.format(host,msg))
            incident = sendToPagerDuty("trigger","snmp/temperature/{0}/{1}".format(host,index),"Temperature issue detected on {0}".format(host),msg)
        else:
            ok+=1
            msg = 'OK for Temperature Sensor({0}): State = {1}; Current = {2}; Threshold = {3}; Description = {4}'.format(index,tempState,tempStatus,tempThreshold,tempDescr)
            logging.debug('{0}\tTEMP\t{1}'.format(host,msg))
            sendToPagerDuty("resolve","snmp/temperature/{0}/{1}".format(host,index),"No temperature issues detected",msg)
    return total,ok,failed

def queryPower(device,host):
    total,ok,failed = 0,0,0
    for index in device.ciscoEnvMonSupplyStatusDescr:
        total+=1
        allowed_state = ['normal(1)','notPresent(5)']
        psuDescr = device.ciscoEnvMonSupplyStatusDescr[index]
        psuState = device.ciscoEnvMonSupplyState[index]

        if str(psuState) not in allowed_state:
            failed+=1
            msg = 'Error for Power Supply({0}): State = {1}; Description = {2}'.format(index,psuState,psuDescr)
            logging.warning('{0}\tPSU\t{1}'.format(host,msg))
            incident = sendToPagerDuty("trigger","snmp/power/{0}/{1}".format(host,index),"Power Supply issue detected on {0}".format(host),msg)
        else:
            ok+=1
            msg = 'OK for Power Supply({0}): State = {1}; Description = {2}'.format(index,psuState,psuDescr)
            logging.debug('{0}\tPSU\t{1}'.format(host,msg))
            sendToPagerDuty("resolve","snmp/power/{0}/{1}".format(host,index),"No power issues detected",msg)

    return total,ok,failed

# Change 'connection_threshold' variable to adjust the maximum number of connections to alarm on.
def queryASA(device,host):
    h_total, h_ok, h_failed = 0,0,0 #hardware
    c_total, c_ok, c_failed = 0,0,0 #connections

    for index in device.cfwHardwareStatusValue:
        h_total += 1
        allowed_value = ['up(2)','active(9)','standby(10)']
        hwInfo = device.cfwHardwareInformation[index] 
        hwValue = device.cfwHardwareStatusValue[index]
        hwDetail = device.cfwHardwareStatusDetail[index]
        details = 'Value = {0}; Info = {1}; Detail = {2}'.format(hwValue, hwInfo, hwDetail)
        
        current_check = "Hardware"
        if str(hwValue) not in allowed_value:
            h_failed += 1
            msg = 'ERROR: {0} Check: {1}'.format(current_check, details)
            incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"{1} issue detected on {0}".format(host,current_check),msg)
            logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
        else:
            h_ok += 1
            msg = 'OK: {0} Check: {1}'.format(current_check, details)
            logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)

    for index in device.cfwConnectionStatDescription:
        connDesc = device.cfwConnectionStatDescription[index]
        connCount = device.cfwConnectionStatCount[index]
        connValue = device.cfwConnectionStatValue[index]
        connection_threshold = 20000
        details = 'Value = {0}; Count = {1}; Description = {2}'.format(connValue, connCount, connDesc)
    
        current_check = "Connections"
        if str(connDesc) == 'number of connections currently in use by the entire firewall':
            c_total += 1
            if int(connValue) > connection_threshold:
                c_failed += 1
                msg = 'ERROR: Current connection count({0}) exceeds threshold({1})'.format(connValue, connection_threshold)
                incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),msg,details)
                logging.warning('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
            else:
                c_ok += 1
                msg = 'OK: {0} Check: {1}'.format(current_check, details)
                logging.debug('{0}\t{2}\t{1}'.format(host,msg,current_check.upper()))
                sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(host,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)
    return h_total, h_ok, h_failed, c_total, c_ok, c_failed

# The Time Figure of Merit (TFOM) value ranges from 6 to 9 and indicates the current estimate of the worst case time error. 
# It is a logarithmic scale, with each increment indicating a tenfold increase in the worst case time error boundaries. 
# The scale is referenced to a worst case time error of 100 picoseconds, equivalent to a TFOM of zero. 
# During normal locked operation the TFOM is 6 and implies a worst case time error of 100 microseconds.
# During periods of signal loss, the CDMA sub-system will compute an extrapolated worst case time error. 
# One hour after the worst case time error has reached the value equivalent to a TFOM of 9, 
# the NTP server will cease to send stratum 1 reply packets and an Alarm LED will be energized.
#
# GPS/GNTP ranges from 3 to 9, with 3 = 100 nanoseconds
def queryTimeServer(device,host):
    total, ok, failed = 0,0,0
    checkpoints = []

    # Different servers will have different combinations of these values. 
    # This script tries each of them and ignores any which aren't present.
    try:
        gntpTFOM = device.gntpTimeFigureOfMerit
        total += 1
        checkpoint = {}
        checkpoint["current_check"] = 'gntpTimeFigureOfMerit'
        checkpoint["current_value"] = str(gntpTFOM)
        checkpoint["expected_value"] = 'lessthan100ns(3)'
        checkpoints.append(checkpoint) 
    except: pass

    try:
        gpsTFOM = device.gpsTimeFigureOfMerit
        total += 1
        checkpoint = {}
        checkpoint["current_check"] = 'gpsTimeFigureOfMerit'
        checkpoint["current_value"] = str(gpsTFOM)
        checkpoint["expected_value"] = 'lessthan100ns(3)'
        checkpoints.append(checkpoint)
    except: pass

    try:
        cdmaTFOM = device.cdmaTimeFigureOfMerit
        total += 1
        checkpoint = {}
        checkpoint["current_check"] = 'cdmaTimeFigureOfMerit'
        checkpoint["current_value"] = str(cdmaTFOM)
        checkpoint["expected_value"] = 'lessthan100us(6)'
        checkpoints.append(checkpoint)
    except: pass

    try:
        cntpTFOM = device.cntpTimeFigureOfMerit
        total += 1
        checkpoint = {}
        checkpoint["current_check"] = 'cntpTimeFigureOfMerit'
        checkpoint["current_value"] = str(cntpTFOM)
        checkpoint["expected_value"] = 'lessthan100us(6)'
        checkpoints.append(checkpoint)
    except: pass

    for index in checkpoints:
        if index["current_value"] != index["expected_value"]:
            failed += 1
            msg = 'ERROR: PTP clock accuracy is degraded. Current {0} = {1} on {2}'.format(index["current_check"], index["current_value"], host)
            incident = sendToPagerDuty("trigger","snmp/{0}/{1}".format(index["current_check"],host),msg,'Expected: {0}'.format(index["expected_value"]))
            logging.warning('{0}\t{1}\t{2}'.format(host,'PTP',msg))
        else:
            ok += 1
            msg = 'OK: PTP clock accuracy is OK. Current {0} = {1} on {2}'.format(index["current_check"], index["current_value"], host)
            logging.debug('{0}\t{1}\t{2}'.format(host,'PTP',msg))
            sendToPagerDuty("resolve","snmp/{0}/{1}".format(index["current_check"],host),msg,msg) 

    return total, ok, failed

def queryDevice(hostname,comm,ver):
    global nxosCount, iosCount, asaCount, ptpCount
    #adjust creds as needed
    if hostname in ['<Your hostname>']: comm = "<Your comment>"
    if hostname in ['<Your hostname>','<Your hostname>','<Your hostname>','<Your hostname>']: comm = "<Your comment>"
    if hostname in ['<Your hostname>','<Your hostname>']: comm = "<Your comment>"

    #Connect to device
    try:
        device = M(host=hostname,community=comm,version=ver,timeout=15,retries=2)
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

    if 'Cisco IOS Software' in desc:
        devType = 'IOS'
    elif 'Cisco Internetwork Operating System Software' in desc:
        devType = 'IOS'
    elif 'Cisco NX-OS' in desc:
        devType = 'NXOS'
    elif 'Cisco Adaptive Security Appliance' in desc:
        devType = 'ASA'
    elif 'Linux' in desc:
        devType = 'PTP'
    else:
        devType = 'UNDEFINED'

    if devType == 'IOS':
        iosCount += 1
        deviceResults = [0,0,0,0,0,0,0,0,0]
        #Perform checks, load results into list
        next_check = "queryFans"
        try:
            deviceResults[0:3] = queryFans(device,hostname)
        except Exception as inst:
            msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
            logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

        next_check = "queryTemp"
        try:
            deviceResults[3:6] = queryTemp(device,hostname)
        except Exception as inst:
            msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
            logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

        next_check = "queryPower"
        try:
            deviceResults[6:9] = queryPower(device,hostname)
        except Exception as inst:
            msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
            logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

        for i in range(len(totalStatsIOS)):
            totalStatsIOS[i]+=deviceResults[i]
        logging.info('{0}\tSTATS\tIOS\t(Checked,OK,Error) || Fan({1},{2},{3}) || Temp({4},{5},{6}) || PSU({7},{8},{9}))'.format(hostname,*deviceResults))
    elif devType == 'NXOS':
        nxosCount += 1
        deviceResults = [0,0,0,0,0,0,0,0,0,0,0,0]
        next_check = "queryFansNXOS"
        try:
            deviceResults[0:3] = queryFansNXOS(device,hostname)
        except Exception as inst:
            msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
            logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

        next_check = "queryPowerNXOS"
        try:
            deviceResults[3:6] = queryPowerNXOS(device,hostname)
        except Exception as inst:
            msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
            logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

        next_check = "queryModuleNXOS"
        try:
            deviceResults[6:9] = queryModuleNXOS(device,hostname)
        except Exception as inst:
            msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
            logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

        next_check = "querySensorNXOS"
        try:
            deviceResults[9:12] = querySensorNXOS(device,hostname)
        except Exception as inst:
            msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
            logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

        for i in range(len(totalStatsNXOS)):
            totalStatsNXOS[i]+=deviceResults[i]
        logging.info('{0}\tSTATS\tNXOS\t(Checked,OK,Error) || Fan({1},{2},{3}) || PSU({4},{5},{6}) || Module({7},{8},{9}) || Sensor({10},{11},{12})'.format(hostname,*deviceResults))
    elif devType == 'ASA':
        asaCount += 1
        deviceResults = [0,0,0,0,0,0]
        next_check = "queryASA"
        try:
            deviceResults[0:6] = queryASA(device,hostname)
        except Exception as inst:
            msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
            logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))
        
        for i in range(len(totalStatsASA)):
            totalStatsASA[i]+=deviceResults[i]
        logging.info('{0}\tSTATS\tASA\t(Checked,OK,Error) || HW({1},{2},{3}) || Conn({4},{5},{6})'.format(hostname,*deviceResults))
    elif devType == 'PTP':
        ptpCount += 1
        deviceResults = [0,0,0]
        next_check = "queryTimeServer"
        try:
            deviceResults[0:3] = queryTimeServer(device,hostname)
        except Exception as inst:
            msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
            logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

        for i in range(len(totalStatsPTP)):
            totalStatsPTP[i]+=deviceResults[i]
        logging.info('{0}\tSTATS\tPTP\t(Checked,OK,Error) || PTP({1},{2},{3})'.format(hostname,*deviceResults))

def main():
    logging.info('***************************************************************************')
    logging.info('Starting Script')
    deviceCount = 0

    #Prepare stats file
    touch(docroot + 'cisco_snmp_alarms_current')
    touch(docroot + 'cisco_snmp_exclusions')
    os.rename(docroot+'cisco_snmp_alarms_current',docroot+'cisco_snmp_alarms_previous')
    touch(docroot + 'cisco_snmp_alarms_current')

    #Parse previous alarms file and output to log file for debugging
    try:
        logPreviousAlarms()
    except Exception as inst:
        msg = 'Exception occurred while parsing previous alarms file. Exception: {0}'.format(inst)
        logging.warning(msg)

    #Load required MIBs
    load(docroot + "mibs/CISCO-SMI.my")
    load(docroot + "mibs/CISCO-TC.my")
    load(docroot + "mibs/ENTITY-MIB.my")
    load(docroot + "mibs/SNMPv2-MIB")
    load(docroot + "mibs/CISCO-ENVMON-MIB.my")
    load(docroot + "mibs/CISCO-ENTITY-FRU-CONTROL-MIB.mib")
    load(docroot + "mibs/CISCO-ENTITY-SENSOR-MIB.mib")
    load(docroot + "mibs/CISCO-FIREWALL-MIB.my")
    # We are using a modified version of the Tempus MIB
    # because the original has syntax errors and cannot be loaded by snimpy
    load(docroot + "mibs/TEMPUSLXUNISON-MIB-SPOT.txt")

    script_start = time.time()
    try:
        deviceFile = open(docroot+'cisco_devices','r')
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

    logging.info('TOTAL\tSTATS\tIOS\t(Checked,OK,Error) || Fan({1},{2},{3}) || Temp({4},{5},{6}) || PSU({7},{8},{9}) || Devices({0})'.format(iosCount,*totalStatsIOS))
    logging.info('TOTAL\tSTATS\tNXOS\t(Checked,OK,Error) || Fan({1},{2},{3}) || PSU({4},{5},{6}) || Module({7},{8},{9}) || Sensor({10},{11},{12}) || Devices({0})'.format(nxosCount,*totalStatsNXOS))
    logging.info('TOTAL\tSTATS\tASA\t(Checked,OK,Error) || HW({1},{2},{3}) || Conn({4},{5},{6}) || Devices({0})'.format(asaCount,*totalStatsASA))
    logging.info('TOTAL\tSTATS\tPTP\t(Checked,OK,Error) || PTP({1},{2},{3}) || Devices({0})'.format(ptpCount,*totalStatsPTP))
    logging.info('Script Complete')


if __name__ == "__main__":
    main()
