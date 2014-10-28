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
import re, sys
import shlex
from subprocess import PIPE
import datetime
import random
import requests
import json

"""
========
OVERVIEW
========

This script monitors server hardware for all HP and SuperMicro servers. It replaces the monitoring previously performed by Nimsoft SNMPget. 

The script uses the following process:
    1. Check ZooKeeper for exclusions
    2. Load MIBs
    3. Check PagerDuty for open incidents
    4. Query Salt for server list
    5. Query servers

=======
DETAILS
=======

1. Check ZooKeeper for exclusions: Exclusions can be added to the SNMPExclusions node in ZK.
This script checks that location each time it runs and stores the results in the snmp_exclusions file. 
If this script later detects a hardware issue, it will first check it against the exclusions list 
before sending it to PagerDuty. Exclusions are stored in the same format as the PD incident key. 
The easiest way to add a new exclusion is to open the incident in PD, copy the incident key, 
then add that to ZK. 

2. Load MIBs: This script uses the Snimpy module for all SNMP processing. This module requires 
that you first load all required MIBs before you start querying devices. The mibs are all located 
in the 'mibs' directory.

3. Check PagerDuty for open incidents: The pygerduty module is used to connect to PagerDuty's API
and pull the list of all open incidents. This list is used to ensure "resolve" commands are only sent to
PD for incidents which are currently open. We cannot send "resolve" commands for every "OK" check, 
because that would be well over PD's API rate limit.

4. Query Salt for server list: Salt is queried to determine the current list of active physical servers, 
along with their manufacturer and model. This ensures that the script always has an accurate list of 
servers to query each time it runs. This eliminates the need for any type of manual configuration when
servers are added or removed from the environment. The script should automatically monitor all physical servers
as long as Salt is working correctly.

5. Query Servers: The script loops through the list returned from Salt and goes through the following process:
    Determine Manufacturer:
        If HP:
            > Try to connect to SNMP agent
            > Try to connect to HP agent (test HP specific OID)
            > Test hardware sensors (temperature, fans, power, memory, cpu, storage (drives, accelerators, controllers), and NICs
        If SM:
            > Try to connect to SNMP agent
            > Try to connect to SuperMicro SuperDoctor agent (test SM specific OID)
            > Test hardware sensors (fans, temperature, status, voltage, current, power)
    For all sensors:
        Compare actual value against allowed values.
            If OK:
                Call sendToPagerDuty("resolve"...) This will check against open PD incidents and send a "resolve" if it 
                finds a match. Otherwise, no action is taken. 
            If not OK:
                Call sendToPagerDuty("trigger"...) This will use pygerduty to send a "trigger" to PD. 
                If it is a new issue, a new incident will be created. Else, it will be added to the existing incident.         
"""

#SET LOGGING AND FILE INFO
if not os.path.exists('/var/log/snmp_monitoring/'):
    os.mkdir('/var/log/snmp_monitoring/')
logging.basicConfig(filename='/var/log/snmp_monitoring/check_hp.log',format='%(asctime)s: %(levelname)s: %(message)s',level=logging.INFO)
docroot = "/opt/spot/snmp_monitoring/"
open_alarms = []

# Uses pygerduty to send "resolves" and "triggers" to PD. Only sends "resolves" for currently open incidents.
def sendToPagerDuty(type,key,desc,det):
    SPOT_API_TOKEN="<your PagerDuty token>"
    SERVICE_API_TOKEN="<your PagerDuty service API>"
    try:
        pager = pygerduty.PagerDuty(api_token=SPOT_API_TOKEN)
        if type == "trigger":
            if checkForExclusion(key) is False:
                det = det + " ***** HP Dispatch: 800-633-3600 ***** "
                incident = pager.trigger_incident(service_key=SERVICE_API_TOKEN, incident_key=key, description=desc, details=det)
                logging.info('<your pagerduty domain>\tPAGER\tCreating Alarm: {0}'.format(key))
                return incident
            else:
                logging.info('<your pagerduty domain>\tPAGER\tAlarm Excluded: {0}'.format(key))
                return 'Excluded'
        elif type == "resolve":
            if checkForAlarm(key):
                logging.info('<your pagerduty domain>\tPAGER\tResolving Open Incident: {0}'.format(key))
                incident = pager.resolve_incident(service_key=SERVICE_API_TOKEN, incident_key=key, description=desc, details=det)
                return incident
    except Exception as inst:
        msg = 'Exception occurred while sending incident to PagerDuty; Exception = "{0}"'.format(inst)
        logging.warning('PAGER\t\tERROR\t{0}'.format(msg))
        return 'exception'

def walker(env):
    command="curl -si salt%s:8000/login -H 'Accept: application/json' -d username='<Salt username>' -d password='<Salt password>' -d eauth='pam'" % env
    login_cmd = shlex.split(command)
    token = subprocess.Popen(login_cmd,stdout=PIPE).communicate()[0]
    string_token = str(token)
    start = string_token.find('token')
    end = string_token.find(',',start)
    semi_token = token[start:end]
    valid = semi_token.split(':')[1].replace('"', '').lstrip().strip()
    cmd="curl -sS salt%s:8000/minions -H 'Accept: application/json' -H 'X-Auth-Token: %s' -d client='local' -d tgt='* and G@kernel:Linux and G@virtual:physical' -d expr_form='compound' -d fun='grains.item' -d arg='manufacturer' -d arg='host' -d arg='productname' " % (env,valid)
    command = shlex.split(cmd)
    output = subprocess.Popen(command,stdout=PIPE).communicate()[0]
    output = output.split(':')
    temp_out = output[5]
    jid = output[5].split(',')[0].replace('"', '').lstrip(' ')
    com = "curl -sS salt%s:8000/jobs/%s -H 'Accept: application/json' -H 'X-Auth-Token: %s'" %(env,jid, valid)
    comm = shlex.split(com)
    result = subprocess.Popen(comm, stdout=PIPE).communicate()[0]    
    host = []
    man = []
    prod = []
    result = result.split(',')
    result[0] = result[0].split('[')[1].replace('{','').lstrip()
    for i in result:
        try:
            if re.search(r'\bhost\b',i):
                h = i.split(':')[0]
                h2 = re.sub('["\{}\[\]]','',h)
                host.append(h2.lstrip())
            if re.search(r'\bmanufacturer\b', i):
                temp = i.split(':')[1]
                val = re.sub('["\]\}]','',temp)
                man.append(val.lstrip())
            elif re.search(r'\bproductname\b',i):
                prod.append(i.split(':')[1].replace('"','').lstrip())
        except Exception as inst:
            msg = 'Exception occurred while querying Salt minion. Server will be skipped; Exception = "{0}"'.format(inst)
            logging.warning('SALT\t\tERROR\t{0}'.format(msg))
    combined = zip(host,man,prod)
    joined = []
    for i in sorted(combined):
        temp = ','.join(i)
        joined.append(temp) 
    return joined 

def physical_checker(env):
    command="curl -si salt%s:8000/login -H 'Accept: application/json' -d username='<salt username>' -d password='<salt password>' -d eauth='pam'" % env
    login_cmd = shlex.split(command)
    token = subprocess.Popen(login_cmd,stdout=PIPE).communicate()[0]
    string_token = str(token)
    start = string_token.find('token')
    end = string_token.find(',',start)
    semi_token = token[start:end]
    valid = semi_token.split(':')[1].replace('"', '').lstrip().strip()
    cmd="curl -sS salt%s:8000/minions -H 'Accept: application/json' -H 'X-Auth-Token: %s' -d client='local' -d tgt='G@kernel:Windows and not G@localhost:CHIV*' -d expr_form='compound' -d fun='cmd.run' -d arg='wmic computersystem get model, manufacturer' " % (env,valid)
    command = shlex.split(cmd)
    output = subprocess.Popen(command,stdout=PIPE).communicate()[0]
    output = output.split(':')
    temp_out = output[5]
    jid = output[5].split(',')[0].replace('"', '').lstrip(' ')
    com = "curl -sS salt%s:8000/jobs/%s -H 'Accept: application/json' -H 'X-Auth-Token: %s'" %(env,jid, valid)
    comm = shlex.split(com)
    result = subprocess.Popen(comm, stdout=PIPE).communicate()[0]
    result = result.split('[')[1].split('",') 
    hosts=[] 
    man_model = []
    for i in result:
        try:
            thost = i.split(':')[0].replace('"','').replace('{','').lstrip()
            both = i.split('\\r\\r\\n')
            tman = both[1]
            if not re.search('VMware', tman):
                hosts.append(thost)
                man_model.append(tman)
        except Exception as inst:
            msg = 'Exception occurred while querying Salt minion. Server will be skipped; Exception = "{0}"'.format(inst)
            logging.warning('SALT\t\tERROR\t{0}'.format(msg))
    combined = zip(hosts, man_model)
    joined = []
    for i in combined:
        temp=','.join(i)
        joined.append(temp)
    return joined

# Query Salt for list of currently active physical servers. Returns hostname, manufacturer, and model.
def querySalt(env):
    if env == 'master':
        env = 'Production'
    filename = 'snmp_servers_temp'
    physical = physical_checker(env)
    result = walker(env)
    total_list = []
    for i in sorted(physical):
        output = re.sub(r'\s{2,}',',' ,i)
        total_list.append(output)
    for j in sorted(result):
        total_list.append(j)

    f = open(docroot+filename, 'w')
    if env == 'Production':
        f.write('<server notin Salt>,<server model>\n')
        f.write('<server not in Salt>,<server model>\n')
    for j in sorted(total_list):
        f.write(j)
        f.write('\n')
    f.close()
    logging.info('SALT\tSuccessfully queried Salt for server list. Environment: {0}; Servers: {1}'.format(env,len(total_list)))

def populateExclusions(env):
    if env == "Staging":
        server_pool = ['<Staging zookeeper node 1>','<Staging zookeeper node 2>','<Staging zookeeper node 3>','<Staging zookeeper node 4>','<Staging zookeeper node 5>']
    elif env == "UAT":
        server_pool = ['<UAT zookeeper node 1>','<UAT zookeeper node 2>','<UAT zookeeper node 3>','<UAT zookeeper node 4>','<UAT zookeeper node 5>']
    elif env == "master":
        server_pool = ['<Production zookeeper node 1>','<Production zookeeper node 2>','<Production zookeeper node 3>','<Production zookeeper node 4>','<Production zookeeper node 5>']

    run = True
    retry_count = 0
    while run == True:
        try:
            excludes = []
            server = random.choice(server_pool)
            host = 'http://{0}:8080/exhibitor/v1/explorer/node?key=/SNMPExceptions'.format(server)
            r = requests.get(host, auth=('<Exhibitor username>','Exhibitor password'))
            data = r.json()
            for item in data:
                value = item["title"]
                host_node = 'http://{0}:8080/exhibitor/v1/explorer/node-data?key=/SNMPExceptions/{1}'.format(server,value)
                req = requests.get(host_node, auth=('<Exhibitor username>','Exhibitor password'))
                node_data = req.json()
                excludes.append(node_data["str"])
            with open(docroot+'snmp_exclusions','w') as f:
                for x in excludes:
                    f.write('{0}\n'.format(x))
            logging.info('ZOOKEEPER\tSuccessfully queried ZooKeeper for exclusions list. Host: {0}; Exclusions: {1}'.format(host,len(excludes)))
            run = False
        except Exception as inst:
            logging.error('ZOOKEEPER\tError querying host {0}. Exception: {1}'.format(host,inst))
            retry_count += 1
            if (retry_count == 5):
                logging.error('ZOOKEEPER\tUnable to connect to any ZooKeeper hosts after {0} retry attempts. Exiting script.'.format(retry_count))
                run = False
            else:
                logging.info('ZOOKEEPER\tRetry attempt {0}'.format(retry_count))

# Uses pygerduty to get current list of all open incidents for PD. We need this information
# to decide when "resolve" messages are needed.
def getCurrentAlarms():
    SPOT_API_TOKEN="<your PagerDuty API token>"
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
    with open(docroot+'snmp_exclusions','r') as f:
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
def queryTemp(device,hostname):
    total,ok,failed = 0,0,0
    for index in device.cpqHeTemperatureIndex:
        total += 1
        expected = 'ok(2)'
        tempCondition = device.cpqHeTemperatureCondition[index]
        tempCelsius = device.cpqHeTemperatureCelsius[index]
        tempLocale = device.cpqHeTemperatureLocale[index]
        tempThreshold = device.cpqHeTemperatureThreshold[index]
        tempIndex = device.cpqHeTemperatureIndex[index]

        if str(tempCondition) != expected:
            failed+=1
            msg = 'Error for Temperature Sensor({0}): Condition = {1}; Celsius = {2}; Threshold = {3}; Location = {4}'.format(tempIndex,tempCondition,tempCelsius,tempThreshold,tempLocale)
            logging.warning('{0}\tTEMP\t{1}'.format(hostname,msg))
            incident = sendToPagerDuty("trigger","snmp/temperature/{0}/{1}".format(hostname,index),"Temperature issue detected on {0}".format(hostname),msg)
        else:
            ok+=1
            msg = 'OK for Temperature Sensor({0}): Condition = {1}; Celsius = {2}; Threshold = {3}; Location = {4}'.format(tempIndex,tempCondition,tempCelsius,tempThreshold,tempLocale)
            logging.debug('{0}\tTEMP\t{1}'.format(hostname,msg))
            sendToPagerDuty("resolve","snmp/temperature/{0}/{1}".format(hostname,index),"No temperature issues detected",msg)
    return total,ok,failed

def queryFans(device,hostname):
    total,ok,failed = 0,0,0
    for index in device.cpqHeFltTolFanIndex:
        total += 1
        expected = 'ok(2)'
        expected_other = 'other(1)'
        fanLocale = device.cpqHeFltTolFanLocale[index]
        fanCondition = device.cpqHeFltTolFanCondition[index]
        fanIndex = device.cpqHeFltTolFanIndex[index]

        if (str(fanCondition) != expected) and (str(fanCondition) != expected_other):
            failed+=1
            msg = 'Error for Fan({0}): Condition = {1}; Location = {2}'.format(fanIndex,fanCondition,fanLocale)
            logging.warning('{0}\tFAN\t{1}'.format(hostname,msg))
            incident = sendToPagerDuty("trigger","snmp/fan/{0}/{1}".format(hostname,fanIndex),"Fan issue detected on {0}".format(hostname),msg)
        else:
            ok+=1
            msg = 'OK for Fan({0}): Condition = {1}; Location = {2}'.format(fanIndex,fanCondition,fanLocale)
            logging.debug('{0}\tFAN\t{1}'.format(hostname,msg))
            sendToPagerDuty("resolve","snmp/fan/{0}/{1}".format(hostname,fanIndex),"No fan issues detected",msg)
    return total,ok,failed

def queryNics(device,hostname):
    total,ok,failed = 0,0,0
    for index in device.cpqNicIfPhysAdapterIndex:
        total += 1
        nicCondition = device.cpqNicIfPhysAdapterCondition[index]
        nicState = device.cpqNicIfPhysAdapterState[index]
        nicStatus = device.cpqNicIfPhysAdapterStatus[index]
        nicName = device.cpqNicIfPhysAdapterName[index]

        if str(nicStatus) == "generalFailure(3)":
            failed+=1
            msg = 'Error for NIC({0}): Status = {1}; Condition = {2}; State = {3} Name = {4}'.format(index,nicStatus,nicCondition,nicState,nicName)
            logging.warning('{0}\tNIC\t{1}'.format(hostname,msg))
            incident = sendToPagerDuty("trigger","snmp/nic/{0}/{1}".format(hostname,index),"NIC issue detected on {0}".format(hostname),msg)
        else:
            ok+=1
            msg = 'OK for NIC({0}): Status = {1}; Condition = {2}; State = {3} Name = {4}'.format(index,nicStatus,nicCondition,nicState,nicName)
            logging.debug('{0}\tNIC\t{1}'.format(hostname,msg))
            sendToPagerDuty("resolve","snmp/nic/{0}/{1}".format(hostname,index),"No NIC issues detected",msg)
    return total,ok,failed

def queryMemory(device,hostname):
    total,ok,failed = 0,0,0
    for index in device.cpqHeResMem2Module:
        expected = 'ok(2)'
        expected_status = 'good(4)'

        memStatus = device.cpqHeResMem2ModuleStatus[index]
        memCondition = device.cpqHeResMem2ModuleCondition[index]
        memSize = device.cpqHeResMem2ModuleSize[index]

        if str(memStatus) != "notPresent(2)":
            total+=1
            if (str(memStatus) != expected_status) or (str(memCondition) != expected):
                failed+=1
                msg = 'Error for memory module({0}): Status = {1}; Condition = {2}; Size = {3}'.format(index,memStatus,memCondition,memSize)
                logging.warning('{0}	MEMORY	{1}'.format(hostname,msg))
                incident = sendToPagerDuty("trigger","snmp/memory/{0}/{1}".format(hostname,index),"Memory issue detected on {0}".format(hostname),msg)
            else:
                ok+=1
                msg = 'OK for memory module({0}): Status = {1}; Condition = {2}; Size = {3}'.format(index,memStatus,memCondition,memSize)
                logging.debug('{0}	MEMORY	{1}'.format(hostname,msg))
                sendToPagerDuty("resolve","snmp/memory/{0}/{1}".format(hostname,index),"No memory issues detected",msg)
    return total,ok,failed

def queryCPU(device,hostname):
    total,ok,failed = 0,0,0
    for index in device.cpqSeCpuUnitIndex:
        total += 1
        expected = 'ok(2)'
        cpuSlot = device.cpqSeCpuSlot[index]
        cpuStatus = device.cpqSeCpuStatus[index]
        cpuName = device.cpqSeCpuName[index]
        if str(cpuStatus) != expected:
            failed+=1
            msg = 'Error for CPU({0}): Status = {1}; Name = {2}; Slot = {3}'.format(index,cpuStatus,cpuName,cpuSlot)
            logging.warning('{0}	CPU	{1}'.format(hostname,msg))
            incident = sendToPagerDuty("trigger","snmp/cpu/{0}/{1}".format(hostname,index),"CPU issue detected on {0}".format(hostname),msg)
        else:
            ok+=1
            msg = 'OK for CPU({0}): Status = {1}; Name = {2}; Slot = {3}'.format(index,cpuStatus,cpuName,cpuSlot)
            logging.debug('{0}	CPU	{1}'.format(hostname,msg))
            sendToPagerDuty("resolve","snmp/cpu/{0}/{1}".format(hostname,index),"No CPU issues detected",msg)
    return total,ok,failed

def queryPower(device,hostname):
    total,ok,failed = 0,0,0
    for index in device.cpqHeFltTolPowerSupplyBay:
        total += 1
        expected = 'ok(2)'
        psuCondition = device.cpqHeFltTolPowerSupplyCondition[index]
        psuUsed = device.cpqHeFltTolPowerSupplyCapacityUsed[index]
        psuMax = device.cpqHeFltTolPowerSupplyCapacityMaximum[index]
        psuChassis = device.cpqHeFltTolPowerSupplyChassis[index]
        psuBay = device.cpqHeFltTolPowerSupplyBay[index]
        psuSerial = device.cpqHeFltTolPowerSupplySerialNumber[index]
        if str(psuCondition) != expected:
            failed+=1
            msg = 'Error for Power Supply: Condition = {1}; Chassis = {2}; Bay = {3}; Used = {4}; Capacity = {5}; Serial = {6}'.format(index,psuCondition,psuChassis,psuBay,psuUsed,psuMax,psuSerial)
            logging.warning('{0}	POWER	{1}'.format(hostname,msg))
            incident = sendToPagerDuty("trigger","snmp/power/{0}/{1}".format(hostname,index),"Power Supply issue detected on {0}".format(hostname),msg)
        else:
            ok+=1
            msg = 'OK for Power Supply: Condition = {1}; Chassis = {2}; Bay = {3}; Used = {4}; Capacity = {5}; Serial = {6}'.format(index,psuCondition,psuChassis,psuBay,psuUsed,psuMax,psuSerial)
            logging.debug('{0}	POWER	{1}'.format(hostname,msg))
            sendToPagerDuty("resolve","snmp/power/{0}/{1}".format(hostname,index),"No power issues detected",msg)
    return total,ok,failed

# This is a bit different than the other query* functions. It checks HDDs, accelerators, and controllers in a single function.
# This allows us to be smarter about the alarms we send. For example, we know that the controller status will always be 
# degraded if there is an accelerator error. Therefore, we suppress the controller error in that scenario to prevent having 
# two incidents for the same issue in PD. 
def queryDrives(device,hostname):
    d_total,d_ok,d_failed = 0,0,0
    c_total,c_ok,c_failed = 0,0,0
    a_total,a_ok,a_failed = 0,0,0
    hdd_or_accel_error = False
    controller_models = []

    for index in device.cpqDaCntlrIndex:
        controller_models.append(str(device.cpqDaCntlrModel[index]))

    for index in device.cpqDaPhyDrvIndex:
        d_total += 1
        allowed_status = ['ok(2)']
        allowed_condition = ['ok(2)']
        allowed_SMART = ['other(1)','ok(2)']
        drvLocation = device.cpqDaPhyDrvLocationString[index]
        drvStatus = device.cpqDaPhyDrvStatus[index]
        drvCondition = device.cpqDaPhyDrvCondition[index]
        drvSMART = device.cpqDaPhyDrvSmartStatus[index]
        drvSerial = device.cpqDaPhyDrvSerialNum[index]
        if (str(drvStatus) not in allowed_status) or (str(drvCondition) not in allowed_condition) or (str(drvSMART) not in allowed_SMART):
            d_failed+=1
            msg = 'Error for HDD: Location = {0}; Status = {1}; Condition = {2}; SMART = {3}; Serial = {4}'.format(drvLocation,drvStatus,drvCondition,drvSMART,drvSerial)
            logging.warning('{0}	HDD	{1}'.format(hostname,msg))
            incident = sendToPagerDuty("trigger","snmp/hdd/{0}/{1}".format(hostname,index),"Hard drive issue detected on {0}".format(hostname),msg)
            hdd_or_accel_error = True
        else:
            d_ok+=1
            msg = 'OK for HDD: Location = {0}; Status = {1}; Condition = {2}; SMART = {3}; Serial = {4}'.format(drvLocation,drvStatus,drvCondition,drvSMART,drvSerial)
            logging.debug('{0}	HDD	{1}'.format(hostname,msg))
            sendToPagerDuty("resolve","snmp/hdd/{0}/{1}".format(hostname,index),"No hard drive issues detected",msg)

    for index in device.cpqDaAccelCntlrIndex:
        a_total += 1
        allowed_status = ['enabled(3)','invalid(2)']
        allowed_condition = ['ok(2)','other(1)']
        allowed_battery = ['ok(2)','notPresent(6)']
        accelStatus = device.cpqDaAccelStatus[index]
        accelCondition = device.cpqDaAccelCondition[index]
        accelBattery = device.cpqDaAccelBattery[index]
        accelSerial = device.cpqDaAccelSerialNumber[index]

        if (str(accelStatus) not in allowed_status) or (str(accelCondition) not in allowed_condition) or (str(accelBattery) not in allowed_battery):
            a_failed+=1
            msg = 'Error for Array Accelerator({0}): Status = {1}; Condition = {2}; Battery = {3}; Serial = {4}'.format(index,accelStatus,accelCondition,accelBattery,accelSerial)
            msg = msg + "; Controller models present on server: "
            for x in controller_models:
                msg = msg + x + ';'
            logging.warning('{0}	ACCEL	{1}'.format(hostname,msg))
            incident = sendToPagerDuty("trigger","snmp/accelerator/{0}/{1}".format(hostname,index),"Accelerator issue detected on {0}".format(hostname),msg)
            hdd_or_accel_error = True
        else:
            a_ok+=1
            msg = 'OK for Array Accelerator({0}): Status = {1}; Condition = {2}; Battery = {3}; Serial = {4}'.format(index,accelStatus,accelCondition,accelBattery,accelSerial)
            logging.debug('{0}\tACCEL\t{1}'.format(hostname,msg))
            sendToPagerDuty("resolve","snmp/accelerator/{0}/{1}".format(hostname,index),"No accelerator issues detected",msg)

    for index in device.cpqDaCntlrIndex:
        c_total += 1
        allowed_status = ['ok(2)']
        allowed_condition = ['ok(2)']
        ctrStatus = device.cpqDaCntlrBoardStatus[index]
        ctrBoardCondition = device.cpqDaCntlrBoardCondition[index]
        ctrCondition = device.cpqDaCntlrCondition[index]
        ctrSerial = device.cpqDaCntlrSerialNumber[index]
        ctrModel = device.cpqDaCntlrModel[index]
        ctrLocation = device.cpqDaCntlrHwLocation[index]
        if (str(ctrStatus) not in allowed_status) or (str(ctrCondition) not in allowed_condition):
            c_failed+=1
            msg = 'Error for Controller: Location = {0}; Status = {1}; Condition = {2}; Model = {3}; Serial = {4}'.format(ctrLocation,ctrStatus,ctrCondition,ctrModel,ctrSerial)
            logging.warning('{0}	CTRLR	{1}'.format(hostname,msg))
            if not hdd_or_accel_error:
                incident = sendToPagerDuty("trigger","snmp/controller/{0}/{1}".format(hostname,index),"Controller issue detected on {0}".format(hostname),msg)
        else:
            c_ok+=1
            msg = 'OK for Controller: Location = {0}; Status = {1}; Condition = {2}; Model = {3}; Serial = {4}'.format(ctrLocation,ctrStatus,ctrCondition,ctrModel,ctrSerial)
            logging.debug('{0}	CTRLR	{1}'.format(hostname,msg))
            sendToPagerDuty("resolve","snmp/controller/{0}/{1}".format(hostname,index),"No controller issues detected",msg)

    return d_total,d_ok,d_failed,c_total,c_ok,c_failed,a_total,a_ok,a_failed

# This is the function used to monitor SuperMicro servers. SM is different than HP in that it reports all hardware status
# in a single SNMP table. The 'type' field is used to determine the type of hardware.
def querySensors(device,hostname):
    # define counters for reporting stats
    t_total,t_ok,t_failed = 0,0,0
    p_total,p_ok,p_failed = 0,0,0
    f_total,f_ok,f_failed = 0,0,0
    o_total,o_ok,o_failed = 0,0,0
    s_total,s_ok,s_failed = 0,0,0

    # loop through sensors, determine type, process
    for index in device.smHealthMonitorName:
        name = str(device.smHealthMonitorName[index])
        type = str(device.smHealthMonitorType[index])
        reading = device.smHealthMonitorReading[index]
        present = device.smHealthMonitorMonitor[index]

        #check to see if component is present in this server
        if present != 1:
            continue

        try:
            highlimit = device.smHealthMonitorHighLimit[index]
        except:
            highlimit = 'UNDEFINED'
        try:
            lowlimit = device.smHealthMonitorLowLimit[index]
        except:
            lowlimit = 'UNDEFINED'
        #Fans
        if type == "0":
            current_check = "Fan"
            current_unit = "RPM"
            f_total += 1
            if ((highlimit != 'UNDEFINED') and (reading > highlimit)) or ((lowlimit != 'UNDEFINED') and (reading < lowlimit)):
                f_failed += 1
                msg = 'Error for {4} Sensor({0}): Value = {1} {5}; High Threshold = {2} {5}; Low Threshold = {3} {5}'.format(name,reading,highlimit,lowlimit,current_check,current_unit)
                incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"{1} issue detected on {0}".format(hostname,current_check),msg)
                logging.warning('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
            else:
                f_ok += 1
                msg = 'OK for {4} Sensor({0}): Value = {1} {5}; High Threshold = {2} {5}; Low Threshold = {3} {5}'.format(name,reading,highlimit,lowlimit,current_check,current_unit)
                logging.debug('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
                sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)
        #Voltage
        elif type == "1":
            current_check = "Voltage"
            current_unit = "mV"
            p_total += 1
            if ((highlimit != 'UNDEFINED') and (reading > highlimit)) or ((lowlimit != 'UNDEFINED') and (reading < lowlimit)):
                p_failed += 1
                msg = 'Error for {4} Sensor({0}): Value = {1} {5}; High Threshold = {2} {5}; Low Threshold = {3} {5}'.format(name,reading,highlimit,lowlimit,current_check,current_unit)
                incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"{1} issue detected on {0}".format(hostname,current_check),msg)
                logging.warning('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
            else:
                p_ok += 1
                msg = 'OK for {4} Sensor({0}): Value = {1} {5}; High Threshold = {2} {5}; Low Threshold = {3} {5}'.format(name,reading,highlimit,lowlimit,current_check,current_unit)
                logging.debug('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
                sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)
        #Temperature
        elif type == "2":
            current_check = "Temperature"
            current_unit = "C"
            t_total += 1
            if ((highlimit != 'UNDEFINED') and (reading > highlimit)) or ((lowlimit != 'UNDEFINED') and (reading < lowlimit)):
                t_failed += 1
                msg = 'Error for {4} Sensor({0}): Value = {1} {5}; High Threshold = {2} {5}; Low Threshold = {3} {5}'.format(name,reading,highlimit,lowlimit,current_check,current_unit)
                incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"{1} issue detected on {0}".format(hostname,current_check),msg)
                logging.warning('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
            else:
                t_ok += 1
                msg = 'OK for {4} Sensor({0}): Value = {1} {5}; High Threshold = {2} {5}; Low Threshold = {3} {5}'.format(name,reading,highlimit,lowlimit,current_check,current_unit)
                logging.debug('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
                sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)
        #Status (0:good, 1:bad)
        elif type == "3":
            current_check = "Status"
            current_unit = ""
            s_total += 1
            if reading != 0:
                s_failed += 1
                msg = 'Error for Status Sensor({0}): Value = {1}; (0 = OK)'.format(name,reading)
                incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"{1} issue detected on {0}".format(hostname,current_check),msg)
                logging.warning('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
            else:
                s_ok += 1
                msg = 'OK for Status Sensor({0}): Value = {1}; (0 = OK)'.format(name,reading)
                logging.debug('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
                sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)
        #Current
        elif type == "7":
            current_check = "Current"
            current_unit = "mA"
            p_total += 1
            if ((highlimit != 'UNDEFINED') and (reading > highlimit)) or ((lowlimit != 'UNDEFINED') and (reading < lowlimit)):
                p_failed += 1
                msg = 'Error for {4} Sensor({0}): Value = {1} {5}; High Threshold = {2} {5}; Low Threshold = {3} {5}'.format(name,reading,highlimit,lowlimit,current_check,current_unit)
                incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"{1} issue detected on {0}".format(hostname,current_check),msg)
                logging.warning('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
            else:
                p_ok += 1
                msg = 'OK for {4} Sensor({0}): Value = {1} {5}; High Threshold = {2} {5}; Low Threshold = {3} {5}'.format(name,reading,highlimit,lowlimit,current_check,current_unit)
                logging.debug('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
                sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)
        #Power
        elif type == "8":
            current_check = "Power"
            current_unit = "mW"
            p_total += 1
            if ((highlimit != 'UNDEFINED') and (reading > highlimit)) or ((lowlimit != 'UNDEFINED') and (reading < lowlimit)):
                p_failed += 1
                msg = 'Error for {4} Sensor({0}): Value = {1} {5}; High Threshold = {2} {5}; Low Threshold = {3} {5}'.format(name,reading,highlimit,lowlimit,current_check,current_unit)
                incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"{1} issue detected on {0}".format(hostname,current_check),msg)
                logging.warning('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
            else:
                p_ok += 1
                msg = 'OK for {4} Sensor({0}): Value = {1} {5}; High Threshold = {2} {5}; Low Threshold = {3} {5}'.format(name,reading,highlimit,lowlimit,current_check,current_unit)
                logging.debug('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
                sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)
        else:
            o_total+=1
            logging.warning('Other Sensor({0}): Type = {4}; Value = {1}; High Threshold = {2}; Low Threshold = {3}'.format(name,reading,highlimit,lowlimit,type))

    #print '{0}:{1}:{2}:{3}:{4}:{5}'.format(hostname,name,type,reading,highlimit,lowlimit)
    return t_total,t_ok,t_failed,p_total,p_ok,p_failed,f_total,f_ok,f_failed,o_total,o_ok,o_failed,s_total,s_ok,s_failed

def querySmMemory(device,hostname):
    total,ok,failed = 0,0,0
    current_check = "Memory"
    for index in device.memTag:
        total += 1
        allowed_status = ["0"]
        memTag = device.memTag[index]
        memDescription = device.memDescription[index]
        memDeviceStatus = device.memDeviceStatus[index]
        memLabeledBank = device.memLabeledBank[index]
        memDeviceLocator = device.memDeviceLocator[index]
        memManufacturer = device.memManufacturer[index]
        memPartNumber = device.memPartNumber[index]
        memSerialNumber = device.memSerialNumber[index]
        memCapacity = device.memCapacity[index]
        if str(memDeviceStatus) not in allowed_status:
            failed += 1
            msg = 'Error for {0}: Status = {1}; Location = {2}; Manufacturer = {3}; PartNum = {4}; Serial = {5}; Capacity = {6}'.format(current_check, memDeviceStatus, memLabeledBank, memManufacturer, memPartNumber, memSerialNumber, memCapacity)
            incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"{1} issue detected on {0}".format(hostname,current_check),msg)
            logging.warning('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
        else:
            ok += 1
            msg = 'OK for {0}: Status = {1}; Location = {2}; Manufacturer = {3}; PartNum = {4}; Serial = {5}; Capacity = {6}'.format(current_check, memDeviceStatus, memLabeledBank, memManufacturer, memPartNumber, memSerialNumber, memCapacity)
            logging.debug('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
            sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)
    return total,ok,failed

def querySmCPU(device,hostname):
    total,ok,failed = 0,0,0
    current_check = "CPU"
    for index in device.cpuIndex:
        total += 1
        allowed_status = ["0"]
        cpuIndex = device.cpuIndex[index]
        cpuName = device.cpuName[index]
        cpuDescription = device.cpuDescription[index]
        cpuManufacturer = device.cpuManufacturer[index]
        cpuDeviceStatus = device.cpuDeviceStatus[index]
        cpuMaxSpeed = device.cpuMaxSpeed[index]
        cpuCurrentSpeed = device.cpuCurrentSpeed[index]
        cpuCoreEnabled = device.cpuCoreEnabled[index]
        cpuCoreCount = device.cpuCoreCount[index]
        cpuThreadCount = device.cpuThreadCount[index]
        cpuSocketDesignation = device.cpuSocketDesignation[index]
        cpuDeviceVersion = device.cpuDeviceVersion[index]
        cpuDeviceID = device.cpuDeviceID[index]
        if str(cpuDeviceStatus) not in allowed_status:
            failed += 1
            msg = 'Error for {0}: Status = {1}; Location = {2}; Name = {3}'.format(current_check, cpuDeviceStatus, cpuName, cpuSocketDesignation)
            incident = sendToPagerDuty("trigger","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"{1} issue detected on {0}".format(hostname,current_check),msg)
            logging.warning('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
        else:
            ok += 1
            msg = 'OK for {0}: Status = {1}; Location = {2}; Name = {3}'.format(current_check, cpuDeviceStatus, cpuName, cpuSocketDesignation)
            logging.debug('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
            sendToPagerDuty("resolve","snmp/{2}/{0}/{1}".format(hostname,index,current_check.lower()),"No {0} issues detected".format(current_check),msg)
    return total,ok,failed

def querySmRaid(device,hostname):
    # Check all disk related metrics. Consolidate all errors into a single PD alarm per server.

    error_msg = ""
    a_total,a_ok,a_failed = 0,0,0 # adapter
    p_total,p_ok,p_failed = 0,0,0 # physical disk
    v_total,v_ok,v_failed = 0,0,0 # virtual disk
    b_total,b_ok,b_failed = 0,0,0 # battery

    current_check = "RAIDadapter"
    for index in device.raidAdapterIndex:
        a_total += 1
        allowed_status = ["0"]
        raidGroup = device.raidAdapterGroup[index]
        raidProductName = device.raidAdapterProductName[index]
        raidBBUAbsent = device.raidIsBBUAbsent[index]
        raidBBUAbsentIgnored = device.raidIsBBUAbsentIgnored[index]
        raidStatus = device.raidAdapterAllinoneStatus[index]
        raidMsg = device.raidAdapterAllinoneMsg[index]
        if str(raidStatus) not in allowed_status:
            a_failed += 1
            msg = 'Error for {0}: Status = {1}; Msg = {2}; Model = {3};'.format(current_check, raidStatus, raidMsg, raidProductName)
            error_msg += '{0}\n'.format(msg)
            logging.warning('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
        else:
            a_ok += 1
            msg = 'OK for {0}: Status = {1}; Msg = {2}; Model = {3};'.format(current_check, raidStatus, raidMsg, raidProductName)
            logging.debug('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))

    current_check = "PhysicalDisk"
    for index in device.raidPDIndex:
        p_total += 1
        allowed_status = ["0"]
        physDiskSlot = device.raidPDSlotNumber[index]
        physDiskFirmwareState = device.raidPDFirmwareState[index]
        physDiskMediaError = device.raidPDMediaErrorCount[index]
        physDiskOtherError = device.raidPDOtherErrorCount[index]
        physDiskPredFail = device.raidPDPredFailCount[index]
        physDiskInfo = device.raidPDInquiryData[index]
        physDiskSpeed = device.raidPDDeviceSpeed[index]
        physDiskType = device.raidPDMediaType[index]
        physDiskStatus = device.raidPDAllinoneStatus[index]
        physDiskMessage = device.raidPDAllinoneMsg[index]
        if str(physDiskStatus) not in allowed_status:
            p_failed += 1
            msg = 'Error for {0}: Status = {1}; Msg = {2}; MediaError = {3}; OtherError = {4}; PredictiveFail = {5}; Type = {6}; Info = {7}'.format(current_check, physDiskStatus, physDiskMessage, physDiskMediaError, physDiskOtherError, physDiskPredFail, physDiskType, physDiskInfo)
            error_msg += '{0}\n'.format(msg)
            logging.warning('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
        else:
            p_ok += 1
            msg = 'OK for {0}: Status = {1}; Msg = {2}; MediaError = {3}; OtherError = {4}; PredictiveFail = {5}; Type = {6}; Info = {7}'.format(current_check, physDiskStatus, physDiskMessage, physDiskMediaError, physDiskOtherError, physDiskPredFail, physDiskType, physDiskInfo)
            logging.debug('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
      
    current_check = "VirtualDisk"
    for index in device.raidVDId:
        v_total += 1
        allowed_status = ["0"]
        virtDiskRaidLevel = device.raidVDRaidLevel[index]
        virtDiskSize = device.raidVDSize[index]
        virtDiskNumDrives = device.raidVDNumDrives[index]
        virtDiskBadBlocks = device.raidVDBadBlocksExist[index]
        virtDiskState = device.raidVDState[index]
        virtDiskStatus = device.raidVDAllinoneStatus[index]
        virtDiskMsg = device.raidVDAllinoneMsg[index]
        if str(virtDiskStatus) not in allowed_status:
            v_failed += 1
            msg = 'Error for {0}: Status = {1}; Msg = {2}; State = {3}; Level = {4}; Size = {5}; NumDrives = {6}'.format(current_check, virtDiskStatus, virtDiskMsg, virtDiskState, virtDiskRaidLevel, virtDiskSize, virtDiskNumDrives)
            error_msg += '{0}\n'.format(msg)
            logging.warning('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
        else:
            v_ok += 1
            msg = 'OK for {0}: Status = {1}; Msg = {2}; State = {3}; Level = {4}; Size = {5}; NumDrives = {6}'.format(current_check, virtDiskStatus, virtDiskMsg, virtDiskState, virtDiskRaidLevel, virtDiskSize, virtDiskNumDrives)
            logging.debug('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))    

    current_check = "ArrayBattery"
    for index in device.raidBBUIndex:
        b_total += 1
        allowed_status = ["0"]
        bbuStatus = device.raidBBUStatus[index]
        bbuAllInOneStatus = device.raidBBUAllinoneStatus[index]
        bbuMsg = device.raidBBUAllinoneMsg[index]
        if str(bbuAllInOneStatus) not in allowed_status:
            b_failed += 1
            msg = 'Error for {0}: Status = {1}; Msg = {2}; State = {3};'.format(current_check, bbuAllInOneStatus, bbuMsg, bbuStatus)
            error_msg += '{0}\n'.format(msg)
            logging.warning('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))
        else:
            b_ok += 1
            msg = 'OK for {0}: Status = {1}; Msg = {2}; State = {3};'.format(current_check, bbuAllInOneStatus, bbuMsg, bbuStatus)
            logging.debug('{0}\t{2}\t{1}'.format(hostname,msg,current_check.upper()))

    # if error_msg is not empty: send alarm...
    if error_msg != "":
        sendToPagerDuty("trigger","snmp/{0}/{1}".format("raid",hostname),"RAID issue detected on {0}".format(hostname),error_msg)
    else:
        sendToPagerDuty("resolve","snmp/{0}/{1}".format("raid",hostname),"No RAID issues detected on {0}".format(hostname),error_msg)

    return a_total, a_ok, a_failed, p_total, p_ok, p_failed, v_total, v_ok, v_failed, b_total, b_ok, b_failed


# The main monitoring function for HP servers. It verifies it can connect, makes sure the HP agent is working correctly, 
# then calls the relevant query* functions from above. It returns a count of all components it queried and their 
# statuses. 
def queryHPServer(hostname,comm,ver):
    #Create results list
    serverResults = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

    """
    #Ping device
    try:
        response = os.system("ping -c 1 -w2 " + hostname + " > /dev/null 2>&1")
        if response != 0:
            msg = 'Ping test failed for {0}. Return code = {1}. Skipping profile.'.format(hostname,response)
            logging.info('{0}\tPING\t{1}'.format(hostname,msg))
            return [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    except Exception as inst:
        msg = 'Exception occurred while trying to ping {0}. Exception = "{1}"'.format(hostname,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))
    """

    #Set default timeout and retry values
    timeout_value = 5
    retries_value = 3

    #Apply any custom timeout and retry values

    #Adjust Community String as needed
    if hostname in ['<Server not in Salt>','<Server not in Salt>']: comm = '<Your comment>'

    #Connect to device
    try:
        device = M(host=hostname,community=comm,version=ver,timeout=timeout_value,retries=retries_value)
        device_name =  device.sysName #to make sure we actually connected
        msg = 'Successfully connected to {0}.'.format(hostname)
        sendToPagerDuty("resolve","snmp/connect/{0}".format(hostname),"SNMP is responding on {0}".format(hostname),msg)
    except Exception as inst:
        msg = 'Exception occurred while connecting to {0}. Exception = "{1}"'.format(hostname,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))
        t = datetime.datetime.now().timetuple()
        #only generate alarm during the day
        if (t[3]>=7) and (t[3]<=19):
            incident = sendToPagerDuty("trigger","snmp/connect/{0}".format(hostname),"Unable to query SNMP on {0}".format(hostname),msg)
        return [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

    #Make sure HP SNMP agent is responding
    try:
        device_mib = device.cpqSeMibRevMajor
        msg = 'Successfully queried HP SNMP agent on {0}.'.format(hostname)
        sendToPagerDuty("resolve","snmp/hp_agent/{0}".format(hostname),"HP SNMP agent is responding on {0}".format(hostname),msg)
    except Exception as inst:
        msg = 'HP SNMP agent is not responding on {0}. Make sure the latest agent is installed. Restart snmpd and the HP agent to troubleshoot.'.format(hostname)
        logging.warning('{0}    ERROR   {1}'.format(hostname,msg))
        #only generate an alarm during the day
        t = datetime.datetime.now().timetuple()
        if (t[3]>=7) and (t[3]<=19):
            incident = sendToPagerDuty("trigger","snmp/hp_agent/{0}".format(hostname),"HP SNMP agent is not responding on {0}".format(hostname),msg)
        return [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

    #Perform checks, load results into list
    next_check = "queryTemp"
    try:
        serverResults[0:2] = queryTemp(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}	ERROR	{1}'.format(hostname,msg))

    next_check = "queryFans"
    try:
        serverResults[3:5] = queryFans(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}	ERROR	{1}'.format(hostname,msg))

    next_check = "queryPower"
    try:
        serverResults[6:8] = queryPower(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}	ERROR	{1}'.format(hostname,msg))

    next_check = "queryMemory"
    try:
        serverResults[9:11] = queryMemory(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}	ERROR	{1}'.format(hostname,msg))

    next_check = "queryCPU"
    try:
        serverResults[12:14] = queryCPU(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}	ERROR	{1}'.format(hostname,msg))

    next_check = "queryDrives"
    try:
        serverResults[15:23] = queryDrives(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}	ERROR	{1}'.format(hostname,msg))

    next_check = "queryNICs"
    try:
        serverResults[24:26] = queryNics(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}    ERROR   {1}'.format(hostname,msg))

    #Generate an alarm if script could not find anything to monitor
    next_check = "resultsCheck"
    try:
        if sum(serverResults) == 0:
            msg = 'Did not find any hardware components to monitor'
            logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))
            incident = sendToPagerDuty("trigger","snmp/components/{0}".format(hostname),"Unable to monitor any values on {0}. Make sure snmdpd and the HP SNMP agent are working correctly.".format(hostname),msg)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}    ERROR   {1}'.format(hostname,msg))

    #Print and return stats
    logging.info('{0}\tSTATS\t(Checked,OK,Error) || Temp({1},{2},{3}) || Fan({4},{5},{6}) || PSU({7},{8},{9}) || Mem({10},{11},{12}) || CPU({13},{14},{15}) || Disk({16},{17},{18}) || CTRLR({19},{20},{21}) || Accel({22},{23},{24}) || NIC({25},{26},{27})'.format(hostname,*serverResults))
    #print '{0} complete; Checks: {2}; Stats: {1}'.format(hostname,serverResults,(sum(serverResults)/2))
    return serverResults

# Main monitoring function for SuperMicro servers. Same logic as queryHPServer()
def querySmServer(hostname,comm,ver):
    #Set default timeout and retry values
    timeout_value = 15
    retries_value = 2

    #Apply any custom timeout and retry values
    if "<Server name>" in hostname.upper():
        timeout_value = 30
        retries_value = 3

    #Connect to device
    try:
        device = M(host=hostname,community=comm,version=ver,timeout=timeout_value,retries=retries_value)
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
        return [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

    #Make sure SuperMicro SNMP agent is responding
    try:
        sd5version = device.sd5Version[1]
        msg = 'Successfully queried SuperMicro SNMP agent on {0}.'.format(hostname)
        sendToPagerDuty("resolve","snmp/sm_agent/{0}".format(hostname),"SuperMicro SNMP agent is responding on {0}".format(hostname),msg)
    except Exception as inst:
        msg = 'SuperMicro SNMP agent is not responding on {0}. Make sure the latest agent is installed.'.format(hostname)
        logging.warning('{0}    ERROR   {1}'.format(hostname,msg))
        #only generate an alarm during the day
        t = datetime.datetime.now().timetuple()
        if (t[3]>=7) and (t[3]<=19):
            incident = sendToPagerDuty("trigger","snmp/sm_agent/{0}".format(hostname),"SuperMicro SNMP agent is not responding on {0}".format(hostname),msg)
        return [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

    SmServerResults = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    
    #Perform checks, load results into list
    next_check = "querySensors"
    try:
        SmServerResults[0:15] = querySensors(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))
    
    next_check = "querySmMemory"
    try:
        SmServerResults[15:18] = querySmMemory(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

    next_check = "querySmCPU"
    try:
        SmServerResults[18:21] = querySmCPU(device,hostname)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))
    
    next_check = "queryRaid"
    try:
        SmServerResults[21:33] = querySmRaid(device,hostname)
    except Exception as inst:
         msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
         logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))
    
    #Generate an alarm if script could not find anything to monitor
    next_check = "resultsCheck"
    try:
        if sum(SmServerResults) == 0:
            msg = 'Did not find any hardware components to monitor'
            logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))
            incident = sendToPagerDuty("trigger","snmp/components/{0}".format(hostname),"Unable to monitor any values on {0}. Make sure snmpd and the SuperMicro SNMP agent are working correctly.".format(hostname),msg)
    except Exception as inst:
        msg = 'Exception occurred while running "{0}"; Exception = "{1}"'.format(next_check,inst)
        logging.warning('{0}\tERROR\t{1}'.format(hostname,msg))

    logging.info('{0}\tSTATS\t(Checked,OK,Error) || Temp({1},{2},{3}) || PSU({4},{5},{6}) || Fan({7},{8},{9}) || Other({10},{11},{12}) || Status({13},{14},{15}) || Memory({16},{17},{18}) || CPU({19},{20},{21}) || RaidAdap({22},{23},{24}) || PhysDisk ({25},{26},{27}) || VirtDisk ({28},{29},{30}) || RaidBattery ({31},{32},{33})'.format(hostname,*SmServerResults))

    return SmServerResults

# Checks exclusions, loads mibs, checks PD for open incidents, gets device list from Salt, 
# loops through devices and calls appropriate function based on HP vs SuperMicro.
def main():
    logging.info('***************************************************************************')
    logging.info('Starting Script')
    hpCount=0
    smCount=0
    totalHpStats = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    totalSmStats = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

    #Prepare stats file
    touch(docroot + 'snmp_exclusions')
    
    #Populate exclusions from ZooKeeper
    logging.info('ZOOKEEPER\tQuerying ZooKeeper for exclusion list.')
    try:
        populateExclusions('{{ salt['pillar.get']('globals:pillar_branch') }}')
    except Exception as inst:
        msg = 'Exception occurred while querying ZooKeeper. Using existing exclusions file; Exception = "{0}"'.format(inst)
        logging.warning('ZOOKEEPER\tERROR\r{0}'.format(msg))
    
    #Load required MIBs
    load(docroot + "mibs/SNMPv2-MIB")
    load(docroot + "mibs/CPQHOST.MIB")
    load(docroot + "mibs/cpqsinfo.mib")
    load(docroot + "mibs/CPQHLTH.MIB")
    load(docroot + "mibs/cpqida.mib")
    load(docroot + "mibs/cpqstdeq.mib")
    load(docroot + "mibs/cpqnic.mib")
    load(docroot + "mibs/SUPERMICRO-SMI.my")
    load(docroot + "mibs/spot-ssm.my")
    load(docroot + "mibs/SUPERMICRO-HEALTH-MIB.my")

    #Check PagerDuty for open incidents
    try:
        getCurrentAlarms()
    except Exception as inst:
        msg = 'Exception occurred while querying PagerDuty for open incidents; Exception = "{0}"'.format(inst)
        logging.warning('PAGER\tERROR\r{0}'.format(msg))

    #Exclude invalid hosts
    invalid_hosts = ['localhost','host']

    #Set credentials
    comm = 'public'
    ver = 2

    script_start = time.time()
    logging.info('SALT\tQuerying Salt for server list.')
    
    try:
        querySalt('{{ salt['pillar.get']('globals:pillar_branch') }}')
        #querySalt('production')
        os.rename(docroot+'snmp_servers_temp',docroot+'snmp_servers')
    except Exception as inst:
        msg = 'Exception occurred while querying Salt. Using existing server file; Exception = "{0}"'.format(inst)
        logging.warning('SALT\t\tERROR\t{0}'.format(msg))

    serverFile = open(docroot+'snmp_servers','r')
    for line in serverFile:
        details = line.split(',')
        hostname = details[0]
        manufacturer = details[1]
        if (manufacturer in ["HP","Hewlett-Packard"]) and (hostname not in invalid_hosts):
            start = time.time()
            hpCount+=1
            hpStats = queryHPServer(hostname,comm,ver)
            end = time.time()
            print 'HP - {0} - {1} - {2} sec. {3} total sec.'.format(hpCount,hostname,(end-start),(end-script_start))
            for i in range(len(totalHpStats)):
                totalHpStats[i]+=hpStats[i]
        elif manufacturer == "Supermicro":
            start = time.time()
            smCount+=1
            smStats = querySmServer(hostname,comm,ver)
            end = time.time()
            print 'SM - {0} - {1} - {2} sec. {3} total sec.'.format(smCount,hostname,(end-start),(end-script_start))
            for i in range(len(totalSmStats)):
                totalSmStats[i]+=smStats[i]


    logging.info('TOTAL\tSTATS\tHP\t(Checked,OK,Error) || Temp({1},{2},{3}) || Fan({4},{5},{6}) || PSU({7},{8},{9}) || Mem({10},{11},{12}) || CPU({13},{14},{15}) || Disk({16},{17},{18}) || CTRLR({19},{20},{21}) || Accel({22},{23},{24}) || NIC({25},{26},{27}) || Servers({0})'.format(hpCount,*totalHpStats))
    logging.info('TOTAL\tSTATS\tSM\t(Checked,OK,Error) || Temp({1},{2},{3}) || PSU({4},{5},{6}) || Fan({7},{8},{9}) || Other({10},{11},{12}) || Status({13},{14},{15}) || Memory({16},{17},{18}) || CPU({19},{20},{21}) || RaidAdap({22},{23},{24}) || PhysDisk ({25},{26},{27}) || VirtDisk ({28},{29},{30}) || RaidBattery ({31},{32},{33}) || Servers({0})'.format(smCount,*totalSmStats))

    logging.info('Script Complete')

if __name__ == "__main__":
    main()
