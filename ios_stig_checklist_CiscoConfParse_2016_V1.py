#
#ios_stig_checklist_2016_V1.py
#Garry Baker
#26MAY2016
#
#Example of how to run script on Windows:
# py.exe .\L2_STIG_Checklist_CATI_CREATE_CKL.py -s L2 TAJI-N-A068-TCF_15APR2016.cfg
#
#
# PS C:\Users\Garry.L.Baker\Documents\Python_scripts\TAJI> py.exe #.\L2_STIG_Checklist_CATI_CREATE_CKL.py -h
#usage: L2_STIG_Checklist_CATI_CREATE_CKL.py [-h] [-s {L2,L3,IR,PR}]
#                                            [-o OUTPUT]
#                                            config
#
#STIG Checklist Populator
#
#positional arguments:
#  config                configuration file to process
#
#optional arguments:
#  -h, --help            show this help message and exit
#  -s {L2,L3,IR,PR}, --stig {L2,L3,IR,PR}
#                        L2 = Layer 2 Switch .................................
#                        L3 = Layer 3 Switch .................................
#                        IR = Infrastrcture Router ...........................
#                        PR = Perimeter Router
#  -o OUTPUT, --output OUTPUT
#                        Output filename (.ckl auto appended)
#
#
#This is going to parse through a Cisco Layer 2 switch configuration and create a DISA STIG
#checklist file which is V1.2 and will need to be imported using StigVeiwer 2.3 as of #24MAY2016)
#
#The concept for this came from:
# https://github.com/c3isecurity/ios-stig/wiki
#
#Also from Jeremy Broadway's work:
#stig_checklist_cisco.py
#Script that creates a DISA STIG Viewer checklist file based on findings.  I
#probably won't make updates to this as I'll move the functionality into the
#newer program.
#https://software.forge.mil/sf/projects/stig_checklist_creator_cisco_dev
#
#----DEPENDANCIES!!!!!!!!!!!!!!!!------------
# the ciscoconfparse!!!!!!!!!!!!!
# I am leveraging the great work he has done!  
# http://www.pennington.net/py/ciscoconfparse/
#
#
#Importing the necessary modules.
import sys
from sys import argv
#Importing the necessary modules. 
from ciscoconfparse import CiscoConfParse
#from ciscoconfparse import IOSConfigList
import glob
#Modules needed to build the CKL XML file
import xml.etree.ElementTree as ET
import os
import codecs
import re
import sys
import argparse

#CAT1 checks NET_ID
NET0460v = "username "
NET0230v = "aaa new-model"
NET0600v = "service password-encryption"
NET0240v = "vendor default passwords"
NET1636v = "aaa authentication login default "
NET1660v = "snmp-server"
NET1665_publicv = "public"
NET1665_privatev = "private"
NET1623v = "aaa authentication login default "
NET0441v = "username "
#CAT2 checks NET_ID
NET0405 = "service call-home"
# SSH section
NET_1636 = "transport input ssh"
NET1647 = "ip ssh version 2"
#CAT3 checks NET_ID
#Services section
NET0724 = "service tcp-keepalives-in"
NET0722 = "no service pad"
NET0820 = "no ip domain-lookup"
NET0812 = "ntp server"
NET0433 = "server-private"

Passed = 0
#Not a Finding
Failed = 0
#Open
NotApp = 0
#Not Applicable
Manual = 0

def catI_NET0460(NET_ID, CCE_ID):
        NET_Check = parse.find_lines(CCE_ID)
        #print ('\n\n' + cfg_file + '\n')
        #print (NET_Check)
        #print (len(NET_Check))
        if len(NET_Check) != 1:
            #print("=====")
            #print("*Open, more than 1 account found: %r " % NET_ID)
            #print("=====")            
            global Failed
            Failed += 1
            CHECK['NET0460'] = OP
        else:
            #print("Not a Finding: %r" % NET_ID)
            global Passed
            Passed += 1
            CHECK['NET0460'] = NF
            
def catI_NET0812(NET_ID, CCE_ID):
        NET_Check = parse.find_lines(CCE_ID)
        #print ('\n\n' + cfg_file + '\n')
        #print (NET_Check)
        #print (len(NET_Check))
        if len(NET_Check) != 2:
            #print("=====")
            #print("*Open, requiremnet is 2 NTP servers: %r " % NET_ID)
            #print("=====")            
            global Failed
            Failed += 1
            CHECK['NET0812'] = OP
        else:
            #print("Not a Finding: %r" % NET_ID)
            global Passed
            Passed += 1
            CHECK['NET0812'] = NF

            
def catI_NET0433(NET_ID, CCE_ID):
        NET_Check = parse.find_lines(CCE_ID)
        #print ('\n\n' + cfg_file + '\n')
        #print (NET_Check)
        #print (len(NET_Check))
        if len(NET_Check) < 2:
            #print("=====")
            #print("*Open, requiremnet is 2 AAA servers: %r " % NET_ID)
            #print("=====")            
            global Failed
            Failed += 1
            CHECK['NET0433'] = OP
        else:
            #print("Not a Finding: %r" % NET_ID)
            global Passed
            Passed += 1
            CHECK['NET0433'] = NF
            
def catI_NET0441(NET_ID, CCE_ID):
        NET_Check = parse.find_lines(CCE_ID)
        #print ('\n\n' + cfg_file + '\n')
        #print (NET_Check)
        #print (len(NET_Check))
        if len(NET_Check) != 1:
            #print("=====")
            #print("*Open, more than 1 account found: %r " % NET_ID)
            #print("=====")
            global Failed
            Failed += 1
            CHECK['NET0441'] = OP
        else:
            #print("Not a Finding: %r" % NET_ID)
            global Passed
            Passed += 1
            CHECK['NET0441'] = NF
            
def catI_NET0230(NET_ID, CCE_ID):
        NET_Check = parse.find_lines(CCE_ID ,exactmatch=True)
        #print ('\n\n' + cfg_file + '\n')
        if NET_Check == [CCE_ID]:
            #print("Not a Finding: %r" % NET_ID)
            global Passed
            Passed += 1
            CHECK['NET0230'] = NF
        else:
            #print("=====")
            #print("*Open: %r " % NET_ID)
            #print("=====")
            global Failed
            Failed += 1
            CHECK['NET0230'] = OP

def catI_NET0600(NET_ID, CCE_ID):
        NET_Check = parse.find_lines(CCE_ID ,exactmatch=True)
        #print ('\n\n' + cfg_file + '\n')
        if NET_Check == [CCE_ID]:
            #print("Not a Finding: %r" % NET_ID)
            global Passed
            Passed += 1
            CHECK['NET0600'] = NF
        else:
            #print("=====")
            #print("*Open: %r " % NET_ID)
            #print("=====")
            global Failed
            Failed += 1 
            CHECK['NET0600'] = OP

def catI_NET0240(NET_ID, CCE_ID):
        #print ('\n\n' + cfg_file + '\n')
        print("=====")
        print ("*Manual Review Requried: %r" % NET_ID)
        print("=====")
        global Manual
        Manual += 1
        CHECK['NET0240'] = NR


def catI_NET1636(NET_ID, CCE_ID):
        NET_Check = parse.find_lines(CCE_ID)
        #print ('\n\n' + cfg_file + '\n')
        #print (NET_Check)
        #print (len(NET_Check))
        if len(NET_Check) != 1:
            #print("=====")
            #print("*Open: %r " % NET_ID)
            #print("=====")
            global Failed
            Failed += 1  
            CHECK['NET1636'] = OP
        else:
            #print("Not a Finding: %r" % NET_ID)
            global Passed
            Passed += 1
            CHECK['NET1636'] = NF

def catI_NET1623(NET_ID, CCE_ID):
        NET_Check = parse.find_lines(CCE_ID)
        #print ('\n\n' + cfg_file + '\n')
        #print (NET_Check)
        #print (len(NET_Check))
        if len(NET_Check) != 1:
            #print("=====")
            #print("*Open: %r " % NET_ID)
            #print("=====")
            global Failed
            Failed += 1 
            CHECK['NET1623'] = OP
        else:
            #print("Not a Finding: %r" % NET_ID)
            global Passed
            Passed += 1
            CHECK['NET1623'] = NF
            
def catI_NET1660(NET_ID, CCE_ID):
        NET_Check = parse.find_lines(CCE_ID)
        #print ('\n\n' + cfg_file + '\n')
        #print(NET_Check)
        if NET_Check and True:
            #print("SNMP is Enabled: ")
            #print("DO THE NEXT THING")
            NET_Check = parse.find_lines("v3")
            if len(NET_Check) >= 1:
                #print("Not a Finding: %r" % NET_ID)
                global Passed
                Passed += 1 
                CHECK['NET1660'] = NF
            else:
                #print("=====")
                #print("*Open: %r " % NET_ID)
                #print("=====")
                global Failed
                Failed += 1
                #print(NET_Check)
                CHECK['NET1660'] = OP
        else:
            #print("*SNMP is Not Enabled: ")
            global NotApp
            NotApp += 1
            CHECK['NET1660'] = NA
            CHECK['NET1665'] = NA

def check_dot1x_NET_NAC_009():
    ## Search all switch interfaces
    #
    # r'^interface.+?thernet' is a regular expression, for ethernet intfs
        list_of_failed_ints = []
        for intf in parse.find_objects(r'^interface'):
        ##
        #Access command statements to check config for
            is_switchport_access = intf.has_child_with(r'switchport mode access')
            has_port_control_auto = intf.has_child_with(r'authentication port-control auto')
        ##
        ## If statement with and to verify all check statements above
            #print ('\n\n' + cfg_file + '\n')
            #list_of_failed_ints = []
            if is_switchport_access and (not has_port_control_auto):
                #print("=====")
                print("*Open: 'NET-NAC-009 dot1x' :", intf.text)
                #list_of_failed_ints = []
                list_of_failed_ints.append(intf.text)
                #print(list_of_failed_ints)
                #failed_check = []
                #print("=====")
                global Failed
                Failed += 1
                CHECK['NET-NAC-009'] = OP
                #for line in list_of_failed_ints:
                    #print (line)
                    #list_of_failed_string = ''.join(list_of_failed_ints)
                    #print ("\nInterfaces that failed")
                    #print (list_of_failed_ints)
                    #YOUR_FINDING['NET-NAC-009'] = list_of_failed_string
                    #print(YOUR_FINDING)
            else:
                #print("Not a Finding: 'NET-NAC-009 dot1x'" )
                global Passed
                Passed += 1
                #CHECK['NET-NAC-009'] = NF
            #list_of_failed_ints = []
            for line in list_of_failed_ints:
                #print (line)
                list_of_failed_string = '\n'.join(list_of_failed_ints)
                #print ("\nInterfaces that failed")
                #print (list_of_failed_ints)
                YOUR_FINDING['NET-NAC-009'] = list_of_failed_string
                #print(YOUR_FINDING)

                
def check_dot1x_NET_VLAN_007():
    ## Search all switch interfaces
    #
    # r'^interface.+?thernet' is a regular expression, for ethernet intfs
        for intf in parse.find_objects(r'^interface.+?thernet'):
        ##
        #Access command statements to check config for
            is_switchport_access = intf.has_child_with(r'switchport mode access')
            is_switchport_trunk = intf.has_child_with(r'switchport mode trunk')
        ##
        ## If statement with and to verify all check statements above
            #print ('\n\n' + cfg_file + '\n')
            if is_switchport_access or is_switchport_trunk:
                #print("Not a Finding: 'NET-NAC-007 '" )
                global Passed
                Passed += 1
                CHECK['NET-VLAN-007'] = NF
            else:
                #print("=====")
                #print("*Open: 'NET-NAC-007 not static access or trunk' :", intf.text)
                #print("=====")
                global Failed
                Failed += 1
                CHECK['NET-VLAN-007'] = OP


def check_dot1x_NET_VLAN_008():
    ## Search all switch interfaces
    #
    # r'^interface.+?thernet' is a regular expression, for ethernet intfs
        for intf in parse.find_objects(r'^interface.+?thernet'):
        ##
        #Access command statements to check config for
            is_switchport_trunk = intf.has_child_with(r'switchport mode trunk')
            has_native_vlan = intf.has_child_with(r'switchport trunk native vlan ')
        ##
        ## If statement with and to verify all check statements above
            #print ('\n\n' + cfg_file + '\n')
            #print (has_native_vlan)
            if is_switchport_trunk and (not has_native_vlan):
                #print("=====")
                #print("*Open: 'NET-NAC-008 no native vlan' :", intf.text)
                #print("=====")
                global Failed
                Failed += 1
                CHECK['NET-VLAN-008'] = OP
            else:
                #print("Not a Finding: 'NET-NAC-009 dot1x'" )
                global Passed
                Passed += 1
                #CHECK['NET-VLAN-008'] = NF             
                
def check_logging_NET1021():
    ## Search all switch interfaces
        #logging = parse.find_objects(r'logging')
        ##
        #Access command statements to check config for
        #print(logging)
        is_logging_debug = parse.has_line_with(r'logging trap debugging')
        is_logging_informational = parse.has_line_with(r'logging trap informational')
        #verify there is a logging host with an IP address
        is_logging_host = parse.has_line_with(r'logging \b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        ##
        ## If statement with and to verify all check statements above
            #print ('\n\n' + cfg_file + '\n')
            #print(is_logging_host)
        if is_logging_debug or is_logging_informational and is_logging_host:
            #print("Not a Finding: 'NET1021 logging'" )
            global Passed
            Passed += 1
            CHECK['NET1021'] = NF
        else:
            #print("=====")
            #print("*Open: 'NET1021 logging'")
            #print("=====")
            global Failed
            Failed += 1
            CHECK['NET1021'] = OP
                

                

def check_printer_vlan_NET_VLAN_023():
    ## Search for printer vlan
    #
    # r'^vlan' is a regular expression, for vlans
        for vlan in parse.find_objects(r'^vlan'):
        ##
        #Access command statements to check config for
            #is_printer_vlan = vlan.has_child_with(r'[Pp][Rr][Ii][Nn][Tt][Ee][Rr]')
            #print (vlan)
            is_printer_vlan = vlan.has_child_with(r'name (?i).*printer.*')
            #print(is_printer_vlan)
        ##
        ## If statement with and to verify all check statements above
            #print ('\n\n' + cfg_file + '\n')
            if is_printer_vlan:
               #print("Not a Finding: 'NET-VLAN-023'" )
               global Passed
               Passed += 1
               CHECK['NET-VLAN-023'] = NF
            else:
               #print("=====")
               #print("*Open: 'NET-VLAN-023' :", intf.text)
               #print("=====")
               global Failed
               Failed += 1
               #CHECK['NET-VLAN-023'] = OP


               
def check_VTY_ACL_NET1637():
    ## Search for LINE VTY access-list name then check if that ACL has log keyword
    #
    #cisco_cfg = CiscoConfParse(cisco_file)
    vty_acl = parse.find_objects(r'access-class')

    # Find the ACL name
    acl_name = ''
    for entry in vty_acl:
        if 'line vty' in entry.parent.text:
            match = re.search(r'access-class (.*) in', entry.text)
            if not acl_name:
                acl_name = match.group(1)
            else:
                new_acl_name = match.group(1)
                if new_acl_name != acl_name:
                    raise ValueError("ACL names do not match")

    if not acl_name:
        raise ValueError("ACL not found under line vty")

    the_acl = r"ip access-list extended {}".format(acl_name)
    acl_object = parse.find_objects(the_acl)[0]

    # Parse the ACL lines looking for 'log' keyword    
    log_lines = []
    no_log_lines = []
    for line in acl_object.all_children:
        if 'permit' in line.text or 'deny' in line.text:
            if 'log' in line.text:
                log_lines.append(line.text)
            else:
                no_log_lines.append(line.text)

    print ("\nLines with log")
    print ('#' * 50)
    for line in log_lines:
        print (line)
    print ('#' * 50)
    

    print ("\nLines without log")
    print ('#' * 50)
    for line in no_log_lines:
        print (line)
        no_log_string = '\n'.join(no_log_lines)
        #print(no_log_string)
        YOUR_FINDING['NET1637'] = no_log_string
    print ('#' * 50)
    print ()
    
    #log_lines = log_lines.split()
    #print (log_lines)
    
    if ' log' in line:
        #print("NOT A Finding: 'NET1637' VTY ACL")
        global Passed
        Passed += 1
        CHECK['NET1637'] = NF
    else:
        #print("*Open: 'NET1637' VTY ACL")
        global Failed
        Failed += 1
        CHECK['NET1637'] = OP
        
    
        
def check_Native_Vlan_NET_VLAN_009():
    ## Search for Native Vlan on TRUNKS and make sure not used on any access ports
    #
    #
    native_vlan = parse.find_objects(r'switchport trunk native vlan')
    #print(native_vlan)

    # Find the ACL name
    native_vlan_number = ''
    for entry in native_vlan:
        if 'interface' in entry.parent.text:
            match = re.search(r'switchport trunk native vlan (.*)', entry.text)
            if not native_vlan_number:
                native_vlan_number = match.group(1)
            else:
                new_native_vlan_name = match.group(1)
                #if new_native_vlan_name != native_vlan_number:
                    #raise ValueError("ACL names do not match")

    #if not native_vlan_number:
        #raise ValueError("ACL not found under line vty")
            
    the_native_vlan_number = r"{}".format(native_vlan_number)
    str(the_native_vlan_number)
    print(the_native_vlan_number)
    #native_vlan_object = parse.find_objects(the_native_vlan_number)[0]
    #print(native_vlan_object)
                    
               
            
# def to find_lines in the config. Good for finding simple configs.
# exmaple "ip ssh version 2".  Use exactmatch to match exactly.
def check(NET_ID, CCE_ID):
    NET_Check = parse.find_lines(CCE_ID ,exactmatch=True)
    if NET_Check == [CCE_ID]:
        #print("PASS: %r" % NET_ID)
        global Passed
        Passed += 1
        CHECK[NET_ID] = NF
    else:
        #print("FAIL: %r " % NET_ID) 
        global Failed
        Failed += 1 
        CHECK[NET_ID] = OP

            
def L2_switch():
    #print("L2 Switch Checks")
    #global cfg_file
    #for cfg_file in cfg_files:
    #    parse = CiscoConfParse(cfg_file)
    catI_NET0230("NET0230 AAA", NET0230v)
    catI_NET0460("NET0460 username", NET0460v)
    catI_NET0600("NET0600 Password Encryption setting", NET0600v)
    catI_NET0240("NET0240 vendor default passwords", NET0240v)
    catI_NET1636("NET1636 VTY AAA aaa authentication login default", NET1636v)
    #Need if elif statements in def to check for SNMP then check for v3
    catI_NET1660("NET1660 SNMP Version 3", NET1660v)
    #Need to find regex for public/private snmp strings in IOS config
    #check("NET1665 SNMP public", NET1665_publicv)
    #check("NET1665 SNMP private", NET1665_privatev)
    catI_NET1623("NET1623 CON AAA aaa authentication login default", NET1623v)
    #Need to look at a better format for output and counting dot1x interfaces
    check_dot1x_NET_NAC_009()
    #This is the same as the catI_NET0460, added for ease of counting CAT I at this point
    catI_NET0441("NET0441 username", NET0441v)
    #MISC Checks for CAT2 and CAT3 for exact string matches
    #
    # SSH checks
    check ("NET1647", NET1647)
    #Services checks
    check ("NET0724", NET0724)
    check ("NET0722", NET0722)
    check ('NET0820', NET0820)
    check ('NET0405', NET0405)
    catI_NET0812 ('NET0812', NET0812)
    catI_NET0433 ('NET0433', NET0433)
    #check for vlan with descpription of "printer"
    check_printer_vlan_NET_VLAN_023 ()
    check_logging_NET1021 ()
    check_dot1x_NET_VLAN_007 ()
    check_dot1x_NET_VLAN_008 ()
    check_VTY_ACL_NET1637 ()
    check_Native_Vlan_NET_VLAN_009 ()
    
            
def start():
    print("\n")
    print(CFG)
    #script, input_file = CFG
    input_file = CFG
    print("\nPython Cisco IOS STIG checker. Using ciscoconfparse")
    print("version 0.01a\n")
    print("Starting IOS STIG check")
    global parse
    parse = CiscoConfParse (input_file)
    print("Opening config file: %r\n" % input_file)
    #Infra_router()
    #Perimeter_router()
    #Perimeter_L3_switch()
    #Infra_L3_switch()
    #L2_switch()
    #Going to try and insert CKL XML file maker here
    #from Jeremey Broadway's stig_checklist_cisco.py script
    #STIG Variables
    #Only set ones that do not require manual review
    global NR
    global NA
    global OP
    global NF
    global FD
    NR = "Not_Reviewed"
    NA = "Not_Applicable"
    OP = "Open"
    NF = "NotAFinding"
    FD = "Finding_Details"

#Start with L2 Checks
#I have started each CHECK as NR(Not Reviewed)
    
    global CHECK
    CHECK = { 'NET0230': NR,
              'NET0405': NR,
              'NET0440': NR,
              'NET0460': NR,
              'NET0465': NR,
              'NET0470': NR,
              'NET0600': NR,
              'NET0720': NR,
              'NET0722': NR,
              'NET0724': NR,
              'NET0730': NR,
              'NET0740': NR,
              'NET0744': NR,
              'NET0820': NR,
              'NET0965': NR,
              'NET1021': NR,
              'NET1030': NR,
              'NET1624': NR,
              'NET1636': NR,
              'NET1638': NR,
              'NET1639': NR,
              'NET1645': NR,
              'NET1646': NR,
              'NET1647': NR,
              'NET1665': NR,
              'NET0722': NR,
              'NET0820': NR,
              'NET0405': NR,
              'NET0726': NR,
              'NET0750': NR,
              'NET0760': NR,
              'NET0770': NR,
              'NET0781': NR,
              'NET0790': NR,
              'NET0897': NR,
              'NET0898': NR,
              'NET0899': NR,
              'NET0900': NR,
              'NET0901': NR,
              'NET0902': NR,
              'NET0812': NR,
              'NET-VLAN-023': NR,
              'NET1021': NR,
              'NET0433': NR,
              'NET-VLAN-007': NR,
              'NET1637': NR,
#NET-NAC-009 802.1x check set to NF and will only be "checked" if it finds an interface with no 'auth'
#NET-VLAN-008Checking trunk for 'native vlan' configuration
              'NET-NAC-009': NF,
              'NET-VLAN-008': NF,
#All that are considered NA (Not Applicable) for Layer 2 devices, IOS defaults and services that are not on L2 switches, also all OOB (Out of Band Management)
              'NET0987': NA,
              'NET0988': NA,
              'NET0989': NA,
              'NET0992': NA,
              'NET0993': NA,
              'NET1007': NA,
              'NET1008': NA,
              'NET0730': NA,
              'NET0720': NA,
              'NET0744': NA,
              'NET0965': NA,
              'NET1629': NA,
              'NET0991': NA,
              'NET0994': NA,
              'NET0995': NA,
              'NET0996': NA,
              'NET0997': NA,
              'NET0990': NA,
              'NET-NAC-032': NA,
              'NET-NAC-031': NA,
#Currently on MD5 is supported for NTP so marking as NA
              'NET0813': NA,
#These all need to be reviewed manaually with online access to the CLI
              'NET1030': NR,
              'NET0240': NR
          }
          
    global YOUR_FINDING
    YOUR_FINDING = {'NET1637': FD
          }
    
    with codecs.open(CFG, 'r', encoding='utf-8') as fi:
        L2_switch()
    fi.close()
          
    tree = ET.parse(CKL)
    root = tree.getroot()

#
# There is probably a better way to do this
# but checklist files don't do a
# <vuln id=123>data</vuln> in order to search by ID
# so have to check data within each <vuln></vuln> section
# as I do not know of a better way to search through
# the XML.
#

    key = ""
#for vuln in root:
#    key = ""
#    for stig in vuln:
#        for data in stig:
#            if data.text in CHECK:
#                #CHECK[data.text][1] = 1
#                key = data.text
#
#        if stig.tag == "STATUS" and len(key) > 0:
#            stig.text = CHECK[key]

    for stig in root:
    
        for istig in stig:
            for vuln in istig:
                key = ""
                for data in vuln:
                    for attrib in data:
                        if attrib.text in CHECK:
                            key = attrib.text
                            #print (key)

                    if data.tag == "STATUS" and len(key) > 0:
                        #print(data.text)
                        data.text = CHECK[key]
                        #print(data.text)
                        #print(CHECK)
                    
                        
        
            
    tree.write(OUT_CKL, encoding="UTF-8", xml_declaration=True, method="xml", short_empty_elements=False)
    
    
    for stig_2 in root:
    
        for istig in stig_2:
            for vuln in istig:
                key = ""
                for data_2 in vuln:
                    for attrib in data_2:
                        if attrib.text in YOUR_FINDING:
                            key = attrib.text
                            #print(key)

                    if data_2.tag == "FINDING_DETAILS" and len(key) > 1:
                        #print(data_2.text)
                        data_2.text = YOUR_FINDING[key]
                        #print(data_2.text)
                        #print(YOUR_FINDING)
                 
    tree.write(OUT_CKL, encoding="UTF-8", xml_declaration=True, method="xml", short_empty_elements=False)
    

#
# Work around weird python or DISA xml markup issue
# by replacing the xml output saved above with what
# the DISA STIG Viewer requires to work correctly.
#
    nline1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
    nline2 = "<CHECKLIST>\n"
    nline12 = "           <AV_NAME xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xsi:type=\"xs:string\">ROLE</AV_NAME>\n"
    nline13 = "           <AV_DATA xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xsi:type=\"xs:string\">Role</AV_DATA>\n"

    TMP = "tmp.ckl"
    with codecs.open(OUT_CKL, 'r', encoding='utf-8') as fi, \
        codecs.open(TMP, 'w', encoding='utf-8') as fo:
        x = 1
        for line in fi:
            if x == 1:
                fo.write(nline1)
            elif x == 2:
                fo.write(nline2)
        #elif x == 12:
        #    fo.write(nline12)
        #elif x == 13:
        #    fo.write(nline13)
            else:
                fo.write(line)
            x += 1

    fi.close()
    fo.close()
    os.remove(OUT_CKL)
    os.rename(TMP,OUT_CKL)
    #
    
    #This will print the Findings on the screen
    print("\n\n")
    print("   NET CHECKS: %r" % (Passed + Failed + NotApp + Manual))
    print("-----------------")
    print("Not a Finding: %r" % Passed)
    print("           NA: %r" % NotApp)
    print("         Open: %r" % Failed)
    print("       Manual: %r" % Manual)
    print("\n\n")

    
# START of the program
def usage():
    print  ("""
IOS-STIG Checker
Version 0.01a 
Windows Usage:  py.exe .\L2_STIG_Checklist_CATI_CREATE_CKL.py <IOS_CONFIG_FILE> 
""")
    sys.exit(1)

def main():
#Orginal args options
#    args = sys.argv[1:]
#    if len(args) == 1:
#        start()
#    else:
#        usage()
#Going to try and insert CKL XML file maker here
#from Jeremey Broadway's stig_checklist_cisco.py script
#STIG Variables
    L2 = "U_Network_L2_Switch_Cisco_V8R19_Manual.ckl"
    L3 = "U_Network_Infrastructure_L3_Switch_Cisco_V8R19_Manual.ckl"
    IR = "U_Network_Infrastructure_Router_Cisco_V8R19_Manual.ckl"
    PR = "U_Network_Perimeter_Router_Cisco_V8R21_Manual.ckl"

    parser  = argparse.ArgumentParser(description="STIG Checklist Populator")
    parser.add_argument("config", type=str, help="configuration file to process")
    parser.add_argument("-s", "--stig",
                    help="L2 = Layer 2 Switch .................................\
                    L3 = Layer 3 Switch .................................\
                    IR = Infrastrcture Router ...........................\
                    PR = Perimeter Router",
                    action="store", choices=("L2", "L3", "IR", "PR"),
                    default="L2")
    parser.add_argument("-o", "--output", help="Output filename (.ckl auto appended)", action="store",
                    default="NONE")
    args = parser.parse_args()

    global CKL
    if args.stig == "L2":
        CKL = L2
    elif args.stig == "L3":
        CKL = L3
    elif args.stig == "IR":
        CKL = IR
    elif args.stig == "PR":
        CKL = PR
    
    global CFG
    CFG=args.config
    #print(CFG)
    
    global OUT_CKL
    if args.output == "NONE":
        l = len(CFG)
        if l > 4 and CFG[l - 4] == ".":
            OUT_CKL = CFG[:l - 3] + "ckl"
        else:
            OUT_CKL = CFG + ".ckl"
    else:
        OUT_CKL = args.output + ".ckl"
    start()


if __name__ == "__main__":
    main()