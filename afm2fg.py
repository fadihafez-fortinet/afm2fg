#!/usr/bin/python3
#
# Author: Fadi Hafez (Fortinet)
# Conversion from AFM to FG
# AFM version 15.1.2.1
#
# versions:
#   1.0.0 (May 2, 2022): 
#   - First version created


from asyncio.constants import DEBUG_STACK_DEPTH
from errno import errorcode
import fcntl, os, sys, io, json
from lib2to3.pygram import python_grammar_no_print_statement
from multiprocessing.sharedctypes import Value
from ssl import PROTOCOL_TLS_SERVER
from pydoc import describe
from tkinter.messagebox import NO
from unicodedata import name
from unittest import skip
from xml.sax.handler import property_xml_string
import re

module_names = ["net","security","pem","auth","sys","ltm","cm","cli"]
modules = {}

attempt_num = 12

protocol_numbers = {
    'ospf': 84,
    'pim': 103,
    'igmp': 2
}

port_lookups = {
    "22": "SSH",
    "443": "HTTPS",
    "69": "TFTP",
    "21": "FTP"
}

class Address:
    name = ""
    ipver = [4, 6]
    types = ["range","subnet"]
    type = ""
    value = ""
    start_ip = ""
    end_ip = ""

    def getAddress(self):
        return self.value

    def __init__(self) -> None:
        pass

    def __init__(self, name, ipver, type, value):
        self.name = name
        self.ipver = ipver
        self.type = type

        if "." in value and "-" not in value and "/" not in value:
            self.value = value + "/32"
        else:
            self.value = value

        if type == "range":
            self.start_ip = value.split("-")[0]
            self.end_ip = value.split("-")[1]
        

class Port:
    value = 0
    name = ""
    type = ""    # ports | port-lists
    description = ""
    comment = ""
    protocol = ""
    ports = []

    def getPort(self):
        return self.ports

    def __init__(self) -> None:
        pass

    def __init__(self, name, value, comment):
        self.name = name
        self.ports = value
        self.comment = comment


class Rule:   

    name = ""
    action = "" # action = accept | accept-decisively | drop | reject
    description = ""
    protocol = ""
    log = False
    rule_number = -1
    destination = {
        "addresses": [Address],
        "ports": [Port]
    }
    source = {
        "addresses": [Address],
        "ports": [Port]
    }

    def printFGFormattedAddress():
        pass

    def __init__(self, name, action, description, protocol, log, rule_number, source, destination) -> None:
        self.name = name or ""
        self.action = action or "accept-decisively"
        self.description = description or ""
        self.protocol = protocol or "tcp"
        self.log = log or False
        self.rule_number = rule_number or -1
        self.source = source or {}
        self.destination = destination or {}
        self.description = description or ""
        
    pass

class Policy:
    name = ""
    rule_list = []
    rule_numbers = []

    srcintf = "any"
    dstintf = "any"
    schedule = "always"
    nat = "disable"
    service = "ALL"
    action = "deny"

    def printDstSrcAddresses(self, dst_address_list, src_address_list):
        ipv4_dst_addresses = []
        ipv6_dst_addresses = []
        ipv4_src_addresses = []
        ipv6_src_addresses = []

        for a in dst_address_list:
            if "-" in a:
                if ":" in a:
                    ipv6_dst_addresses.append(a + "_range")
                else:
                    ipv4_dst_addresses.append(a + "_range")
            else:
                if ":" in a:
                    ipv6_dst_addresses.append(a)
                else:
                    ipv4_dst_addresses.append(a)

        for a in src_address_list:
            if "-" in a:            
                if ":" in a:
                    ipv6_src_addresses.append(a + "_range")
                else:
                    ipv4_src_addresses.append(a + "_range")
            else:
                if ":" in a:
                    ipv6_src_addresses.append(a)
                else:
                    ipv4_src_addresses.append(a)


        if len(ipv4_dst_addresses):
            print("        set dstaddr ", end="")
            print(*ipv4_dst_addresses, sep=' ')
            print("")
        elif len(ipv4_src_addresses) > 0:
            print("        set dstaddr all")

        if len(ipv6_dst_addresses):
            print("        set dstaddr6 ", end="")
            print(*ipv6_dst_addresses, sep=' ')
            print("")
        elif len(ipv6_src_addresses) > 0:
            print("        set dstaddr6 all")

        if len(ipv4_src_addresses):
            print("        set srcaddr ", end="")
            print(*ipv4_src_addresses, sep=' ')
            print("")
        elif len(ipv4_dst_addresses) > 0:
            print("        set srcaddr all")

        if len(ipv6_src_addresses):
            print("        set srcaddr6 ", end="")
            print(*ipv6_src_addresses, sep=' ')
            print("")
        elif len(ipv6_dst_addresses) > 0:
            print("        set srcaddr6 all")

    def printDstPorts(self, dst_ports_list):

        if len(dst_ports_list) == 0:
            print("        set service ALL_TCP ALL_UDP")
            return

        print("        set service ", end="")

        for s in dst_ports_list:
            if len(s) > 78:
                shortname, c = shortenServiceName(s)
                print(shortname + " ", end="")
            else:
                print(s + " ", end="")

        print("")

    def printService(self, protocol):
        if protocol == "tcp":
            print("        set service ALL_TCP")
        elif protocol == "udp":
            print("        set service ALL_UDP")

    def printAction(self, action):
        if action == "accept-decisively":
            print("        set action accept")

    def printLog(self, log):
        if log == 1:
            print("        set logtraffic all")

    def printFGFormmattedFWPolicy(self):

        rule_list_counter = 0

        print("config firewall policy")

        for rl in self.rule_list:
            overall_rule_num = 1
            
            rule_pre_name = shortenRuleName(self.name)

            for r in rl:
                rule_name = shortenRuleName(r.name)
                rule_number = 100000 * int(self.rule_numbers[rule_list_counter]) + 1000 * overall_rule_num + 10 * int(r.rule_number)
                print("# " + self.name + "__" + r.name)
                # print("    edit " + self.rule_numbers[rule_list_counter] + str(overall_rule_num) + r.rule_number)
                # print("    edit " + str(rule_number))
                print("    edit 0")
                print("        set name " + rule_pre_name + "__" + rule_name + "att_" + str(attempt_num))
                print("        set srcintf " + self.srcintf)
                print("        set dstintf " + self.dstintf)
                print("        set comments " + self.name + "_" + r.name)

                self.printDstSrcAddresses(r.destination["addresses"], r.source["addresses"])
                self.printDstPorts(r.destination["ports"])
                # self.printService(r.protocol)
                self.printAction(r.action)
                self.printLog(r.log)

                print("        set schedule always")
                print("    next")

                overall_rule_num += 1
            print("")
            rule_list_counter += 1
        
        print("end")

    def validate(self):

        errorcount = 0

        for rl in self.rule_list:
            for r in rl:
                
                # validate the destnation addresses exist in the global addresses list
                for a in r.destination["addresses"]:
                    if a not in addresses:
                        print("validation error, policy name: " + r.name + " destination address not found: " + a)
                        errorcount += 1

                # validate the source addresses exist in the global addresses list
                for a in r.source["addresses"]:
                    if a not in addresses:
                        print("validation error, policy name: " + r.name + " source address not found: " + a)
                        errorcount += 1

                # validate the destination service exists in the global ports list
                for p in r.destination["ports"]:
                    if len(p) > 78:
                        continue
                    port_found = False
                    for gp in ports:
                        if gp.name == p:
                            port_found = True
                            break
                    if not port_found:
                        print("validation error, policy name:  " + r.name + " destination service not found: " + p)
                        errorcount += 1                        

                # validate the destination service exists in the global ports list
                for p in r.source["ports"]:
                    if len(p) > 78:
                        continue
                    port_found = False
                    for gp in ports:
                        if gp.name == p:
                            port_found = True
                            break
                    if not port_found:                        
                        print("validation error, policy name: " + r.name + " source service not found: " + p)
                        errorcount += 1                        

        print(str(errorcount) + " errors found in policy")


    def __init__(self, name, rules, rule_numbers) -> None:
        self.name = name
        self.rule_list = rules
        self.rule_numbers = rule_numbers

# end Class Policy



addresses = {}
ports = [Port]
# rules = [Rule]
rules_list = {}
policies = []
policy_names = []
global_rule_number = 0


def shortenRuleName(rule_name):
    new_name = ""

    if len(rule_name) < 40:
        return rule_name

    orig_name = rule_name.strip("_").strip("-").split("_")
    for i in orig_name:
        if len(i) == 0:
            continue
        new_name += i[0]

    if new_name in policy_names:
        num_of_new_names = policy_names.count(new_name)
        policy_names.append(new_name)
        new_name += str(num_of_new_names)
    else:
        policy_names.append(new_name)

    return new_name
# end shortenRuleName

def parseRule(rule):
    pass

# take an array of configuration and return a dictionary
def dictify(arr):

    obj = {}
    val_arr = []
    i = 0

    while i < len(arr):
        l = arr[i]
        if l.endswith('{ }'):
            val_arr.append(l.split()[0])

        elif l.endswith('{'):
            k = l.split()[0]
            obj[k], skip_lines = dictify(arr[i+1:])
            i += skip_lines

        elif l.endswith('}'):
            if len(val_arr) > 0:
                return val_arr, i+1
            else:
                return obj, i+1

        elif len(l.split()) == 2:
            k,v = l.split()
            obj[k] = v

        elif len(l.split()) == 1:
            val_arr.append(l)

        i += 1
    
    return obj


def parseList(items):

    item_list = []
    curr_item = []
    brace_count = 0

    # put each rule into an array and pass it to parseRule
    for line in items:
        curr_item.append(line)

        if line.endswith("{ }"):
            continue
        if line.endswith("{"):
            brace_count += 1
        elif line.endswith("}"):
            brace_count -= 1

        if brace_count == 0:
            item_list.append(dictify(curr_item))
            curr_item = []
    
    return item_list

# enddef parseList


def parseLists(list, list_type, name):

    linenum = 0
    curr_list = {
        "name": name,
    }

    for line in list:
        if line.startswith(list_type + ' {'):
            linenum += 1
            curr_list[list_type] = parseList(list[linenum:])
        
        linenum += 1
    
    return curr_list
    
# enddef parseLists

def readKeyValues(f):

    linenum = 0
    kv = {}
    arr = []

    for line in f:
        linenum += 1
        #print(str(linenum) + ": " + line, end='')

        # entering a module
        """         if line.find("{") >= 0 and line.split()[0] in modules:
            modname = line.split()[1]
            print("entering module " + modname)
            kv[modname] = readKeyValues(f)
            return kv """

        if line.find("{") > -1:
            keyname = line.split()[0]
            print("entering values")
            kv[keyname] = readKeyValues(f)
        elif line.find("}") > -1:
            print("exiting values or module")
            if len(arr) > 0:
                return arr
            else:
                return kv
        elif len(line.split()) == 2:
            keyname, val = line.split()
            kv[keyname] = val
        elif len(line.split()) == 1:
            keyname = line.strip()
            arr.append(keyname)

# enddef readKeyValues

# read section until section ending }
# return an array with all the lines in the section
def readSection(f):

    t = []
    brace_level = 1
    for l in f:
        t.append(l.strip())
        if l.find("{") > -1:
            brace_level += 1
        if l.find("}") > -1:
            brace_level -= 1
            if (brace_level == 0):
                break
    return t

# enddef readSection

def processAuth(section):
    # print(section)
    modules['auth']['afm_config'].append(section)
    return 0

# enddef processAuth

def processCM(section):
    # print(section)
    modules['cm']['afm_config'].append(section)
    return 0

# enddef processCM

def removeCommonPrepend(name):
    if name.lower().startswith('/common/'):
        return name.split('/')[-1]
    else:
        return name

# enddef removeCommonPrepend

def processNet(section):
    # print(section)
    modules['net']['afm_config'].append(section)

    type = section[0].split()[1]
    name = removeCommonPrepend(section[0].split()[2])
    if type == "address-list":
        addresses = parseList(section)
        if "addresses" in addresses[0]['net']:
            modules['net']['address_lists'][name] = {'name': name, 'type': 'addresses', 'addresses': addresses[0]['net']['addresses']}
        elif "address-lists" in addresses[0]['net']:
            modules['net']['address_lists'][name] = {'name': name, 'type': 'address-lists', 'addresses': addresses[0]['net']['address-lists']}

    elif type == "port-list":
        ports = parseList(section)
        if "port-lists" in ports[0]['net']:
            modules['net']['port_lists'][name] = {'name': name, 'type': 'port-lists', 'ports': ports[0]['net']['port-lists']}

        if "ports" in ports[0]['net']:
            modules['net']['port_lists'][name] = {'name': name, 'type': 'ports', 'ports': ports[0]['net']['ports']}

    return 0

# enddef processNet

def processSecurity(section):
    # print(section)
    modules['security']['afm_config'].append(section)
    
    type = section[0].split()[2]
    name = removeCommonPrepend(section[0].split()[3])
    if (type == "rule-list"):
        modules['security']['rule_lists'].append(parseLists(section, 'rules', name))

    elif (type == "address-list"):
        addresses = parseList(section)
        if "addresses" in addresses[0]['security']:
            modules['security']['address_lists'][name] = {'name': name, 'type': 'addresses', 'addresses': addresses[0]['security']['addresses'] }
        elif "address-lists" in addresses[0]['security']:
            modules['security']['address_lists'][name] = {'name': name, 'type': 'address-lists', 'addresses': addresses[0]['security']['address-lists'] }

    elif type == "port-list":
        ports = parseList(section)
        if "port-lists" in ports[0]['security']:
            modules['security']['port_lists'][name] = {'name': name, 'type': 'port-lists', 'ports': ports[0]['security']['port-lists']}

        if "ports" in ports[0]['security']:
            modules['security']['port_lists'][name] = {'name': name, 'type': 'ports', 'ports': ports[0]['security']['ports']}

    elif (type == "policy"):
        modules['security']['policy_lists'].append(parseLists(section, 'rules', name))

    return 0

# enddef processSecurity

def processPEM(section):
    # print(section)
    modules['pem']['afm_config'].append(section)
    return 0

# enddef processPEM

def processSYS(section):
    # print(section)
    modules['sys']['afm_config'].append(section)
    return 0

# enddef processSYS

def processLTM(section):
    # print(section)
    modules['ltm']['afm_config'].append(section)
    return 0

# enddef processLTM

def processCLI(section):
    # print(section)
    modules['cli']['afm_config'].append(section)
    return 0

# enddef processCLI

def getModuleName(str):
    return str.split(' ',1)[0]

# enddef getModuleName

def readModuleValues(f):

    fullconfig = {}
    kv = {}
    imodarr = []
    mt = []

    # loop through all the lines of the configuration and group the lines of a section (address-list for example)
    # into an array called section_array
    for line in f:

        # ignore all lines that have { } - empty configuration element
        if line.find("{ }") > -1 or line.find("{}") > -1:
            # print(line.strip())
            continue

        # ignore all lines that start with #
        if line.find('#') == 0:
            continue

        if len(line.strip()) == 0:
            continue

        section_array = []

        modname = getModuleName(line)
        section_array.append(line.strip())
        section_array.extend(readSection(f))

        if modname == "auth":
            processAuth(section_array)
        elif modname == "cm":
            processCM(section_array)
        elif modname == "net":
            processNet(section_array)
        elif modname == "security":
            processSecurity(section_array)
        elif modname == "pem":
            processPEM(section_array)
        elif modname == "sys":
            processSYS(section_array)
        elif modname == "ltm":
            processLTM(section_array)
        elif modname == "cli":
            processCLI(section_array)

    return(fullconfig)

# enddef readModuleValues

def createFGAddressGroups():

    for address_list in modules['net']['address_lists']:
        pass

    for address_list in modules['security']['address_lists']:
        pass

# enddef createFGAddressGroups

def createFGAddresseObjects():

    for address_list_name, address_list in modules['net']['address_lists'].items():

        if address_list['type'] == "addresses":
            for a in address_list['addresses']:
                createFGAddress(address_list_name, removeCommonPrepend(a))

        if address_list['type'] == "address-lists":
            for a in address_list['addresses']:
                createFGAddress(address_list_name, removeCommonPrepend(a))

    for address_list_name, address_list in modules['security']['address_lists'].items():

        # name = address_list['name']
        if address_list['type'] == "addresses":
            for a in address_list['addresses']:
                createFGAddress(address_list_name, removeCommonPrepend(a))

# enddef createFGAddresseObjects

def shortenServiceName(name):
    comment = name
    shortname = ''
    shortname_arr = name.strip("_").strip("-").split("_")
    for i in shortname_arr:
        if len(i) ==0:
            continue
        shortname += i[0]

    return shortname, comment

# enddef shortenServiceName

def createFGServiceObjects():

    for k, port_list in modules['net']['port_lists'].items():
        name = port_list['name']
        comment = ''
        port_numbers = []

        if len(name) > 78:
            shortname, comment = shortenServiceName(name)
            name = shortname

        for p in port_list['ports']:
            port_numbers.append(p)

        ports.append(Port(name, port_numbers, comment))

    for k, port_list in modules['security']['port_lists'].items():
        name = port_list['name']
        comment = ''
        port_numbers = []

        if len(name) > 78:
            shortname, comment = shortenServiceName(name)
            name = shortname

        for p in port_list['ports']:
            port_numbers.append(p)

        ports.append(Port(name, port_numbers, comment))



# enddef createFGServiceObjects

def printFGAddressObjects():

    print("conf firewall address")

    for name, a in addresses.items():
        if a.ipver == 4:
            if a.type == "range":
                print("    edit " + a.name + "_range")
                print("        set type iprange")
                print("        set start-ip " + a.start_ip)
                print("        set end-ip " + a.end_ip)
                print("    next")
            else:
                print("    edit " + a.name)
                print("        set subnet " + a.value)
                print("    next")

    print("end")

    print("conf firewall address6")

    for name, a in addresses.items():
        if a.ipver == 6:
            if a.type == "range":
                print("    edit " + a.name + "_range")
                print("        set type iprange")
                print("        set start-ip " + a.start_ip)
                print("        set end-ip " + a.end_ip)
                print("    next")
            else:
                print("    edit " + a.name)
                print("        set ip6 " + a.value)
                print("    next")

    print("end")

# enddef printFGAddressObjects

def printFGServiceObjects():

    print("conf firewall service custom")

    for p in ports:
        print("    edit " + p.name)

        if p.comment != '':
            print("        set comment " + p.comment)

        lower_pname = p.name.lower()
        if p.protocol == "tcp":
        # if "tcp-" in lower_pname or "tcp_" in lower_pname:
            print("        set tcp-portrange ", end='')
            print(*p.ports)
        elif p.protocol == "udp":
        # elif "udp-" in lower_pname or "udp_" in lower_pname:
            print("        set udp-portrange ", end='')
            print(*p.ports)
        else:
            print("        set tcp-portrange ", end='')
            print(*p.ports)
            print("        set udp-portrange ", end='')
            print(*p.ports)
            
        print("    next")

    print("end")        
    
# enddef printFGServiceObjects

def createFGAddress(name, addr):

    if type(addr) is dict:
        a = list(addr.keys())[0]
    else:
        a = addr

    # don't want to add address dups
    if a in addresses:
        return

    if "_" in addr:
        return

    # is this an address or a range of addresses, or just an address-list
    if  re.fullmatch('^\s*([0-9]{1,3}.){3}[0-9]{1,3}[/]{0,1}\d{0,2}\D*$', addr):
        addresses[a] = Address(a, 4, 'subnet', a)
    elif re.fullmatch('^\s*([0-9]{1,3}.){3}[0-9]{1,3}-([0-9]{1,3}.){3}[0-9]{1,3}\D*$', addr):
        addresses[a] = Address(a, 4, 'range', a)
    elif addr.count(':') >= 2 and '-' in addr:
        addresses[a] = Address(a, 6, 'range', a)
    elif addr.count(':') >= 2:
        addresses[a] = Address(a, 6, 'subnet', a)

    return ""

# enddef createFGAddress

def extractAddressesFromAddressList(address_list_name):

    if address_list_name in modules['net']['address_lists']:
        address_list = modules['net']['address_lists'][address_list_name]
    elif address_list_name in modules['security']['address_lists']:
        address_list = modules['security']['address_lists'][address_list_name]

    if address_list["type"] == "addresses":
        # if the addresses are dicts then just get the keys.  The values are irrelevant
        if address_list["addresses"] is dict:
            return list(address_list["addresses"].keys())
        else:
            return address_list["addresses"]

    # address list name is actually another address list
    ret = []
    for a in address_list["addresses"]:
        ret.extend(extractAddressesFromAddressList(removeCommonPrepend(a)))

    return ret

# enddef extractAddressesFromAddressList

def extractPortsFromPortsList(port_list_name):

    port_list = {'ports': []}

    if port_list_name in modules['net']['port_lists']:
        port_list = modules['net']['port_lists'][port_list_name]
    else:
        port_list = modules['security']['port_lists'][port_list_name]

    return port_list["ports"]

# enddef extractPortsFromPortsList

def applyL4ProtocolToPort(dst_port_list_name, ip_protocol):
    for p in ports:
        if p.name == dst_port_list_name:
            p.protocol = ip_protocol

# enddef applyL4ProtocolToPort

def createFGPolicy():

    global global_rule_number

    for rule_list in modules['security']['rule_lists']:

        # print(rule_list["name"])
        curr_rule_list = []
        if 'rules' in rule_list:
            for rlist in rule_list["rules"]:
                for r in rlist:
                    # print(r)
                    # print(rlist[r])
                    curr_rule = rlist[r]

                    curr_rule_dests = {
                        'addresses': [],
                        'ports': [],
                        'raw-ports': []
                    }

                    ip_protocol = ""
                    if "ip-protocol" in curr_rule:
                        ip_protocol = curr_rule['ip-protocol']

                    if "destination" in curr_rule:
                        destination = curr_rule['destination']
                        
                        if "address-lists" in destination:
                            for dst_address_list_name in destination['address-lists']:
                                al = extractAddressesFromAddressList(removeCommonPrepend(dst_address_list_name))
                                curr_rule_dests["addresses"].extend(al)

                        if "addresses" in destination:
                            curr_rule_dests["addresses"].extend(destination["addresses"])
                            for a in destination["addresses"]:
                                createFGAddress('',a)
                            
                        
                        if "port-lists" in destination:                        
                            for dst_port_list_name in destination["port-lists"]:
                                curr_rule_dests["ports"].append(removeCommonPrepend(dst_port_list_name))
                                
                                # we know the L4 protocol so lets apply it to global port var now
                                applyL4ProtocolToPort(removeCommonPrepend(dst_port_list_name), ip_protocol)

                                # pl = extractPortsFromPortsList(dst_port_list_name)
                                # curr_rule_dests["ports"].extend(pl)                

                        if "ports" in destination:
                            curr_rule_dests["raw-ports"].extend(destination["ports"])

                    curr_rule_srcs = {
                        'addresses': [],
                        'ports': [],
                        'raw-ports': []
                    }

                    if "source" in curr_rule:
                        source = curr_rule['source']

                        if "address-lists" in source:
                            for src_address_list_name in source['address-lists']:
                                al = extractAddressesFromAddressList(removeCommonPrepend(src_address_list_name))
                                curr_rule_srcs["addresses"].extend(al)

                        if "addresses" in source:
                            curr_rule_srcs["addresses"].extend(source["addresses"])
                            for a in source["addresses"]:
                                createFGAddress('',a)
                        
                        # NOTE: never seen port lists in source but let's leave this in anyways                    
                        if "port-lists" in source:
                            for src_port_list_name in source["port-lists"]:
                                pl = extractPortsFromPortsList(removeCommonPrepend(src_port_list_name))
                                curr_rule_srcs["ports"].extend(pl)

                        if "ports" in source:
                            curr_rule_srcs["raw-ports"].extend(source["ports"])
                        
                    if "rule-number" in curr_rule:
                        global_rule_number = curr_rule['rule-number']
                    else:
                        global_rule_number += 10

                    if 'ip-protocol' not in curr_rule:
                        curr_rule['ip-protocol'] = 'tcp'

                    curr_rule_obj = Rule(r, curr_rule['action'], '', curr_rule['ip-protocol'], 1, global_rule_number, curr_rule_srcs, curr_rule_dests)
                    # rules.append(curr_rule_obj)
                    curr_rule_list.append(curr_rule_obj)

                rules_list[rule_list['name']] = curr_rule_list
                
            print("")

    for policy in modules['security']['policy_lists']:
        policy_name = policy["name"]
        rules_for_this_policy = []
        rule_nums_for_this_policy = []
        rule_num_incrementer = 0

        for rule in policy["rules"]:
            rule_list_name = list(rule.keys())[0]
            rule_list = rule[rule_list_name]

            if "rule-number" in rule_list:
                rule_nums_for_this_policy.append(rule_list["rule-number"])
            else:
                rule_num_incrementer += 1
                rule_nums_for_this_policy.append(str(rule_num_incrementer))

            print(rule_list_name)

            if "rule-list" in rule_list:
                rules_for_this_policy.append(rules_list[removeCommonPrepend(rule_list['rule-list'])])
            else:
                # TODO: create a new rule with the values provided in this rule
                pass

        p = Policy(policy_name, rules_for_this_policy, rule_nums_for_this_policy)
        policies.append(p)

# enddef createFGPolicy


def createFGPolicies():
    
    for p in policies:
        p.printFGFormmattedFWPolicy()

# enddef createFGPolicies

def validateAllPolicies():
    for p in policies:
        p.validate()
        
# enddef validateAllPolicies

def init():
    for m in module_names:
        modules[m] = {
            "afm_config": []
        }
    
    modules['security']['rule_lists'] = []
    modules['security']['port_lists'] = {}
    modules['security']['address_lists'] = {}
    modules['security']['policy_lists'] = []
    modules['security']['shared_objects_lists'] = []

    modules['net']['address_lists'] = {}
    modules['net']['port_lists'] = {}

# enddef init

if __name__ == "__main__":

    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print ("USAGE: afm2fg.py <afmconfig.ucs> [<afmconfig.json>]")
        print ("  Reads in an F5 UCS file and writes out a JSON formatted equivelant")
        print ()
        exit(100)

    fname = sys.argv[1]
    fnamew = ""

    if (len(sys.argv) == 3):
        fnamew = sys.argv[2]

    print (fname + "\n")

    init()

    try:
        f = io.open(fname, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True)

        readModuleValues(f)

        createFGAddresseObjects()
        createFGServiceObjects()
        createFGPolicy()

        printFGAddressObjects()
        printFGServiceObjects()

        createFGPolicies()

        # validate that all referenced Addresses or Services in the Policies actually exist and the FortiGate configuration will not return errors when pasted into a FortiGate
        validateAllPolicies()

        if fnamew:
            fwrite = io.open(fnamew, mode='w', buffering=-1, encoding=None, errors=None, newline=None, closefd=True)
            fwrite.write(json.dumps(modules))
            fwrite.close()

        f.close()

    except OSError:
        print (OSError.errno)


