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
from stringprep import in_table_a1
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

    def setProtocol(self, protocol):
        self.protocol = protocol

    def __init__(self) -> None:
        pass

    def __init__(self, name, value, comment, protocol=''):
        self.name = name
        self.ports = value
        self.comment = comment
        self.protocol = protocol


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
            if len(s.name) > 78:
                shortname, s.comment = shortenServiceName(s.name)
                print(shortname + " ", end="")
            else:
                print(s.name + " ", end="")

        print("")

    def printService(self, protocol):
        if protocol == "tcp":
            print("        set service ALL_TCP")
        elif protocol == "udp":
            print("        set service ALL_UDP")
        elif protocol == "icmp":
            print("        set service ALL_ICMP")

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
                    if p.name not in ports:
                        print("validation error, policy name:  " + r.name + " destination service not found: " + p.name)
                        errorcount += 1                        

                # validate the destination service exists in the global ports list
                for p in r.source["ports"]:
                    if p.name not in ports:
                        print("validation error, policy name: " + r.name + " source service not found: " + p.name)
                        errorcount += 1                        

        print(str(errorcount) + " errors found in policy")


    def __init__(self, name, rules, rule_numbers) -> None:
        self.name = name
        self.rule_list = rules
        self.rule_numbers = rule_numbers

# end Class Policy



addresses = {}
ports = {}
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

def readValues(arr):

    bracecount = 0
    values_arr = []
    for i in arr:
        if i.strip().endswith("{ }"):
            values_arr.append("\"" + i.split()[0] + "\" ")
        elif i.strip().startswith("{"):
            values_arr.append("\"" + i.split()[0] + "\" ")
            bracecount += 1
        elif i.strip().startswith("}"):
            bracecount -= 1

        if bracecount == -1:
            break

    return values_arr

# enddef readValues

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
                if 'addresses' not in obj and 'address-lists' not in obj and 'ports' not in obj and 'port-lists' not in obj:
                    val_arr.extend(list(obj.keys()))
                    return val_arr, i+1
                else:
                    for v in val_arr:
                        obj[v] = 'True'

                    return obj, i+1
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
    
    policy_type = section[0].split()[1]
    type = section[0].split()[2]
    name = removeCommonPrepend(section[0].split()[3])

    if policy_type == "firewall":
        if (type == "rule-list"):
            modules['security']['firewall']['rule_lists'].append(parseLists(section, 'rules', name))

        elif (type == "address-list"):
            addresses = parseList(section)
            if "addresses" in addresses[0]['security']:
                modules['security']['firewall']['addresses'][name] = {'name': name, 'type': 'addresses', 'addresses': addresses[0]['security']['addresses'] }
            if "address-lists" in addresses[0]['security']:
                modules['security']['firewall']['address_lists'][name] = {'name': name, 'type': 'address-lists', 'addresses': addresses[0]['security']['address-lists'] }

        elif type == "port-list":
            ports = parseList(section)
            if "port-lists" in ports[0]['security']:
                modules['security']['firewall']['port_lists'][name] = {'name': name, 'type': 'port-lists', 'ports': ports[0]['security']['port-lists']}
            if "ports" in ports[0]['security']:
                modules['security']['firewall']['ports'][name] = {'name': name, 'type': 'ports', 'ports': ports[0]['security']['ports']}

        elif (type == "policy"):
            modules['security']['firewall']['policy_lists'].append(parseLists(section, 'rules', name))

    elif policy_type == "nat":

        if type == "destination-translation":
            addresses = parseList(section)
            modules['security']['nat']['destination-translation'][name] = {'name': name, 'type': addresses[0]['security']['type'], 'addresses': addresses[0]['security']['addresses']}

        elif type == "source-translation":
            addresses = parseList(section)
            modules['security']['nat']['source-translation'][name] = {'name': name, 'type': addresses[0]['security']['type'], 'addresses': addresses[0]['security']['addresses']}

        elif type == "policy":
            modules['security']['nat']['policy_lists'].append(parseLists(section, 'rules', name))

        pass
        # TODO: implement elements for NAT objects

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

    for address_list in modules['security']['firewall']['address_lists']:
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

    for address_list_name, address_list in modules['security']['firewall']['address_lists'].items():

        # name = address_list['name']
        if address_list['type'] == "addresses":
            for a in address_list['addresses']:
                createFGAddress(address_list_name, removeCommonPrepend(a))

    for address_list_name, address_list in modules['security']['firewall']['addresses'].items():

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

        ports[name] = Port(name, port_numbers, comment)

    for k, port_list in modules['security']['firewall']['port_lists'].items():
        name = port_list['name']
        comment = ''
        port_numbers = []

        if len(name) > 78:
            shortname, comment = shortenServiceName(name)
            name = shortname

        for p in port_list['ports']:
            port_numbers.append(p)

        ports[name] = Port(name, port_numbers, comment)

    for k, port_list in modules['security']['firewall']['ports'].items():
        name = port_list['name']
        comment = ''
        port_numbers = []

        if len(name) > 78:
            shortname, comment = shortenServiceName(name)
            name = shortname

        for p in port_list['ports']:
            port_numbers.append(p)

        ports[name] = Port(name, port_numbers, comment)


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

        this_port = ports[p]
        print("    edit " + this_port.name)

        if ports[p].comment != '':
            print("        set comment " + this_port.comment)

        if this_port.protocol == "":
            this_port.protocol = "tcp"

        if this_port.protocol == "tcp":
        # if "tcp-" in lower_pname or "tcp_" in lower_pname:
            print("        set tcp-portrange ", end='')
            print(*this_port.ports)
        elif this_port.protocol == "udp":
        # elif "udp-" in lower_pname or "udp_" in lower_pname:
            print("        set udp-portrange ", end='')
            print(*this_port.ports)
        elif this_port.protocol == "icmp":
            print("        set protcol ICMP ", end='')
            print("        unset icmptype ", end='')
        else:
            print("        set tcp-portrange ", end='')
            print(*this_port.ports)
            print("        set udp-portrange ", end='')
            print(*this_port.ports)
            
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
    elif address_list_name in modules['security']['firewall']['address_lists']:
        address_list = modules['security']['firewall']['address_lists'][address_list_name]
    elif address_list_name in modules['security']['firewall']['addresses']:
        address_list = modules['security']['firewall']['addresses'][address_list_name]

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
        port_list = modules['security']['firewall']['port_lists'][port_list_name]

    return port_list["ports"]

# enddef extractPortsFromPortsList

def applyL4ProtocolToPort(dst_port_list_name, ip_protocol):
    if dst_port_list_name in ports:
        ports[dst_port_list_name].setProtocol(ip_protocol)

# enddef applyL4ProtocolToPort

def createFGPort(port, protocol):
    for p in ports:
        cp = ports[p]
        if len(ports[p].ports) > 1:
            continue

        if port == ports[p].ports[0] and ports[p].protocol != "":
                return ports[p]
        
    ports[port] = Port(port, port, '', protocol)
    return ports[port]

# enddef createFGPort

def createFGPolicy():

    global global_rule_number

    for rule_list in modules['security']['firewall']['rule_lists']:

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
                                curr_rule_dests["ports"].append(ports[removeCommonPrepend(dst_port_list_name)])
                                
                                # we know the L4 protocol so lets apply it to global port var now
                                applyL4ProtocolToPort(removeCommonPrepend(dst_port_list_name), ip_protocol)

                                # pl = extractPortsFromPortsList(dst_port_list_name)
                                # curr_rule_dests["ports"].extend(pl)

                        if "ports" in destination:
                            for dst_port in destination["ports"]:
                                dp = createFGPort(dst_port, ip_protocol)
                                curr_rule_dests["ports"].append(dp)                                
                            
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
                                pl = ports[removeCommonPrepend(src_port_list_name)]
                                curr_rule_srcs["ports"].append(pl)

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

    for policy in modules['security']['firewall']['policy_lists']:
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
    
    
    modules['security']['shared_objects_lists'] = []

    modules['security']['firewall'] = {}
    modules['security']['firewall']['rule_lists'] = []
    modules['security']['firewall']['port_lists'] = {}
    modules['security']['firewall']['address_lists'] = {}
    modules['security']['firewall']['ports'] = {}
    modules['security']['firewall']['addresses'] = {}
    modules['security']['firewall']['policy_lists'] = []

    modules['security']['nat'] = {}
    modules['security']['nat']['destination-translation'] = {}
    modules['security']['nat']['source-translation'] = {}
    modules['security']['nat']['policy_lists'] = []

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


