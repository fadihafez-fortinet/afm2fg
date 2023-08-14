#!/usr/bin/python3
#
# Author: Fadi Hafez (Fortinet)
# Conversion from AFM to FG
# AFM version 15.1.2.1
#
# versions:
#   1.0.0 (May 2, 2022): 
#   - First version created
#   1.1.0 (Mar 30, 2023):
#   - Fixed some bugs
#   1.2.0 (Aug 13, 2023):
#   - New brach for VZ
#

#
# TODO:
#  -
# CHANGES:
#  - 03/31/23: fix the numbers of the policies used in the name - need to avoid overlap
#  - 03/31/23: remove any IPv6_all and IPv4_all injections into the configuration
#  - 03/31/23: only include the IPv4/v6 addresses from address-list if SRC/DST (other side) has equivalent IPv4/v6
#  - 03/30/23: leave the IPv4/v6 addresses in as 'commented' if other side (SRC/DST) does not have equivalent
#  - 04/05/23: Added COMMENT_OUT_POLICIES_WITH_MISSING_SRC_OR_DST_ADDRESSES to allow commenting out of policies that are missing SRC or DST addresses
#  - 08/13/23: New branch for VZ

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
import ipaddress

module_names = ["net","security","pem","auth","sys","ltm","cm","cli"]
modules = {}

attempt_num = 0
MAX_RULE_NAME_LEN = 35
MAX_SERVICE_NAME_LEN = 78
COMMENT_OUT_POLICIES_WITH_MISSING_SRC_OR_DST_ADDRESSES = True

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
    types = ["range","subnet","fqdn"]
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
    protocol = []
    ports = []

    def getPort(self):
        return self.ports

    def addProtocol(self, protocol):
        if protocol not in self.protocol:
            self.protocol.append(protocol)

    def __init__(self, name, value, comment, protocol=[]):
        self.name = name
        if type(value) is not list:    
            self.ports = [value]
        else:
            self.ports = value
        self.comment = comment
        self.protocol = protocol


class Rule:   

    name = ""
    rule_list_name = ""
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
    translations = {
        "source": "",
        "destination": ""
    }

    def printFGFormattedAddress():
        pass

    def __init__(self, name, rule_list_name, action, description, protocol, log, rule_number, source, destination, translations=None) -> None:
        self.name = name or ""
        self.rule_list_name = rule_list_name or ""
        self.action = action or "accept-decisively"
        self.description = description or ""
        self.protocol = protocol or "tcp"
        self.log = log or False
        self.rule_number = rule_number or -1
        self.source = source or {}
        self.destination = destination or {}
        self.translations = translations
        
class Policy:
    name = ""
    rule_list = []
    rule_numbers = []

    type = "" # fw | nat

    srcintf = "any"
    dstintf = "any"
    schedule = "always"
    nat = "disable"
    service = "ALL"
    action = "deny"

    def printDstSrcAddresses(self, dst_address_list, src_address_list, central_snat_enabled=False, commented_out=False):
        ipv4_dst_addresses = []
        ipv6_dst_addresses = []
        ipv4_src_addresses = []
        ipv6_src_addresses = []

        dstaddr = "dstaddr"
        srcaddr = "srcaddr"
        dstaddr6 = "dstaddr6"
        srcaddr6 = "srcaddr6"

        if central_snat_enabled:
            dstaddr = "dst-addr"
            srcaddr = "orig-addr"
            dstaddr6 = "dst-addr6"
            srcaddr6 = "orig-addr6"

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

        # SRC and DST IPv4 addresses
        if len(ipv4_dst_addresses) and len(ipv4_src_addresses):
            if commented_out: print("# ", end="")
            print("        set " + dstaddr + " ", end="")
            print(*ipv4_dst_addresses, sep=' ')
            print("")
            if commented_out: print("# ", end="")
            print("        set " + srcaddr + " ", end="")
            print(*ipv4_src_addresses, sep=' ')
            print("")
        elif len(ipv4_dst_addresses) == 0 and len(ipv4_src_addresses) == 0:
            # contains neither SRC or DST addresses
            pass
        else:
            if len(ipv4_src_addresses) == 0:
                print("        # set " + dstaddr + " ", end="")
                print(*ipv4_dst_addresses, sep=' ')
                print("")
            elif len(ipv4_dst_addresses) == 0:
                print("        # set " + srcaddr + " ", end="")
                print(*ipv4_src_addresses, sep=' ')
                print("")

        if len(ipv6_dst_addresses) and len(ipv6_src_addresses):
            if commented_out: print("# ", end="")
            print("        set " + dstaddr6 + " ", end="")
            print(*ipv6_dst_addresses, sep=' ')
            print("")
            if commented_out: print("# ", end="")
            print("        set " + srcaddr6 + " ", end="")
            print(*ipv6_src_addresses, sep=' ')
            print("")
        elif len(ipv6_dst_addresses) == 0 and len(ipv6_src_addresses) == 0:
            # contains neither SRC or DST addresses
            pass
        else:
            if len(ipv6_src_addresses) == 0:
                print("        # set " + dstaddr6 + " ", end="")
                print(*ipv6_dst_addresses, sep=' ')
                print("")
            elif len(ipv6_dst_addresses) == 0:
                print("        # set " + srcaddr6 + " ", end="")
                print(*ipv6_src_addresses, sep=' ')
                print("")


    def printDstPorts(self, dst_ports_list, commented_out=False):

        if len(dst_ports_list) == 0:
            if commented_out: print("# ", end="")
            print("        set service ALL")
            return

        if commented_out: print("# ", end="")
        print("        set service ", end="")

        for s in dst_ports_list:
            if len(s.name) > MAX_SERVICE_NAME_LEN:
                shortname, s.comment = shortenServiceName(s.name)
                if commented_out: print("# ", end="")
                print(shortname + " ", end="")
            else:
                if commented_out: print("# ", end="")
                print(s.name + " ", end="")

        print("")

    def printService(self, protocol, commented_out=False):
        if protocol == "tcp":
            if commented_out: print("# ", end="")
            print("        set service ALL_TCP")
        elif protocol == "udp":
            if commented_out: print("# ", end="")
            print("        set service ALL_UDP")
        elif protocol == "icmp":
            if commented_out: print("# ", end="")
            print("        set service ALL_ICMP")

    def printAction(self, action, commented_out=False):
        if action == "accept-decisively" or action == "accept":
            if commented_out: print("# ", end="")
            print("        set action accept")

    def printLog(self, log, commented_out=False):
        if log == 1:
            if commented_out: print("# ", end="")
            print("        set logtraffic all")

    def printFGFormattedFWPolicy(self, policy_num):

        rule_list_counter = 0

        print("config firewall policy")

        # go through rule_lists
        for rl in self.rule_list:
            overall_rule_num = 1
            
            rule_pre_name = shortenRuleName(self.name)

            # go through all rules in current rule_list
            for r in rl:
                rule_name = shortenRuleName(r.rule_list_name + "/" + r.name)
                rule_number = str(policy_num) + "_" + self.rule_numbers[rule_list_counter] + "_" + str(overall_rule_num) + "_" + str(r.rule_number)
                print("# " + self.name + "/" + r.name)

                if COMMENT_OUT_POLICIES_WITH_MISSING_SRC_OR_DST_ADDRESSES and (len(r.destination["addresses"]) == 0 or len(r.source["addresses"]) == 0):
                    print("#    edit 0")

                    print("#        set name policy" + str(policy_num) + "_" + str(rule_number))
                    print("#        set srcintf " + self.srcintf)
                    print("#        set dstintf " + self.dstintf)
                    print("#        set comments " + self.name + "/" + r.rule_list_name + "/" + r.name)

                    self.printDstSrcAddresses(r.destination["addresses"], r.source["addresses"], commented_out=True)
                    self.printDstPorts(r.destination["ports"], commented_out=True)
                    # self.printService(r.protocol, commented_out=True)
                    self.printAction(r.action, commented_out=True)
                    self.printLog(r.log, commented_out=True)

                    print("#        set schedule always")
                    print("#    next")

                else:
                    print("    edit 0")

                    print("        set name policy" + str(policy_num) + "_" + str(rule_number))
                    print("        set srcintf " + self.srcintf)
                    print("        set dstintf " + self.dstintf)
                    print("        set comments " + self.name + "/" + r.rule_list_name + "/" + r.name)

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

    def printFGFormattedNATPolicy(self):

        print("config firewall central-snat-map")

        for r in self.rule_list:
            overall_rule_num = 1
            
            rule_pre_name = shortenRuleName(self.name)

            rule_name = shortenRuleName(rule_pre_name + "/" + r.name)

            print("# " + self.name + "/" + r.name)
            print("    edit 0")

            print("        set srcintf " + self.srcintf)
            print("        set dstintf " + self.dstintf)
            print("        set comments " + self.name + "_" + r.name)

            self.printDstSrcAddresses(r.destination["addresses"], r.source["addresses"], True)

            if r.translations:
                if r.translations["source"]:
                    print("        set nat enable")
                    print("        set nat-ippool " + removeCommonPrepend(r.translations["source"]))

            print("    next")

            overall_rule_num += 1
            print("")
        
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

        print("# policy name: " + self.name)
        print("# " + str(errorcount) + " errors found in policy")


    def __init__(self, type, name, rules, rule_numbers) -> None:
        self.type = type
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
nat_translation_dups = []
global_rule_number = 0


def shortenRuleName(rule_name):
    new_name = ""

    if len(rule_name) < MAX_RULE_NAME_LEN:
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

# Scans the modules['security']['nat']['destination-translation'] and modules['security']['nat']['source-translation'] arrays looking for duplicate addresses
# If found, it marks the 2nd, 3rd, etc. address object as a duplicate of the first
# This helps to reduce the number of NAT pools that need to be created later, saving resources
def markNATDups():

    dt_names = []
    dt_addresses = []
    st_names = []
    st_addresses = []

    for dt_name in modules['security']['nat']['destination-translation']:

        dt = modules['security']['nat']['destination-translation'][dt_name]
        if dt["addresses"][0] in dt_addresses:
            dt["dup"] = {"duplicate_of" : dt_names[dt_addresses.index(dt["addresses"][0])]}

        dt_names.append(dt_name)
        dt_addresses.append(dt["addresses"][0])
    

    for st_name in modules['security']['nat']['source-translation']:

        st = modules['security']['nat']['source-translation'][st_name]
        if st["addresses"][0] in st_addresses:
            st["dup"] = {"duplicate_of" : st_names[st_addresses.index(st["addresses"][0])]}

        st_names.append(st_name)
        st_addresses.append(st["addresses"][0])


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
            if "fqdns" in addresses[0]['security']:
                modules['security']['firewall']['fqdns'][name] = {'name': name, 'type': 'fqdn', 'addresses': addresses[0]['security']['fqdns'] }

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

# create a FortiOS type address object and append it to the global addresses array
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

        if address_list['type'] == "fqdn":
            pass

    for address_list_name, address_list in modules['security']['firewall']['addresses'].items():

        # name = address_list['name']
        if address_list['type'] == "addresses":
            for a in address_list['addresses']:
                createFGAddress(address_list_name, removeCommonPrepend(a))

    for address_list_name, address_list in modules['security']['firewall']['fqdns'].items():

        if address_list['type'] == "fqdn":
            for a in address_list['addresses']:
                createFGAddress(address_list_name, removeCommonPrepend(a))


# enddef createFGAddresseObjects

# Since F5 service names can be very lengthy, they have to be shortened.  The actual name will end up in the FortiOS policy comment instead
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

        # NEED TO APPLY THIS TO THE LOOKUP TOO
        if len(name) > MAX_SERVICE_NAME_LEN:
             shortname, comment = shortenServiceName(name)
             name = shortname

        for p in port_list['ports']:
            port_numbers.append(p)

        ports[name] = Port(name, port_numbers, comment, [])

    for k, port_list in modules['security']['firewall']['ports'].items():
        name = port_list['name']
        comment = ''
        port_numbers = []

        if len(name) > MAX_SERVICE_NAME_LEN:
            shortname, comment = shortenServiceName(name)
            name = shortname

        for p in port_list['ports']:
            port_numbers.append(p)

        ports[name] = Port(name, port_numbers, comment, [])

    for k, port_list in modules['security']['firewall']['port_lists'].items():
        name = port_list['name']
        comment = ''
        port_numbers = []

        if len(name) > MAX_SERVICE_NAME_LEN:
            shortname, comment = shortenServiceName(name)
            name = shortname

        for p in port_list['ports']:
            port_numbers.extend(ports[removeCommonPrepend(p)].ports)

        ports[name] = Port(name, port_numbers, comment, [])


# enddef createFGServiceObjects

def printFGAddressObjects():

    print("config firewall address")

    for name, a in addresses.items():
        if a.ipver == 4:
            if a.type == "subnet":
                print("    edit " + a.name)
                print("        set subnet " + a.value)
                print("    next")
            elif a.type == "range":
                print("    edit " + a.name + "_range")
                print("        set type iprange")
                print("        set start-ip " + a.start_ip)
                print("        set end-ip " + a.end_ip)
                print("    next")
            elif a.type == "fqdn":
                print("    edit " + a.name)
                print("        set type fqdn")
                print("        set fqdn " + a.value)
                print("    next")


    print("end")

    print("config firewall address6")

    for name, a in addresses.items():
        if a.ipver == 6:
            if a.type == "subnet":
                print("    edit " + a.name)
                print("        set ip6 " + a.value)
                print("    next")
            elif a.type == "range":
                print("    edit " + a.name + "_range")
                print("        set type iprange")
                print("        set start-ip " + a.start_ip)
                print("        set end-ip " + a.end_ip)
                print("    next")
            elif a.type == "fqdn":
                print("    edit " + a.name)
                print("        set type fqdn")
                print("        set fqdn " + a.value)
                print("    next")

    print("end")

# enddef printFGAddressObjects

def printFGServiceObjects():

    print("config firewall service custom")

    for p in ports:

        this_port = ports[p]
        print("    edit " + this_port.name)

        if ports[p].comment != '':
            print("        set comment " + this_port.comment)

        if len(this_port.protocol) == 0:
            this_port.protocol.append("tcp")
            print("        set tcp-portrange ", end='')
            print(*this_port.ports)
            print("        set udp-portrange ", end='')
            print(*this_port.ports)

        if "tcp" in this_port.protocol:
            print("        set tcp-portrange ", end='')
            print(*this_port.ports)

        if "udp" in this_port.protocol:
            print("        set udp-portrange ", end='')
            print(*this_port.ports)

        if "icmp" in this_port.protocol:
            print("        set protcol ICMP ", end='')
            print("        unset icmptype ", end='')
            
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
    if  re.fullmatch('^\s*([0-9]{1,3}\.){3}[0-9]{1,3}[/]{0,1}\d{0,2}\D*$', addr):
        addresses[a] = Address(a, 4, 'subnet', a)
    elif re.fullmatch('^\s*([0-9]{1,3}\.){3}[0-9]{1,3}-([0-9]{1,3}\.){3}[0-9]{1,3}\D*$', addr):
        addresses[a] = Address(a, 4, 'range', a)
    elif addr.count(':') >= 2 and '-' in addr:
        addresses[a] = Address(a, 6, 'range', a)
    elif addr.count(':') >= 2:
        addresses[a] = Address(a, 6, 'subnet', a)
    elif list(filter(addr.endswith, ['.com','.us','.edu'])):
        addresses[a] = Address(a, 4, 'fqdn', a)

    return ""

# enddef createFGAddress

def extractAddressesFromAddressList(address_list_name):

    if address_list_name in modules['net']['address_lists']:
        address_list = modules['net']['address_lists'][address_list_name]
    elif address_list_name in modules['security']['firewall']['address_lists']:
        address_list = modules['security']['firewall']['address_lists'][address_list_name]
    elif address_list_name in modules['security']['firewall']['addresses']:
        address_list = modules['security']['firewall']['addresses'][address_list_name]
    elif address_list_name in modules['security']['firewall']['fqdns']:
        address_list = modules['security']['firewall']['fqdns'][address_list_name]

    if address_list["type"] == "addresses" or address_list["type"] == "fqdn":
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
        ports[dst_port_list_name].addProtocol(ip_protocol)

# enddef applyL4ProtocolToPort

def createFGPort(port, protocol):
    for p in ports:
        cp = ports[p]
        if len(ports[p].ports) > 1:
            continue

        if port == ports[p].ports[0] and protocol in ports[p].protocol:
            return ports[p]
        elif port == ports[p].ports[0]:
            ports[p].addProtocol(protocol)
            return ports[p]

    ports[port] = Port(port, port, '', [protocol])
    return ports[port]

# enddef createFGPort

def getFirstAndLastIP(subnet):
    net = ipaddress.ip_network(subnet)
    return net[1].exploded, net[-1].exploded

# enddef getFirstAndLastIP

def createNATPools():

    print("config firewall ippool")

    for stp in modules["security"]["nat"]["source-translation"]:
        p = modules["security"]["nat"]["source-translation"][stp]
        if 'dup' in p:
            continue

        print("    edit " + p["name"])
        for a in p["addresses"]:
            if "/" not in a or a.endswith("/32"):
                a_nosubnet = a.split("/")[0]
                print("        set startip " + a_nosubnet)
                print("        set endip " + a_nosubnet)
            elif "/" in a:
                s, e = getFirstAndLastIP(a)
                print("        set startip " + s)
                print("        set endip " + e)

        if p["type"] == "static-nat":
            print("        set type one-to-one")

        print("    next")
    print("end")

# enddef createNATPools

def createVIPs():

    print("config firewall vip")

    for p in policies:
        if p.type == "nat":
            for r in p.rule_list:
                if r.translations and r.translations["destination"]:
                    dst_tr_name = removeCommonPrepend(r.translations["destination"])

                    # skip this vip if the DNAT extip and mappedip are not the same length
                    extip = r.destination["addresses"][0]
                    mappedip = modules["security"]["nat"]["destination-translation"][dst_tr_name]["addresses"][0] 
                    if ("-" in extip and "-" in mappedip) or ("-" not in extip and "-" not in mappedip):
                        print("    edit " + dst_tr_name)
                        print("        set extip " + r.destination["addresses"][0])
                        print("        set mappedip " + modules["security"]["nat"]["destination-translation"][dst_tr_name]["addresses"][0])
                        print("        set extintf any")
                        print("    next")
                    else:
                        print("# VIP TRANSLATION MISMATCH ")
                        print("#    edit " + dst_tr_name)
                        print("#        set extip " + r.destination["addresses"][0])
                        print("#        set mappedip " + modules["security"]["nat"]["destination-translation"][dst_tr_name]["addresses"][0])
                        print("#        set extintf any")
                        print("#    next")

    print("end")

# enddef createVIPs

def updateGlobalRulesList(r, rule, rule_list_name):

    global global_rule_number

    curr_rule_dests = {
        'addresses': [],
        'ports': [],
        'raw-ports': []
    }

    ip_protocol = ""
    if "ip-protocol" in rule:
        ip_protocol = rule['ip-protocol']

    if "destination" in rule:
        destination = rule['destination']
        
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
                dpln = removeCommonPrepend(dst_port_list_name)
                if len(dpln) > 78:
                    shortened_dpln, desc = shortenServiceName(dpln)
                    curr_rule_dests["ports"].append(ports[shortened_dpln])
                else:
                    curr_rule_dests["ports"].append(ports[dpln])
                
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

    if "source" in rule:
        source = rule['source']

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
        
    curr_rule_translations = {
        'source': "",
        'destination': ""
    }

    if "translation" in rule:
        if "source" in rule["translation"]:
            st = removeCommonPrepend(rule["translation"]["source"])
            if "dup" in modules['security']['nat']['source-translation'][st]:
                curr_rule_translations["source"] = modules['security']['nat']['source-translation'][st]['dup']['duplicate_of']
            else:
                curr_rule_translations["source"] = rule["translation"]["source"]

        if "destination" in rule["translation"]:
            curr_rule_translations["destination"] = rule["translation"]["destination"]
    else:
        curr_rule_translations = None


    # if "rule-number" in rule:
    #     global_rule_number = rule['rule-number']
    # else:
    global_rule_number += 10

    if 'ip-protocol' not in rule:
        rule['ip-protocol'] = 'all'

    if 'action' not in rule:
        rule['action'] = 'accept'

    curr_rule_obj = Rule(r, rule_list_name, rule['action'], '', rule['ip-protocol'], 1, global_rule_number, curr_rule_srcs, curr_rule_dests, curr_rule_translations)
    return curr_rule_obj
    # rules.append(curr_rule_obj)

def createFGPolicy():

    for rule_list in modules['security']['firewall']['rule_lists']:

        # print(rule_list["name"])
        curr_rule_list = []
        if 'rules' in rule_list:
            for rlist in rule_list["rules"]:
                for r in rlist:
                    curr_rule = rlist[r]
                    curr_rule_obj = updateGlobalRulesList(r, curr_rule, rule_list["name"])
                    curr_rule_list.append(curr_rule_obj)

                rules_list[rule_list['name']] = curr_rule_list                

    for policy in modules['security']['nat']['policy_lists']:
        policy_name = policy["name"]
        rules_for_this_policy = []
        rule_nums_for_this_policy = []
        rule_num_incrementer = 0

        for rule in policy["rules"]:
            rule_name = list(rule.keys())[0]
            rule_details = rule[rule_name]

            if "rule-number" in rule_details:
                rule_nums_for_this_policy.append(rule_details["rule-number"])
            else:
                rule_num_incrementer += 1
                rule_nums_for_this_policy.append(str(rule_num_incrementer))

            rule_details['name'] = rule_name

            curr_rule_obj = updateGlobalRulesList(rule_name, rule_details, "")

            rules_for_this_policy.append(curr_rule_obj)

        p = Policy("nat", policy_name, rules_for_this_policy, rule_nums_for_this_policy)
        policies.append(p)

    for policy in modules['security']['firewall']['policy_lists']:
        policy_name = policy["name"]
        rules_for_this_policy = []
        rule_nums_for_this_policy = []
        rule_num_incrementer = 0

        for rule in policy["rules"]:
            rule_name = list(rule.keys())[0]
            rule_list = rule[rule_name]

            if "rule-number" in rule_list:
                rule_nums_for_this_policy.append(rule_list["rule-number"])
            else:
                rule_num_incrementer += 1
                rule_nums_for_this_policy.append(str(rule_num_incrementer))

            if "rule-list" in rule_list and removeCommonPrepend(rule_list['rule-list']) in rules_list:
                rules_for_this_policy.append(rules_list[removeCommonPrepend(rule_list['rule-list'])])
            else:
                # TODO: create a new rule with the values provided in this rule
                pass

        p = Policy("fw", policy_name, rules_for_this_policy, rule_nums_for_this_policy)
        policies.append(p)

# enddef createFGPolicy


def createFGPolicies():

    policy_num = 1 
    for p in policies:
        if p.type == "nat":
            p.printFGFormattedNATPolicy()
        if p.type == "fw":
            p.printFGFormattedFWPolicy(policy_num)
        policy_num += 1

# enddef createFGPolicies

def validateAllPolicies():
    for p in policies:
        if p.type == "fw":
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
    modules['security']['firewall']['fqdns'] = {}
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
        print("USAGE: afm2fg.py <afmconfig.conf> [<afmconfig.json>]")
        print("  Reads in an F5 configuration file and writes to STDOUT the equivalent FortiOS configuration.")
        print("  If a second parameter (optional JSON filename) is provided, it writes out a JSON formatted F5 configuration into that file")
        print ()
        exit(100)

    fname = sys.argv[1]
    fnamew = ""

    if (len(sys.argv) == 3):
        fnamew = sys.argv[2]

    init()

    try:
        f = io.open(fname, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True)

        readModuleValues(f)

        markNATDups()

        createFGAddresseObjects()
        createFGServiceObjects()
        createFGPolicy()

        printFGAddressObjects()
        printFGServiceObjects()

        createNATPools()
        createVIPs()
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


