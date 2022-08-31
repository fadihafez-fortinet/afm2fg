# afm2fg
Python script that takes in an F5 AFM configuration and outputs a FortiGate configuration

08/30/2022 - Added support for NAT policies.  Creates VIPs for destination NAT and IPPools for source NAT.

08/03/2022 - Currently converts AFM net and security sections only

First step is to convert the F5 AFM configuration into JSON format
Second step is to create the global dictionary that contains the following keys: net, security, pem, auth, sys, ltm, cm and cli
Third step is to traverse the contents of the lists in the global dictionaries and instantiate an object for each element, based on the appropriate class
Fourth step is to print all the objects created in step 3, as FortiGate formatted configuration

