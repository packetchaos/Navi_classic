#!/usr/bin/env python3
#navi v3.2
#Created by The ITNinja - Casey Reid
#Disclaimer: This is NOT supported By Tenable! It is also not a secure way of communicating with the API.
#This is used to show what is possible with the Tenable API

import requests
import sys
import time
import pickle
import os

requests.packages.urllib3.disable_warnings()
def save_keys():
    #check to see if the file exists

    print("Hey you don't have any Keys!")
    access_key = input("Please provide your Access Key : ")
    secret_key = input("Please provide your Secret Key : ")

    dicts = {"Access Key": access_key, "Secret Key": secret_key}

    pickle_out = open("keys.pickle", "wb")
    pickle.dump(dicts, pickle_out)
    pickle_out.close()

    print("Now you have keys, re-run your command")
    sys.exit()

def grab_headers():
    access_key = ''
    secret_key = ''
    if os.path.isfile('./keys.pickle') is False:
        save_keys()
    else:
        pickle_in = open("keys.pickle", "rb")
        keys = pickle.load(pickle_in)
        access_key = keys["Access Key"]
        secret_key = keys["Secret Key"]

    headers = {'Content-type':'application/json','X-ApiKeys':'accessKey='+access_key+';secretKey='+secret_key}

    return headers

def get_data(url_mod):
    url = "https://cloud.tenable.com"
    headers = grab_headers()
    r = requests.request('GET', url + url_mod, headers=headers, verify=False)
    data = r.json()
    return data

def main(cmd,opt):
    try:
        if cmd == 'get':
            get(opt)
        elif cmd == 'scan':
            try:
                scan(opt)
            except:
                print("Invalid input")
        elif cmd == 'new':
            save_keys()
        else:
            host_data(cmd,opt)
    except KeyError:
        print("You forgot your keys, or they are not correct.\n")
        print("Consider changing your keys using 'new keys' command")

def findplugin(plugin_id):
    data = get_data('/workbenches/assets/')
    print("We are looking for the plugin_out put for plugin: "+plugin_id+" on all assets; this may take a minute")
    for x in range(len(data["assets"])):
        try:
            ip = data["assets"][x]["ipv4"][0]
            id = data["assets"][x]["id"]
            try:
                info = get_data('/workbenches/assets/' + str(id) + '/vulnerabilities/' + str(plugin_id)+'/outputs')
                eval = info["outputs"][0]["plugin_output"]
                print(ip)
                print_data(info)
                print("-------------------------\n")
            except IndexError:
                pass


        except:
            pass

def usage():
    print("\nUsage: <command(get or scan)> or <Ip address> <option>\n")
    print("<IP address options>")
    print("          N - Netstat")
    print("          T - Trace Rt")
    print("          P - Patch")
    print("          S - Software")
    print("          B - Missing MS Patch and last Boot")
    print("          C - Connection info")
    print("          U - Unique Asset Info")
    print("          s - Services running")
    print("          E - Outbound External Connections")
    print("          R - Local Firewall Rules")
    print("          <plugin id>\n")
    print("usage ex: '192.168.128.2 N' or '192.168.128.2 19506'\n")
    print("<'get' options>")
    print("           latest - Details on last scan run")
    print("           nnm - newest host found by nnm")
    print("           scanners - List all of the available scanners")
    print("           users - list all of the users")
    print("           exclusions - List of all of the exclusions")
    print("           containers - List all containers in Container security, ids, # of vulns")
    print("           docker - List hosts with running containers; show those containers")
    print("           webapp - List running web servers")
    print("           assets - List the IPs found in the last 30 days")
    print("           creds  - List any hosts that had credential failures")
    print("usage ex: 'get latest'\n")
    print("<'scan (ip address or subnet)'>\n")
    print("usage ex: scan 192.168.128.2\n")
    print("<'new keys'>")
    print("           Allows you to enter in new keys")

def latest():
    data = get_data('/scans')
    l = []
    e = {}
    for x in range(len(data["scans"])):

        # keep UUID and Time together
        # get last modication date for duration computation
        epoch_time = data["scans"][x]["last_modification_date"]
        # get the scanner ID to display the name of the scanner
        d = data["scans"][x]["id"]
        #need to identify type to compare against pvs and agent scans
        type = str(data["scans"][x]["type"])
        name = str(data["scans"][x]["name"])
        #don't capture the PVS or Agent data in latest
        while type not in ['pvs','agent','webapp']:
            # put scans in a list to find the latests
            l.append(epoch_time)
            # put the time and id into a dictionary
            e[epoch_time] = d
            break
    # find the latest time
    grab_time = max(l)

    # get the scan with the corresponding ID
    grab_uuid = e[grab_time]

    # turn epoch time into something readable
    epock_latest = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(grab_time))

    # pull the scan data
    details = get_data('/scans/' + str(grab_uuid))
    print("\nThe last Scan run was at " + epock_latest)
    print("\nThe Scanner name is : " + str(details["info"]["scanner_name"]))
    print("\nThe Name of the scan is "+name)
    print("The " + str(details["info"]["hostcount"]) + " host(s) that were scanned are below :\n")
    for x in range(len(details["hosts"])):
        print(details["hosts"][x]["hostname"])

    start = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime(details["info"]["scan_start"]))
    print("\nscan start : " + start)
    try:
        stop = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime(details["info"]["scan_end"]))
        print("scan finish : " + stop)

        duration = (details["info"]["scan_end"] - details["info"]["scan_start"])/60
        print("Duration : " + str(duration)+" Minutes")
    except:
        print("This scan is still running")
    print("Scan Notes Below : ")
    for x in range(len(details["notes"])):
        print("         " + details["notes"][x]["title"])
        print("         " + details["notes"][x]["message"]+"\n")

def assets():
    data = get_data('/workbenches/assets/?date_range=30')
    l = []

    for x in range(len(data["assets"])):
        for y in range(len(data["assets"][x]["ipv4"])):
            ip = data["assets"][x]["ipv4"][y]
            id = data["assets"][x]["id"]

            while ip not in l:
                l.append(ip)
    l.sort()
    print("\nIn the last 30 days, I found " + str(len(l)) + " IP Addresess. See below:\n")
    for z in range(len(l)):
        print(l[z])

def users():
    data = get_data('/users')
    for x in range(len(data["users"])):
        print(data["users"][x]["name"])
        print(data["users"][x]["user_name"])

def nnm():
    #dynamically find the PVS sensor
    nnm_data = get_data('/scans')

    nnm_id = 0
    for x in range(len(nnm_data["scans"])):
        #print(nnm_data["scans"][x]["type"])
        if (str(nnm_data["scans"][x]["type"]) == 'pvs'):
            nnm_id = nnm_data["scans"][x]["id"]

            try:
                data = get_data('/scans/' + str(nnm_id) + '/')
                print("Here are the assets and their scores last found by Nessus Network Monitor")
                print("   IP Address     : Score")
                print("----------------")

                for y in range(len(data["hosts"])):
                    print(str(data["hosts"][y]["hostname"]) + " :  " + str(data["hosts"][y]["score"]))

                print()
            except:
                print("No Data found or no Nessus Monitor found")
                print("check permissions to the scanner")
        else:
            pass

def scan(cmd):
    print("\nChoose your Scan Template")
    print("1.  Basic")
    print("2   Discovery Scan")
    option = input("Please enter option #.... ")
    if option == '1':
        template = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"
    elif option == '2':
        template = "bbd4f805-3966-d464-b2d1-0079eb89d69708c3a05ec2812bcf"
    else:
        print("Using Basic scan since you can't follow directions")
        template = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"

    print("Here are the available scanners")
    scanners()
    scanner_id = input("What scanner do you want to scan with ?.... ")

    print("creating your scan of : " + cmd + "  Now...")

    payload = dict(uuid=template, settings={"name": "Navi Created Scan of "+cmd,
                                                                                          "enabled": "true",
                                                                                          "scanner_id":scanner_id,
                                                                                          "text_targets": cmd})
    headers = grab_headers()
    # create a new scan
    r = requests.post('https://cloud.tenable.com/scans', json=payload, headers=headers, verify=False)
    scan_data = r.json()


    # pull scan ID after Creation
    scan = scan_data["scan"]["id"]

    # launch Scan
    r2 = requests.request('POST', 'https://cloud.tenable.com/scans/' + str(scan) + '/launch', headers=headers, verify=False)
    data2 = r2.json()

    # print Scan UUID
    print("A scan started with UUID: " + data2["scan_uuid"])

def software(id):
    apps = get_data('/workbenches/assets/' + id + '/vulnerabilities/22869/outputs')

    try:
        print(apps['outputs'][0]['plugin_output'])
    except IndexError:
        try:
            l_apps = get_data('/workbenches/assets/' + id + '/vulnerabilities/20811/outputs')
            print(l_apps['outputs'][0]['plugin_output'])
        except:
            print("No Software Found")

def outbound(id):

    data = get_data('/workbenches/assets/' + id + '/vulnerabilities/16/outputs')
    print("\nOutbound External Connection")
    print("----------------")
    for x in range(len(data["outputs"])):
        print(data["outputs"][x]["plugin_output"])
        print("-----")
        for y in range(len(data["outputs"][x]["states"])):
            #print(data["outputs"][x]["states"][y]["results"])
            for z in range(len(data["outputs"][x]["states"][y]["results"])):
                application = data["outputs"][x]["states"][y]["results"][z]["application_protocol"]
                print("Port : " + str(data["outputs"][x]["states"][y]["results"][z]["port"])+'/'+str(application))

def unique(id,ip):
    print("IP Addresses:")
    print("--------------")
    # there maybe multiple IP addresses, loop through if that is the case.
    for z in range(len(ip)):
        print(ip[z])

    print("\nTenable UUID")
    print("--------------")
    print(id + '\n')
    info = get_data('/workbenches/assets/' + id + '/info')

    print("FQDN")
    print("--------------")
    # FQDN may be blank, so inform the user if that is the case;
    try:
        print(info['info']['fqdn'][0] + '\n')
    except:
        print("NO FQDN Found\n")

    print("Mac Address(s)")
    print("--------------")
    # there may be multiple Mac addressses assoicated, loop through each one
    for y in range(len(info['info']['mac_address'])):
        # there may not be any Mac addresses assigned, so inform the user if that is the case.
        try:
            print(info['info']['mac_address'][y])
        except:
            print("No Mac Address found")

    print("\nOperating System")
    print("--------------")
    print(info['info']['operating_system'][0])
    print('\n')

    print("Linux Memory Information")
    data2 = get_data('/workbenches/assets/' + id + '/vulnerabilities/45433/outputs')
    print("----------------")
    print_data(data2)

    print("Processor Information")
    data3 = get_data('/workbenches/assets/' + id + '/vulnerabilities/45432/outputs')
    print("----------------")
    print_data(data3)
    data4 = get_data('/workbenches/assets/' + id + '/vulnerabilities/48942/outputs')
    print_data(data4)

    print("Last Scan Date "+ str(info['info']['last_authenticated_scan_date']))

def plugin_by_ip(cmd,plugin):
    data = get_data('/workbenches/assets/vulnerabilities')

    for x in range(len(data['assets'])):
        # Grab the ID and IP address to pull data related to the current asset
        ip = (data['assets'][x]['ipv4'])
        id = (data['assets'][x]['id'])
        if cmd in ip:
            try:
                plugin_data = get_data('/workbenches/assets/' + id + '/vulnerabilities/' + plugin + '/outputs')
                print_data(plugin_data)
            except:
                print("No Data")
        else:
            pass

def print_data(data):
    try:
        #there may be multiple outputs
        for x in range(len(data['outputs'])):
            print(data['outputs'][x]['plugin_output'])
            print('\n')
    except:
        print("No Data found")
        print('\n')

def host_data(cmd,opt):

    data = get_data('/workbenches/assets/vulnerabilities')

    for x in range(len(data['assets'])):
        # Grab the ID and IP address to pull data related to the current asset
        ip = (data['assets'][x]['ipv4'])
        id = (data['assets'][x]['id'])

        if cmd in ip:
            if opt == 'N':
                print("Netstat info")
                print("Established and Listening")
                print("----------------")
                plugin_by_ip(cmd,str(58651))
                print("Netstat Open Ports")
                print("----------------")
                plugin_by_ip(cmd,str(14272))
            elif opt == 'S':
                print("Searching for Software...")
                software(id)
            elif opt == 'P':
                print("Patch Information")
                print("----------------")
                plugin_by_ip(cmd,str(66334))
            elif opt == 'T':
                print("Trace Route Info")
                print("----------------")
                plugin_by_ip(cmd,str(10287))
            elif opt == 'O':
                print("Process Info")
                print("----------------")
                plugin_by_ip(cmd,str(70329))
            elif opt == 'B':
                print("Missing Patches")
                print("----------------")
                plugin_by_ip(cmd,str(38153))
                print("Last Reboot")
                print("----------------")
                plugin_by_ip(cmd,str(56468))
            elif opt == 'C':
                print("Connection info")
                print("----------------")
                plugin_by_ip(cmd,str(64582))
            elif opt == 'U':
                unique(id,ip)
            elif opt == 's':
                print("Service(s) Running")
                print("----------------")
                plugin_by_ip(cmd,str(22964))
            elif opt == 'E':
                outbound(id)
            elif opt =="R":

                print("Local Firewall Info")
                print("----------------")
                plugin_by_ip(cmd,str(56310))

            else:
                try:
                    plugin_by_ip(cmd,opt)

                except:
                    print("No Data")
                    print("This is the raw data we got back")
                    print(data)
                    usage()

def scanners():
    try:
        data = get_data('/scanners')

        for x in range(len(data["scanners"])):
            print(str(data["scanners"][x]["name"]) + " : " + str(data["scanners"][x]["id"]))
    except:
        print("You may not have access...Check permissions...or Keys")

def exclude():
    try:
        data = get_data('/exclusions')
        for x in range(len(data["exclusions"])):
            print("Exclusion Name : " + data["exclusions"][x]["name"])
            print(data["exclusions"][x]["members"])

    except:
        print("No Exclusions Set")

def containers():
    data = get_data('/container-security/api/v1/container/list')
    print("Container Name : ID : # of Vulns\n")
    for x in range(len(data)):
        # print(data[x])

        print(str(data[x]["name"]) + " : " + str(data[x]["id"]) + " : " + str(data[x]["number_of_vulnerabilities"]))

def get(opt):

    if opt == 'nnm':
        nnm()
    elif opt == 'latest':
        latest()
    elif opt == 'scanners':
        scanners()
    elif opt == 'users':
        users()
    elif opt == 'exclusions':
        exclude()
    elif opt == 'containers':
        containers()
    elif opt == 'docker':
        print("We are looking for RUNNING docker containers...hang tight...This could take a minute or two")
        findplugin(str(93561))
    elif opt == 'webapp':
        print("We are looking for Web Servers running...hang tight...This could take a minute or two")
        findplugin(str(1442))
    elif opt =='assets':
        assets()
    elif opt =='creds':
        print("I'm looking for credential issues...Please hang tight")
        findplugin(str(104410))
    else:
        try:
            int(opt)
            findplugin(opt)
        except:
            print("You entered an option that doesn't exist either on purpose or by mistake\n")
            time.sleep(2)
            print("Check our Usage information...\nHere let me get that for you...")
            time.sleep(3)
            usage()

if __name__ == '__main__':
    try:
        print("Hey Listen!")
        main(sys.argv[1],sys.argv[2])

    except IndexError:
        usage()
