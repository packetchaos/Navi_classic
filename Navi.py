#!/usr/bin/env python3
#navi v3.1
#Created by The ITNinja - Casey Reid

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
        else:
            host_data(cmd,opt)
    except KeyError:
        print("You forgot your keys, or they are not correct.")

def usage():
    print()
    print("Usage: <command(get or scan)> or <Ip address> <option>")
    print()
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
    print("          <plugin id>")
    print()
    print("usage ex: '192.168.128.2 N' ")
    print()
    print("<'get' options>")
    print("           latest - Details on last scan run")
    print("           nnm - newest host found by nnm")
    print("           scanners - List all of the available scanners")
    print("           users - list all of the users")
    print("           exclusions - LIst of all of the exclusions")
    print()
    print("usage ex: 'get' latest")
    print()
    print("<'scan (ip address or subnet)'>")
    print()
    print("usage ex: scan 192.168.128.2")

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
    print()
    print("The last Scan run was at " + epock_latest)
    print()
    print("The Scanner name is : " + str(details["info"]["scanner_name"]))
    print()
    print("The Name of the scan is "+name)
    print("The " + str(details["info"]["hostcount"]) + " host(s) that were scanned are below :")
    print()
    for x in range(len(details["hosts"])):
        print(details["hosts"][x]["hostname"])

    start = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime(details["info"]["scan_start"]))
    print()
    print("scan start : " + start)
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
        print("         " + details["notes"][x]["message"])
        print()

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
        # print(nnm_data["scans"][x]["type"])
        if (str(nnm_data["scans"][x]["type"]) == 'pvs'):
            nnm_id = nnm_data["scans"][x]["id"]
        else:
            pass
    try:
        data = get_data('/scans/' + str(nnm_id) + '/')
        print("Here are the assets and their scores last found by Nessus Network Monitor")
        print("   IP Address     : Score")
        print("----------------")

        for y in range(len(data)):
            print(str(data["hosts"][y]["hostname"])+ " :  "+ str(data["hosts"][y]["score"]))

    except:
        print("No Data found or no Nessus Monitor found")
        print("check permissions to the scanner")

def scan(cmd):
    print()
    print("Choose your Scan Template")
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

def netstat(id):
    data = get_data('/workbenches/assets/'+id+'/vulnerabilities/58651/outputs')
    print("Netstat info")
    print("Established and Listening")
    print("----------------")
    print_data(data)
    print("Netstat Open Ports")
    print("----------------")
    data2 = get_data('/workbenches/assets/' + id + '/vulnerabilities/14272/outputs')
    print_data(data2)

def services(id):
    data = get_data('/workbenches/assets/'+id+'/vulnerabilities/22964/outputs')

    print("Service(s) Running")
    print("----------------")
    print_data(data)

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

def patch(id):
    data = get_data('/workbenches/assets/'+id+'/vulnerabilities/66334/outputs')
    print("Patch Information")
    print("----------------")
    print_data(data)

def tracert(id):
    data = get_data('/workbenches/assets/'+id+'/vulnerabilities/10287/outputs')
    print("Trace Route Info")
    print("----------------")
    print_data(data)

def process(id):
    data = get_data('/workbenches/assets/'+id+'/vulnerabilities/70329/outputs')
    print("Process Info")
    print("----------------")
    print_data(data)

def boot(id):
    data = get_data('/workbenches/assets/'+id+'/vulnerabilities/56468/outputs')
    patch_list = get_data('/workbenches/assets/'+id+'/vulnerabilities/38153/outputs')
    print("Missing Patches")
    print("----------------")

    print_data(patch_list)
    print("Last Reboot")
    print("----------------")
    print_data(data)

def connect(id):
    data = get_data('/workbenches/assets/'+id+'/vulnerabilities/64582/outputs')
    print("Connection info")
    print("----------------")
    print_data(data)

def outbound(id):
    data = get_data('/workbenches/assets/' + id + '/vulnerabilities/16/outputs')
    print()
    print("Outbound External Connection")
    print("----------------")
    for x in range(len(data["outputs"])):
        print(data["outputs"][x]["plugin_output"])
        print("-----")
        for y in range(len(data["outputs"][x]["states"])):
            #print(data["outputs"][x]["states"][y]["results"])
            for z in range(len(data["outputs"][x]["states"][y]["results"])):
                application = data["outputs"][x]["states"][y]["results"][z]["application_protocol"]
                print("Port : " + str(data["outputs"][x]["states"][y]["results"][z]["port"])+'/'+str(application))
    print()

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

def firewall(id):
    data = get_data('/workbenches/assets/' + id + '/vulnerabilities/56310/outputs')
    print("Local Firewall Info")
    print("----------------")
    print_data(data)

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
                netstat(id)
            elif opt == 'S':
                print("Searching for Software...")
                software(id)
            elif opt == 'P':
                patch(id)
            elif opt == 'T':
                tracert(id)
            elif opt == 'O':
                process(id)
            elif opt == 'B':
                boot(id)
            elif opt == 'C':
                connect(id)
            elif opt == 'U':
                unique(id,ip)
            elif opt == 's':
                services(id)
            elif opt == 'E':
                outbound(id)
            elif opt =="R":
                firewall(id)

            else:
                try:
                    plugin = get_data('/workbenches/assets/' + id + '/vulnerabilities/' + opt + '/outputs')
                    print_data(plugin)
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
        print("You may not have access...Check permissions")

def exclude():
    try:
        data = get_data('/exclusions')
        for x in range(len(data["exclusions"])):
            print("Exclusion Name : " + data["exclusions"][x]["name"])
            print(data["exclusions"][x]["members"])

    except:
        print("No Exclusions Set")

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
    else:
        print("Try Again")
        print("Only Four options")
        print("get latest, get nnm, get scanners or get users")


if __name__ == '__main__':
    try:
        print("Hey Listen!")
        main(sys.argv[1],sys.argv[2])

    except IndexError:
        usage()