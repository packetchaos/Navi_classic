#!/usr/bin/env python3
#navi v4.2

#Created by Casey Reid
#Disclaimer: This is NOT supported By Tenable!
#The API keys are not stored in an encrypted format.
#This is used to show what is possible with the Tenable API

import requests
import sys
import time
import pickle
import os
import threading
import pprint

requests.packages.urllib3.disable_warnings()

def save_keys():
    #assumption is that the user keys didn't work or don't exist
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

    #check for API keys; if none, get them from the user by calling save_keys()
    if os.path.isfile('./keys.pickle') is False:
        save_keys()
    else:
        pickle_in = open("keys.pickle", "rb")
        keys = pickle.load(pickle_in)
        access_key = keys["Access Key"]
        secret_key = keys["Secret Key"]

    #set the header
    headers = {'Content-type':'application/json','X-ApiKeys':'accessKey='+access_key+';secretKey='+secret_key}
    return headers

def get_data(url_mod):
    '''

    :param url_mod: The URL endpoint. Ex: /scans
    :return: Response from API in json format
    '''
    url = "https://cloud.tenable.com"
    headers = grab_headers()
    r = requests.request('GET', url + url_mod, headers=headers, verify=False)
    data = r.json()
    return data

def post_data(url_mod):
    '''

    :param url_mod: The URL endpoint. Ex: /scans/<scan-id>/launch
    :return: Response from the API
    '''
    url = "https://cloud.tenable.com"
    headers = grab_headers()
    r = requests.post(url + url_mod, headers=headers, verify=False)

    return r

def main(cmd,opt):
    try:
        if cmd == 'get':
            get(opt)
        elif cmd == 'post':
            new_data = post_data(opt)
            print('Status Code')
            print(new_data.status_code)
            print()
            print('Status Response/Reason')
            print(new_data.reason)
        elif cmd == 'pause':
            pause(opt)
        elif cmd == 'resume':
            resume(opt)
        elif cmd == 'stop':
            stop(id)
        elif cmd == 'scan':
            try:
                scan(opt)
            except:
                print("Invalid input")
        elif cmd == 'report':
            try:
                report(opt)
            except:
                print("Invalid Input")
        elif cmd == 'exploit':
            try:
                exploit(opt)
            except:
                print("Invalid Input")
        elif cmd == 'new':
            save_keys()
        else:
            host_data(cmd,opt)
    except KeyError:
        print("You forgot your keys, or they are not correct.\n")
        print("Consider changing your keys using 'new keys' command")

def findplugin(plugin_id):
    data = get_data('/workbenches/assets/')
    print("Searching for the plugin_out put for plugin: "+plugin_id+" on all assets...")
    for x in range(len(data["assets"])):
        try:
            ip = data["assets"][x]["ipv4"][0]
            uid = data["assets"][x]["id"]

            #removed from Threading due to API constraints
            info = get_data('/workbenches/assets/' + str(uid) + '/vulnerabilities/' + str(plugin_id) + '/outputs')
            eval = info["outputs"][0]["plugin_output"]
            print(ip)
            print_data(info)

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
    print("          0 - Process information")
    print("          <plugin id>\n")
    print("usage ex: '192.168.128.2 N' or '192.168.128.2 19506'\n")
    print("<'get' options>")
    print("           latest - Details on last scan run")
    print("           scans  - Get all of the scans, their IDs and their status")
    print("           running  - Get all of the scans currently running")
    print("           nnm - newest host found by nnm")
    print("           scanners - List all of the available scanners")
    print("           users - list all of the users")
    print("           exclusions - List of all of the exclusions")
    print("           containers - List all containers in Container security, ids, # of vulns")
    print("           docker - List hosts with running containers; show those containers")
    print("           webapp - List running web servers")
    print("           assets - List the IPs found in the last 30 days")
    print("           creds  - List any hosts that had credential failures")
    print("           logs - Print the action and the actor for every log activity recorded")
    print("           agents - List agents connected to US cloud Scanner")
    print("           <api-endpoint> example: [ get /scans ]")
    print("           <plugin_id>\n")
    print("usage ex: 'get latest' or 'get 19506'\n")
    print(" report <ip address> - Get the Critical Vulns and the solutions\n")
    print(" exploit <ip address> - Get the Exploitable vulns, Description, Solution and CVE ID\n")
    print("<'scan (ip address or subnet)'>\n")
    print("usage ex: scan 192.168.128.2\n")
    print("Control your scans: pause, resume, stop using the scan id\n")
    print("<'pause (scan ID)'> usage ex: pause 13\n")
    print("post <api-endpoint> example: post /scans/13/launch ")
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
        #don't capture the PVS or Agent data in latest
        while type not in ['pvs','agent','webapp']:
            # put scans in a list to find the latest
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
    print("\nThe Name of the scan is " + str(details["info"]["name"]))
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
    print("Remember, don't pick a Cloud scanner for an internal IP address")
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

def report(opt):
    N = get_data("/workbenches/assets/vulnerabilities")

    for asset in range(len(N["assets"])):

        for ips in range(len(N["assets"][asset]["ipv4"])):
            ip = N["assets"][asset]["ipv4"][ips]

            if opt == ip:

                print("Critical Vulns for Ip Address :" + opt)
                print()
                id = N["assets"][asset]["id"]
                vulns = get_data("/workbenches/assets/" + id + "/vulnerabilities?date_range=90")
                #pprint.pprint(vulns["vulnerabilities"])
                for severities in range(len(vulns["vulnerabilities"])):
                    vuln_name = vulns["vulnerabilities"][severities]["plugin_name"]
                    id = vulns["vulnerabilities"][severities]["plugin_id"]
                    severity = vulns["vulnerabilities"][severities]["severity"]
                    state = vulns["vulnerabilities"][severities]["vulnerability_state"]

                    #only pull the critical vulns; critical = severity 4
                    if severity >= 4:
                        print("Plugin Name : " + vuln_name)
                        print("ID : " + str(id))
                        print("Severity : " + str(severity))
                        print("State : " + state)
                        print("----------------\n")
                        plugin_by_ip(str(opt), str(id))



            else:
                pass

def exploit(opt):


    N = get_data(
        '/workbenches/assets/vulnerabilities?filter.0.quality=eq&filter.0.filter=plugin.attributes.exploit_available&filter.0.value=True')
    for assets in range(len(N['assets'])):
        asset_id = N['assets'][assets]['id']

        for ips in N['assets'][assets]['ipv4']:
            ip_addy = N['assets'][assets]['ipv4'][0]
            if ip_addy == opt:
                print("Exploitable Details for : " + ip_addy)
                print()
                V = get_data('/workbenches/assets/' + asset_id + '/vulnerabilities?filter.0.quality=eq&filter.0.filter=plugin.attributes.exploit_available&filter.0.value=True')
                for plugins in range(len(V['vulnerabilities'])):
                    plugin = V['vulnerabilities'][plugins]['plugin_id']
                    # pprint.pprint(plugin)

                    P = get_data('/plugins/plugin/' + str(plugin))
                    # pprint.pprint(P['attributes'])
                    print("\n----Exploit Info----")
                    print(P['name'])
                    print()
                    for attribute in range(len(P['attributes'])):

                        if P['attributes'][attribute]['attribute_name'] == 'cve':
                            cve = P['attributes'][attribute]['attribute_value']
                            print("CVE ID : " + cve)

                        if P['attributes'][attribute]['attribute_name'] == 'description':
                            description = P['attributes'][attribute]['attribute_value']
                            print("Description")
                            print("------------\n")
                            print(description)
                            print()

                        if P['attributes'][attribute]['attribute_name'] == 'solution':
                            solution = P['attributes'][attribute]['attribute_value']
                            print("\nSolution")
                            print("------------\n")
                            print(solution)
                            print()

def pause(id):
    try:
        data = post_data('/scans/' + str(id) + '/pause')
        if data.status_code == 200:
            print(" Your Scan was Paused")
        elif data.status_code == 409:
            print("Wait a few seconds and try again")
        elif data.status_code == 404:
            print("yeah, this scan doesn't exist")
        elif data.status_code == 501:
            print("There was an error: ")
            print(data.reason)
        else:
            print("It's possible this is already paused")
    except:
        print("Ahh now you've done it...")
        print("double check your id")

def resume(id):
    try:
        data = post_data('/scans/' + str(id) + '/resume')
        if data.status_code == 200:
            print(" Your Scan Resumed")
        elif data.status_code == 409:
            print("Wait a few seconds and try again")
        elif data.status_code == 404:
            print("yeah, this scan doesn't exist")
        else:
            print("It's possible this is already running")


    except:
        print("Ahh now you've done it...")
        print("double check your id")

def stop(id):
    try:
        data = post_data('/scans/' + str(id) + '/stop')
        if data.status_code == 200:
            print(" Your Scan was Stopped")
        elif data.status_code == 409:
            print("Wait a few seconds and try again")
        elif data.status_code == 404:
            print("yeah, this scan doesn't exist")
        else:
            print("It's possible this is already stopped")


    except:
        print("Ahh now you've done it...")
        print("double check your id")

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
    print("\nOutbound External Connection Found by Nessus Network Monitor")
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
    #pprint.pprint(info)
    print("\nCurrent Severity Counts")
    print("--------------")
    for s in range(len(info['info']['counts']['vulnerabilities']['severities'])):
        severity = info['info']['counts']['vulnerabilities']['severities'][s]['name']
        count = info['info']['counts']['vulnerabilities']['severities'][s]['count']

        print(severity + " " + str(count))

    print("\nFQDN")
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
                print("No data")
        else:
            pass

def print_data(data):
    try:
        #there may be multiple outputs
        for x in range(len(data['outputs'])):
            print(data['outputs'][x]['plugin_output'])
    except:
        print("No Data found\n")

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

                except(TypeError):
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

def running():
    try:
        data = get_data('/scans')

        for scans in range(len(data['scans'])):
            # pprint.pprint(N['scans'][scans])
            if data['scans'][scans]['status'] == "running":

                name = data['scans'][scans]['name']
                scan_id = data['scans'][scans]['id']
                status = data['scans'][scans]['status']

                print("Scan Name : " + name)
                print("Scan ID : " + str(scan_id))
                print("Current status : " + status)


    except:
        print("You may not have access...Check permissions...or Keys")

def list_scans():
    try:
        data = get_data('/scans')

        for x in range(len(data['scans'])):

            name = data['scans'][x]['name']
            scan_id = data['scans'][x]['id']
            status = data['scans'][x]['status']

            print("Scan Name : " + name)
            print("Scan ID : " + str(scan_id))
            print("Current status : " + status)
            print("-----------------")
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
    try:
        data = get_data('/container-security/api/v1/container/list')
        print("Container Name : ID : # of Vulns\n")
        for x in range(len(data)):
            # print(data[x])

            print(str(data[x]["name"]) + " : " + str(data[x]["id"]) + " : " + str(data[x]["number_of_vulnerabilities"]))
    except:
        print("No containers found")

def logs():
    data = get_data('/audit-log/v1/events')
    #pprint.pprint(data['events'])
    for log in range(len(data['events'])):
        received = data['events'][log]['received']
        action = data['events'][log]['action']
        actor = data['events'][log]['actor']['name']

        print("Date : " + received)
        print("-------------------")
        print(action)
        print(actor)
        print()

def agents():
    data = get_data('/scanners')

    # get US cloud Scanner ID
    for scanner in range(len(data['scanners'])):
        if data['scanners'][scanner]['name'] == 'US Cloud Scanner':
            scan_id = data['scanners'][scanner]['id']

            #pull agent data from the US cloud Scanner
            agents = get_data('/scanners/' + str(scan_id) + '/agents')

            #cycle through the agents and display the useful information
            for a in range(len(agents['agents'])):
                print('\n------Agent Info-------\n')
                print(agents['agents'][a]['name'])
                print(agents['agents'][a]['ip'])
                print(agents['agents'][a]['platform'])
                print("\nLast time it connected")
                last_connect = agents['agents'][a]['last_connect']
                connect_time = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(last_connect))
                print(connect_time)
                print("\nLast time it was scanned")
                last_scanned = agents['agents'][a]['last_scanned']
                scanned_time = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(last_scanned))
                print(scanned_time)
                print("\nStatus")
                print(agents['agents'][a]['status'])
                print('\n-----End Info-----------\n')

def get(opt):

    if opt == 'nnm':
        nnm()
    elif opt == 'logs':
        logs()
    elif opt == 'running':
        running()
    elif opt == 'scans':
        list_scans()
    elif opt == 'latest':
        latest()
    elif opt == 'agents':
        agents()
    elif opt == 'scanners':
        scanners()
    elif opt == 'users':
        users()
    elif opt == 'exclusions':
        exclude()
    elif opt == 'containers':
        containers()
    elif opt == 'docker':
        print("Searching for RUNNING docker containers...")
        findplugin(str(93561))
    elif opt == 'webapp':
        print("Searching for Web Servers running...")
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

        except ValueError:
            try:
                data = get_data(opt)
                pprint.pprint(data)
            except:
                print("The API endpoint you tried threw an error")
                print("Or the command you tried didn't work")

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
