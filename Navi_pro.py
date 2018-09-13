#!/usr/bin/env python3
import click
import requests
import pprint
import time
import threading
import os
import pickle
import sys

requests.packages.urllib3.disable_warnings()

@click.group()
def cli():
    click.echo("Hey Listen!")

@cli.command()
def keys():
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
        keys()
    else:
        pickle_in = open("keys.pickle", "rb")
        actual_keys = pickle.load(pickle_in)
        access_key = actual_keys["Access Key"]
        secret_key = actual_keys["Secret Key"]

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
    try:
        r = requests.request('GET', url + url_mod, headers=headers, verify=False)

        if r.status_code == 200:
            data = r.json()
            return data
        elif r.status_code == 404:
            click.echo('Check your query...')
            click.echo(r)
        elif r.status_code == 429:
            click.echo("Too many requests at a time... Threading is unbound right now.")
        elif r.status_code == 400:
            pass
        else:
            click.echo("Something went wrong...Don't be trying to hack me now")
            click.echo(r)
    except ConnectionError:
        print("Check your connection...You got a connection error")
    #Trying to catch API errors

def post_data(url_mod):
    '''

    :param url_mod: The URL endpoint. Ex: /scans/<scan-id>/launch
    :return: Response from the API
    '''
    url = "https://cloud.tenable.com"
    headers = grab_headers()
    r = requests.post(url + url_mod, headers=headers, verify=False)

    return r

def plugin_by_ip(cmd,plugin):
    data = get_data('/workbenches/assets/vulnerabilities')

    for x in range(len(data['assets'])):
        # Grab the ID and IP address to pull data related to the current asset
        ip = (data['assets'][x]['ipv4'])
        id = (data['assets'][x]['id'])
        if cmd in ip:
            try:
                plugin_data = get_data('/workbenches/assets/' + id + '/vulnerabilities/' + plugin + '/outputs')
                #Send data to be printed to the screen
                print_data(plugin_data)
            except:
                print("No Data")
        else:
            pass

def find_by_plugin(plugin):
    data = get_data('/workbenches/assets/')
    print("Searching for the plugin_out put for plugin: " + plugin + " on all assets...")
    for x in range(len(data["assets"])):
        try:
            ip = data["assets"][x]["ipv4"][0]
            uid = data["assets"][x]["id"]
            # create a new thread for each asset
            # Need to come back and put limitations on this
            t = threading.Thread(target=thread_fetch, args=(ip, uid, plugin))
            t.start()
        except:
            pass

def print_data(data):
    try:
        #there may be multiple outputs
        for x in range(len(data['outputs'])):
            click.echo(data['outputs'][x]['plugin_output'])

        #print an extra line in case the user sends multiple commands
        click.echo()

    except:
        pass

def thread_fetch(ip,uid,plugin_id):
    #i'm new to threading, so I broke this code out from the findplugin function to take advantage of threading
    #I intend to fix this with a more proper solution as I learn.
    try:
        info = get_data('/workbenches/assets/' + str(uid) + '/vulnerabilities/' + str(plugin_id) + '/outputs')
        #Need a better way of causing a failure so we don't print every IP.
        #raising the eval equality will raise a Index Error if there is no data associated
        eval = info["outputs"][0]["plugin_output"]

        #print the IP address and send the rest to the print function to be printed
        print(ip)
        print_data(info)
    except:
        pass

def nessus_scanners():
    try:
        data = get_data('/scanners')

        for x in range(len(data["scanners"])):
            print(str(data["scanners"][x]["name"]) + " : " + str(data["scanners"][x]["id"]))
    except:
        print("You may not have access...Check permissions...or Keys")

@cli.command()
@click.argument('ipaddr')
@click.option('--plugin', default='', help='Plugin ID')
@click.option('-n', is_flag=True, help='Netstat Established and Listening and Open Ports')
@click.option('-p', is_flag=True, help='Patch Information')
@click.option('-t', is_flag=True, help='Trace Route')
@click.option('-o', is_flag=True, help='Process Information')
@click.option('-c', is_flag=True, help='Connection Information')
@click.option('-s', is_flag=True, help='Services Running')
@click.option('-r', is_flag=True, help='Local Firewall Rules')
@click.option('-b', is_flag=True, help='Missing Patches')
@click.option('-d', is_flag=True, help="Scan Detail: 19506")
@click.option('-software', is_flag=True, help="Find software installed on Unix of windows hosts")
@click.option('-outbound', is_flag=True, help="outbound connections found by nnm")
@click.option('-exploit', is_flag=True, help="Display exploitable vulnerabilities")
@click.option('-critical', is_flag=True, help="Display critical vulnerabilities")
@click.option('-details', is_flag=True, help="Details on an Asset: IP, UUID, Vulns, etc")
def ip(ipaddr, plugin, n, p, t, o, c, s, r, b, d, software, outbound, exploit, critical, details):

    plugin_by_ip(ipaddr, plugin)

    if d:
        click.echo('Scan Detail')
        click.echo('----------------')
        plugin_by_ip(ipaddr, str(19506))

    if n:
        click.echo("Netstat info")
        click.echo("Established and Listening")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(58651))
        click.echo("Netstat Open Ports")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(14272))

    if p:
        click.echo("Patch Information")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(66334))

    if t:
        click.echo("Trace Route Info")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(10287))

    if o:
        click.echo("Process Info")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(70329))

    if b:
        click.echo("Missing Patches")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(38153))

        click.echo("Last Reboot")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(56468))

    if c:
        click.echo("Connection info")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(64582))

    if s:
        click.echo("Service(s) Running")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(22964))

    if r:
        click.echo("Local Firewall Info")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(56310))

    if software:
        try:
            plugin_by_ip(ipaddr, str(22869))
            plugin_by_ip(ipaddr, str(20811))
        except IndexError:
                print("No Software found")

    if outbound:
        asset = get_data('/workbenches/assets/vulnerabilities')

        for x in range(len(asset['assets'])):
            # Grab the ID and IP address to pull data related to the current asset
            ip = (asset['assets'][x]['ipv4'])
            id = (asset['assets'][x]['id'])

            if ipaddr in ip:
                data = get_data('/workbenches/assets/' + id + '/vulnerabilities/16/outputs')
                print("\nOutbound External Connection Found by Nessus Network Monitor")
                print("----------------")
                for x in range(len(data["outputs"])):
                    print(data["outputs"][x]["plugin_output"])
                    print("-----")
                    for y in range(len(data["outputs"][x]["states"])):
                        # print(data["outputs"][x]["states"][y]["results"])
                        for z in range(len(data["outputs"][x]["states"][y]["results"])):
                            application = data["outputs"][x]["states"][y]["results"][z]["application_protocol"]
                            print(
                                "Port : " + str(data["outputs"][x]["states"][y]["results"][z]["port"]) + '/' + str(application))
        print()

    if exploit:
        N = get_data(
            '/workbenches/assets/vulnerabilities?filter.0.quality=eq&filter.0.filter=plugin.attributes.exploit_available&filter.0.value=True')
        for assets in range(len(N['assets'])):
            asset_id = N['assets'][assets]['id']

            for ips in N['assets'][assets]['ipv4']:
                ip_addy = N['assets'][assets]['ipv4'][0]
                if ip_addy == ipaddr:
                    print("Exploitable Details for : " + ip_addy)
                    print()
                    V = get_data(
                        '/workbenches/assets/' + asset_id + '/vulnerabilities?filter.0.quality=eq&filter.0.filter=plugin.attributes.exploit_available&filter.0.value=True')
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

    if critical:
        N = get_data("/workbenches/assets/vulnerabilities")

        for asset in range(len(N["assets"])):

            for ips in range(len(N["assets"][asset]["ipv4"])):
                ip = N["assets"][asset]["ipv4"][ips]

                if ipaddr == ip:

                    print("Critical Vulns for Ip Address :" + ipaddr)
                    print()
                    id = N["assets"][asset]["id"]
                    vulns = get_data("/workbenches/assets/" + id + "/vulnerabilities?date_range=90")
                    for severities in range(len(vulns["vulnerabilities"])):
                        vuln_name = vulns["vulnerabilities"][severities]["plugin_name"]
                        id = vulns["vulnerabilities"][severities]["plugin_id"]
                        severity = vulns["vulnerabilities"][severities]["severity"]
                        state = vulns["vulnerabilities"][severities]["vulnerability_state"]

                        # only pull the critical vulns; critical = severity 4
                        if severity >= 4:
                            print("Plugin Name : " + vuln_name)
                            print("ID : " + str(id))
                            print("Severity : " + str(severity))
                            print("State : " + state)
                            print("----------------\n")
                            plugin_by_ip(str(ipaddr), str(id))



                else:
                    pass

    if details:
        asset = get_data('/workbenches/assets/vulnerabilities')

        for x in range(len(asset['assets'])):
            # Grab the ID and IP address to pull data related to the current asset
            ip = (asset['assets'][x]['ipv4'])
            id = (asset['assets'][x]['id'])

            if ipaddr in ip:
                print("IP Addresses:")
                print("--------------")
                # there maybe multiple IP addresses, loop through if that is the case.
                for z in range(len(ip)):
                    print(ip[z])

                print("\nTenable UUID")
                print("--------------")
                print(id + '\n')
                info = get_data('/workbenches/assets/' + id + '/info')
                # pprint.pprint(info)
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

                print("Last Scan Date " + str(info['info']['last_authenticated_scan_date']))

@cli.command()
@click.option('--plugin', default='', help='Plugin ID')
@click.option('-docker', is_flag=True, help="Find Running Docker Containers")
@click.option('-webapp', is_flag=True, help="Find Web Servers running")
@click.option('-creds', is_flag=True, help="Find Credential failures")
def find(plugin, docker, webapp, creds):

    if plugin != '':

        if str.isdigit(plugin) != True:
            print("You didn't enter a number")
        else:
            find_by_plugin(plugin)

    if docker:
        print("Searching for RUNNING docker containers...")
        find_by_plugin(str(93561))

    if webapp:
        print("Searching for Web Servers running...")
        find_by_plugin(str(1442))

    if creds:
        print("I'm looking for credential issues...Please hang tight")
        find_by_plugin(str(104410))

@cli.command()
@click.option('-latest', is_flag=True, help="Report the Last Scan Details")
def report(latest):
    #get the latest Scan Details
    if latest:
        data = get_data('/scans')
        l = []
        e = {}
        for x in range(len(data["scans"])):
            # keep UUID and Time together
            # get last modication date for duration computation
            epoch_time = data["scans"][x]["last_modification_date"]
            # get the scanner ID to display the name of the scanner
            d = data["scans"][x]["id"]
            # need to identify type to compare against pvs and agent scans
            type = str(data["scans"][x]["type"])
            # don't capture the PVS or Agent data in latest
            while type not in ['pvs', 'agent', 'webapp']:
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

            duration = (details["info"]["scan_end"] - details["info"]["scan_start"]) / 60
            print("Duration : " + str(duration) + " Minutes")
        except:
            print("This scan is still running")
        print("Scan Notes Below : ")
        for x in range(len(details["notes"])):
            print("         " + details["notes"][x]["title"])
            print("         " + details["notes"][x]["message"] + "\n")

@cli.command()
@click.argument('url')
def api(url):
    try:
        data = get_data(url)
        pprint.pprint(data)
    except:
        click.echo("The API endpoint you tried threw an error")

@cli.command()
@click.option('-scanners', is_flag=True, help="List all of the Scanners")
@click.option('-users', is_flag=True, help="List all of the Groups")
@click.option('-exclusions', is_flag=True, help="List all Exclusions")
@click.option('-containers', is_flag=True, help="List all containers and their Vulnerability  Scores")
@click.option('-logs', is_flag=True, help="List The actor and the action in the log file")
@click.option('-running', is_flag=True, help="List the running Scans")
@click.option('-scans', is_flag=True, help="List all Scans")
@click.option('-nnm', is_flag=True, help="Nessus Network Monitor assets and their vulnerability scores")
@click.option('-assets', is_flag=True, help="Assets found in the last 30 days")
def list(scanners, users, exclusions, containers, logs, running, scans, nnm, assets):
    #need to do
    #groups
    #target-groups
    if scanners:
        nessus_scanners()

    if users:
        data = get_data('/users')
        for x in range(len(data["users"])):
            print(data["users"][x]["name"])
            print(data["users"][x]["user_name"])

    if exclusions:
        try:
            data = get_data('/exclusions')
            for x in range(len(data["exclusions"])):
                print("Exclusion Name : " + data["exclusions"][x]["name"])
                print(data["exclusions"][x]["members"])

        except:
            print("No Exclusions Set")

    if containers:
        try:
            data = get_data('/container-security/api/v1/container/list')
            print("Container Name : ID : # of Vulns\n")
            for x in range(len(data)):
                # print(data[x])

                print(str(data[x]["name"]) + " : " + str(data[x]["id"]) + " : " + str(
                    data[x]["number_of_vulnerabilities"]))
            print()
        except:
            print("No containers found")

    if logs:
        data = get_data('/audit-log/v1/events')
        # pprint.pprint(data['events'])
        for log in range(len(data['events'])):
            received = data['events'][log]['received']
            action = data['events'][log]['action']
            actor = data['events'][log]['actor']['name']

            print("Date : " + received)
            print("-------------------")
            print(action)
            print(actor)
            print()

    if running:
        #run = 0
        try:
            data = get_data('/scans')
            run = 0
            for x in range(len(data['scans'])):
                if data['scans'][x]['status'] == "running":
                    run = run + 1
                    name = data['scans'][x]['name']
                    scan_id = data['scans'][x]['id']
                    status = data['scans'][x]['status']

                    click.echo("Scan Name : " + name)
                    print("Scan ID : " + str(scan_id))
                    print("Current status : " + status)
            if run == 0:
                print("No running scans")
        except:
            print("You may not have access...Check permissions...or Keys")

    if scans:
        try:
            data = get_data('/scans')

            for x in range(len(data['scans'])):
                name = data['scans'][x]['name']
                scan_id = data['scans'][x]['id']
                status = data['scans'][x]['status']

                print("Scan Name : " + name)
                print("Scan ID : " + str(scan_id))
                print("Current status : " + status)
                print("-----------------\n")

        except:
            print("You may not have access...Check permissions...or Keys")

    if nnm:
        # dynamically find the PVS sensor
        nnm_data = get_data('/scans')

        for x in range(len(nnm_data["scans"])):

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

    if assets:
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
        print()

@cli.command()
@click.argument('targets')
def scan(targets):
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
    nessus_scanners()
    scanner_id = input("What scanner do you want to scan with ?.... ")

    print("creating your scan of : " + targets + "  Now...")

    payload = dict(uuid=template, settings={"name": "Navi-Pro Created Scan of " + targets,
                                            "enabled": "true",
                                            "scanner_id": scanner_id,
                                            "text_targets": targets})
    headers = grab_headers()
    # create a new scan
    r = requests.post('https://cloud.tenable.com/scans', json=payload, headers=headers, verify=False)
    scan_data = r.json()

    # pull scan ID after Creation
    scan = scan_data["scan"]["id"]

    # launch Scan
    r2 = requests.request('POST', 'https://cloud.tenable.com/scans/' + str(scan) + '/launch', headers=headers,
                          verify=False)
    data2 = r2.json()

    # print Scan UUID
    print("A scan started with UUID: " + data2["scan_uuid"])
    print("The scan ID is " + str(scan))

@cli.command()
@click.argument('Scan_id')
def pause(scan_id):
    try:
        data = post_data('/scans/' + str(scan_id) + '/pause')
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

@cli.command()
@click.argument('scan_id')
def resume(scan_id):
    try:
        data = post_data('/scans/' + str(scan_id) + '/resume')
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

@cli.command()
@click.argument('scan_id')
def stop(scan_id):
    try:
        data = post_data('/scans/' + str(scan_id) + '/stop')
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

@cli.command()
@click.argument('scan_id')
def start(scan_id):
    try:
        data = post_data('/scans/' + str(scan_id) + '/launch')
        if data.status_code == 200:
            print(" Your Scan was Started")
        elif data.status_code == 409:
            print("Wait a few seconds and try again")
        elif data.status_code == 404:
            print("yeah, this scan doesn't exist")
        else:
            print("It's possible this is already started")


    except:
        print("Ahh now you've done it...")
        print("double check your id")

if __name__ == '__main__':
    cli()
