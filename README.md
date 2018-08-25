# Navi
A Command-line tool which leverages the Tenable.io API to reduce the time it takes to get information that is common during remediation or a troubleshooting event

## Usage
In order to get going you need to add your API keys!
`python3 Navi.py new keys`

Each command has two parts: the Command and the Option/Request. There are four core commands: get, scan, post and ip address. When inputting a single ip address you can query plugins by supplying the plugin ID or one of the built in options denoted by a letter. 

### IP address queries
  * N - Netstat
  * T - Trace Rt
  * P - Patch
  * S - Software
  * B - Missing MS Patch and last Boot
  * C - Connection info
  * U - Unique Asset Info
  * s - Services running
  * E - Outbound External Connections
  * R - Local Firewall Rules
  * O - Process information
  * plugin-id - Example: 19506

### Examples
`python3 Navi.py 192.168.128.1 N`
`python3 Navi.py 192.168.128.1 19506`

### Get information
  * latest - Details on last scan run
  * scans  - Get all of the scans, their IDs and their status
  * running  - Get all of the scans currently running
  * nnm - newest host found by nnm
  * scanners - List all of the available scanners
  * users - list all of the users
  * exclusions - List of all of the exclusions
  * containers - List all containers in Container security, ids, # of vulns
  * docker - List hosts with running containers; show those containers
  * webapp - List running web servers
  * assets - List the IPs found in the last 30 days
  * creds  - List any hosts that had credential failures
  * logs   - List the actor and the action seperated by Date
  * agents - List agents connected to US cloud Scanner
  * plugin-id - Example: 19506
  * API-Endpoint 

### Examples
`python3 Navi.py get latest`
`python3 Navi.py get 19506`
`python3 Navi.py get /scans`

### Scan ip address or subnet
`python3 Navi.py scan 192.168.128.0/24`

## Use Cases
### What was last scanned?
`python3 Navi.py get latest`

### What scans are running right now?
`python3 Navi.py get running`

### Find a Scan
`python3 Navi.py get scans | grep Navi`

### Create a Scan
`python3 Navi.py scan 192.168.128.0/24`
  * Choose your scan type: Basic or Discovery
  * Pick your scanner by ID: scanners will be displayed
  * Scan will immediately kick off

### Control your scans
`python3 Navi.py pause 13(scan-id)`
`python3 Navi.py resume 13`
`python3 Navi.py stop 13`

### Find Available scanners
`pyhton3 Navi.py get scanners`

### Find Non-Cloud scanners
`python3 Navi.py get scanners | grep -e -v Cloud`

### Check an data not programed or query a new api-endpoint
`python3 Navi.py get /scans`
`python3 Navi.py post /scans/13/launch`
