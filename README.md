# Navi
A Command-line tool which leverages the Tenable.io API to reduce the time it takes to get information that is common during remediation or a troubleshooting event

## Usage
In order to get going you need to add your API keys!
`./Navi.py new keys`

Each command has two parts: the Command and the Option/Request. There are four core commands: get, scan, post and ip address. When inputting a single ip address you can query plugins by supplying the plugin ID or one of the built in options denoted by a letter. 

### IP address queries
  * N - Netstat
  * T - Trace Rt
..*P - Patch
..*S - Software
..*B - Missing MS Patch and last Boot
..*C - Connection info
..*U - Unique Asset Info
..*s - Services running
..*E - Outbound External Connections
..*R - Local Firewall Rules
..*O - Process information
..*<plugin id>

###Examples
`./Navi.py 192.168.128.1 N`
`./Navi.py 192.168.128.1 19506`

### Get information
..*latest - Details on last scan run
..*scans  - Get all of the scans, their IDs and their status
..*running  - Get all of the scans currently running
..*nnm - newest host found by nnm
..*scanners - List all of the available scanners
..*users - list all of the users
..*exclusions - List of all of the exclusions
..*containers - List all containers in Container security, ids, # of vulns
..*docker - List hosts with running containers; show those containers
..*webapp - List running web servers
..*assets - List the IPs found in the last 30 days
..*creds  - List any hosts that had credential failures
..*agents - List agents connected to US cloud Scanner
..*<plugin_id>
..*<api-endpoint>

####Examples
`./Navi.py get latest`
`./Navi.py get 19506`
`./Navi.py get /scans`

### Scan <ip address or subnet>
`./Navi.py scan 192.168.128.0/24`

##Use Cases
### What was last scanned?
`./Navi.py get latest`

### What scans are running right now?
`./Navi.py get running`

### Find Available scanners
`./Navi.py get scanners`
