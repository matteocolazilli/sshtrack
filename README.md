# SSHTrack

## Description
SSHTrack is a project made during my bachelor thesis that aims to track SSH session leveraging eBPF.
It uses a socket filter and different tracepoints offered by the eBPF framework to hook 
incoming SSH sessions and consequentially to retrieve and report in JSON format relative 
information about them. Currently, logged information are:

* login user's UID 
* a login timestamp in ms from the system boot
* the PID of the process holding the session
* IP source address 
* IP source port
* last executed command with the first six passed arguments 

Additionally, it can highlight suspicious commands based on a specific configuration file
that can be manually modified.
Furthermore, it can be used side-by-side with the furnished Python server to generate 
an HTML page exposed to external access to monitor incoming SSH sessions from a different 
host.


