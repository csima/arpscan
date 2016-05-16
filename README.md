# arpscan

Purpose of this is to monitor a network for any devices that are not stored in a whitelist and fire off an email if a new device has been detected on the network.
As a side benefit it also will show when a device comes online/offline. Note: This functionality is pretty unreliable - devices such as iOS will go to sleep and no longer
respond to ARP requests OR I'm screwing up somewhere in this code. See my blog post for more detail on ARP reliability scanning part.

Step: 1 - Run arpscan and dump your initial MAC whitelist. Do this via `arpscan -output mac`. You might want to let this run for a couple minutes
and review which query gave the most total devices back and copy that mac list and format it correctly and put it under 'whitelist' in arpscan.yaml

Step: 2 - Edit the arpscan.yaml configuration file
You will want to fill in your email authentication creds here to fire off an email. Also specifiy your MAC whitelist.

```
# define a whitelist of mac addresses. 
# this list is what is used for email alerts
# to get a list run arpscan with the command param './arpscan -output mac'
#interface: en0
whitelist:
# - 00:00:00:00:00:00
email:
 enabled: false
 username: user
 password: password
 to: joe@joe.com
 server: smtp.gmail.com
 port: 587
 frequency: 8 # how frequent the new device report is emailed in hours
 ```
 Step: 3 - Run it and walk away
 I recommend keeping the frequency setting at 8 hours - this will give you an email report every day on if any new devices popped up. 
 
 ### Troubleshooting
 
 Scanning the wrong interface: Uncomment and change the 'interface: en0' line in arpscan.yaml. Specify the interface that you want to monitor.
 
 Not receiving any email: ensure 'enabled: true' is specified and of course your email settings are correct
 
