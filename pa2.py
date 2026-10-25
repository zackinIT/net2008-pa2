import yaml
import json

import xml.etree.ElementTree as ET

tree = ET.parse("PA2_sample1.xml")
root = tree.getroot()

print(root.tag)
print(root.get("site"))

#empty lists/dicts
roles = {}
ids = []
violations =[]

#dict for status
interfaces = {
    "up": 0,
    "down": 0,
    "other": 0
}

#counters for loops
total_devices = 0
skipped_devices=0

#reading/storing the yaml policy
with open("PA2_policy.yaml", "r") as f:
   policy =yaml.safe_load(f)  


for device in root.findall("device"): #searching the whole root 
 
    if (device.get("id")) is None: #skiping devices without an id, increment count
        skipped_devices+=1
        
    else:
       role =device.get("role")
       if role in roles:
           roles[role]+=1
       else:
        roles[role]= 1

       
      
       for interface in device.findall("interface"): 
        #check every interfaces status in the device
         if interface.get("status") in ("up", "down"):
             interfaces[interface.get("status")] += 1 #incerment the status its in
         else: 
             interfaces["other"]+=1
       
       id = device.get("id")
       ids.append(id)
       print(f'Role:{role}\nid: {id}\n')
       total_devices+=1

       #policy 
       if policy.get("require_owner", False): #checks wheater the polciy requres an owner
        owner= device.findtext("owner") #returns none if doesnt exit
        
        if owner is None:
         violations.append({"device": device.get("id"), "type": "missing_owner"})
        
        

#report dict

report = {
 "site": (root.get("site")),
 "total_devices": total_devices,
"skipped_devices":skipped_devices,
"roles": roles,
"interfaces": interfaces,
"violations": violations,
"compliant": sorted(ids) # for now, sorted puts it in alpha order

}
#writng the python report dict into audit.json file    
with open("audit.json", "w") as f:
   json.dump(report, f, indent=2)    
 
print(total_devices)
print(skipped_devices)
print(roles)
print (interfaces)
print(ids)
print(policy)
print (violations)