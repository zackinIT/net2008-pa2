import yaml

import xml.etree.ElementTree as ET

tree = ET.parse("PA2_sample1.xml")
root = tree.getroot()

print(root.tag)
print(root.get("site"))

roles = {}

interfaces = {
    "up": 0,
    "down": 0,
    "other": 0
}

total_devices = 0
skipped_devices=0


for device in root.findall("device"): #searching whole root 
 
    if (device.get("id")) is None: #if the device doesnt have an id skip it 
        skipped_devices+=1
        
    else:
       role =device.get("role")
       if role in roles:
           roles[role]+=1
           
           
       
       else:
        roles[role]= 1
       # id = device.get("id")
       
       # print(f'Role:{role}\nid: {id}\n')
       for interface in device.findall("interface"):
         status= interface.get("status")
       
         if status in ("up", "down"):
             interfaces[status] +=1
         else:
             interfaces["other"]+=1

        
            
       
       id = device.get("id")
       print(f'Role:{role}\nid: {id}\n')
       total_devices+=1
       
              
        
 
print(total_devices)
print(skipped_devices)
print(roles)
print (interfaces)