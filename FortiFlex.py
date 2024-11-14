import sys
import json
import urllib3
import requests
import yaml
from fortiosapi import FortiOSAPI
from fortiosapi.exceptions import NotLogged
import os
import re
from tqdm import tqdm
from datetime import datetime
import logging
import time
from requests.auth import HTTPBasicAuth
from requests.exceptions import ConnectTimeout
from base64 import b64encode
# Disable warnings about unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Set logging level to ERROR
logging.basicConfig(level=logging.ERROR)


class Fortigate:
    def __init__(self, info):
        self.info_params = self.info_file(info)
        self.host = self.info_params['host']
        self.username = self.info_params['username']
        self.local_username = self.info_params["local_username"]
        self.password = self.info_params['password']
        self.api_key = self.info_params['api_key']
        self.api = FortiOSAPI()

    def info_file(self, file_path):
        with open(f'yaml/{file_path}', 'r') as file:
            info_params = yaml.safe_load(file)
        return info_params
    
    def login(self,set_info_file):
        with open(f'yaml/{set_info_file}', 'r') as set_file:
            dst_info = yaml.safe_load(set_file)
        session = requests.Session()
        session.verify = False  # Disable SSL verification
        self.api._session = session
        try:
            login = self.api.tokenlogin(host=self.host, apitoken=self.api_key, verify=False, vdom="root")
        except NotLogged:
            print("Wrong API key on the destination device. Please check.")
            sys.exit(1)
        except ConnectTimeout:
            print("Timeout. Please ensure that your fortigate device is accessible via this method.")
            sys.exit(1)
        else:
            okmsg = "Connected to destination Fortigate device."
            return okmsg
   
    def user_login(self,set_info_file):
        with open(f'yaml/{set_info_file}', 'r') as set_file:
            dst_info = yaml.safe_load(set_file)
        session = requests.Session()
        session.verify = False  # Disable SSL verification
        self.api._session = session
        try:
            login = self.api.login(host=self.host, username=self.local_username, password=self.password, verify=False,vdom="root")
        except NotLogged:
            print("Wrong user credentials on the destination device. Please check.")
            sys.exit(1)
        except ConnectTimeout:
            print("Timeout. Please ensure that your fortigate device is accessible via this method.")
            sys.exit(1)
        else:
            okmsg = "Connected to destination Fortigate device."
            return okmsg

    def logout(self):
        # Logout from the api device
        self.api.logout()

    def print_config_sections(self):
        counter = 0
        section_list = []
        print("\nFound the below configuration sections in the file:")
        with open('sections/sections.txt', 'r') as f:
            for line in f:
                    counter += 1
                    section_name = line.strip()
                    print(f"\n{counter} - {section_name}")
                    section_list.append(section_name)
        return section_list

    def get_config(self,**kwargs):    
        section_name = kwargs.get("section_name")
        migration_flag = kwargs.get("migration_flag")    
        vdom = kwargs.get("vdom")
        functionality = kwargs.get("functionality")
        path, name = section_name.split(' ')
        parameters =  'with_meta=false&skip=true&exclude-default-values=true&plain-text-password=1&datasource=true&with_meta=true&skip=true'  
        if vdom=="global":
            vdom=""
        config = self.api.get(path=path, name=name,parameters=parameters,vdom=vdom).get('results', [])
        section_name_underscore = section_name.replace(' ', '_')
        output_filename = section_name_underscore + "_" + "config.json"
        #Checks the migration flag
        if migration_flag == False:
            #Make it a list if it is not
            if isinstance(config, list):
                pass
            else:
                config = [config]
            if functionality == 1:
                save = input("Do you want to save the configuration section from the fortigate?(y-> YES / n-> NO): ")
            else:
                save = input("Do you want to save the configuration section from the source fortigate?(y-> YES / n-> NO): ")
            while True:
                if save=='y':
                    with open(output_filename, 'w') as json_file:
                        json.dump(config, json_file, indent=4)
                    print(f"\nJSON configuration for the whole section is saved as {output_filename}")
                    while True:
                        answer =input("\nDo you see the indivindual objects?(y-> YES / n-> NO): ")
                        if answer=='y':
                            self.get_object_config(output_filename,section_name)
                            break
                        if answer=='n':
                            break
                        else:
                            print("\nInvalid option.")
                            break
                    break
                if save=='n':
                    break
                else:
                    print("\nInvalid option.")
                    break
        if migration_flag == True:
            output = self.config_filtering(path,name,config,output_filename)
            return output  
    #THE BELOW FUNCTION IS USED FOR THE REFERENCES CHECK
    def fetch_configuration(self,path, name, mkey, vdom):
        parameters ='with_meta=false&skip=true&exclude-default-values=true&plain-text-password=1&datasource=true&with_meta=true&skip=true'
        #parameters =  'with_meta=false&skip=true&exclude-default-values=true&datasource=true' 
        config = self.api.get(path=path, name=name, parameters=parameters, vdom=vdom, mkey=mkey).get('results', [])
        snmp_index = "snmp-index"
        devindex = "devindex"
        uuid = "uuid"
        macaddr = "macaddr"
        monitor_bandwidth ="monitor-bandwidth"
        seed = "seed"
        id = "id"
        fortitoken = "fortitoken"
        two_factor = "two-factor"
        password = "password"
        for item in config:
            try:
                if snmp_index in item:
                    item.pop(snmp_index)
                if devindex in item:
                    item.pop(devindex)
                if uuid in item:
                        item.pop(uuid)
                if macaddr in item:
                    item.pop(macaddr)
                if monitor_bandwidth in item:
                    item.pop(monitor_bandwidth)    
                #For fortitokens
                if seed in item:
                    item.pop(seed)     
            except AttributeError:
                pass
        if path=="user" and name=="local":
            for item in config:
                try:
                    if id in item:
                        item.pop(id)
                    if fortitoken in item:
                        item.pop(fortitoken)
                    if two_factor in item:
                        item.pop(two_factor)  
                    if "passwd" in item:
                        item["passwd"]="randompassword"
                except AttributeError:
                    pass 
        if path=="user" and name=="ldap":
            for item in config:
                try:
                    if "password" in item:
                        item["password"]="randompassword"
                except AttributeError:
                    pass 
        if path=="system" and name=="sdwan":
                for service in config["service"]:
                    if "mode" in service:
                        service.pop("mode")
                        service["load-balance"]="enable"
        if path=="system" and name=="admin":
        #You can create a new admin but you can not change the password of the system admin. You can only change the other parameters of the system admin
                if password in item:
                    item.pop(password) 
        if path=="system" and name=="settings":
                try:   
                    config["gui-sslvpn"]="enable"  
                except AttributeError:
                    pass     

        return config

    def config_filtering(self,path,name,config,output_filename):
        # Below values are being popped because fortigate api cannot pass them.
        snmp_index = "snmp-index"
        devindex = "devindex"
        uuid = "uuid"
        macaddr = "macaddr"
        seed="seed"
        id="id"
        fortitoken = "fortitoken"
        two_factor = "two-factor"
        password = "password"
        for item in config:
            try:
                if snmp_index in item:
                    item.pop(snmp_index)
                if devindex in item:
                    item.pop(devindex)
                if uuid in item:
                        item.pop(uuid)
                if macaddr in item:
                    item.pop(macaddr)
                #For fortitokens
                if seed in item:
                    item.pop(seed)
            except AttributeError:
                pass
        
        if path=="system" and name=="settings":
        #Enable ssl-vpn setting
                try:   
                    config["gui-sslvpn"]="enable"  
                except AttributeError:
                    pass        
        if path=="user" and name=="local":
            #Fortigate api cannot handle id, fortitokens and two factor config
            for item in config:
                try:
                    if id in item:
                        item.pop(id)
                    if fortitoken in item:
                        item.pop(fortitoken)
                    if two_factor in item:
                        item.pop(two_factor)
                    if "passwd" in item:
                        item["passwd"]="randompassword"
                except AttributeError:
                    pass 
        if path=="user" and name=="ldap":
            #Forti cannot transfer passwords as appearing as ENC XXXX, so we modify the value
            for item in config:
                try:
                    if "password" in item:
                        item["password"]="randompassword"
                except AttributeError:
                    pass 
        if path=="system" and name=="admin":
        #You can create a new admin but you can not change the password of the system admin. You can only change the other parameters of the system admin
                if password in item:
                    item.pop(password)        
        if path=="system" and name=="sdwan":
        ##FORTI 200F DOES NOT HAVE THE mode load-balance parameter, it has it as a seperate config
            if "service" in config:
                for service in config["service"]:
                    if "mode" in service:
                        service.pop("mode")
                        service["load-balance"]="enable"
        if path == "system" and name == "interface":
            filtered_data = [item for item in config
                                if item.get('name') != "mgmt"]  ##Filter mgmt interface
            sorted_json_object = sorted(filtered_data, key=lambda x: (
                    x.get('type') != 'physical',        # Physical interfaces first
                    x.get('type') != 'aggregate',       # Aggregate interfaces next
                    'vlanid' not in x,                  # VLAN interfaces with 'vlanid' key
                    x.get('type') != 'wifi',            # WiFi interfaces
                    x.get('type') != 'tunnel',          # Tunnel interfaces
                    x.get('type') != 'virtual-wire',    # Virtual Wire interfaces
                    x.get('type') != 'loopback',        # Loopback interfaces
                    x.get('type') != 'sd-wan',          # SD-WAN interfaces
                    x.get('type') or ''                 # Alphabetical order if types are the same
        ))
            with open(output_filename, 'w') as json_file:
                json.dump(sorted_json_object, json_file, indent=4) 
            return output_filename   
        else:
            #Make it a list if it is not
            if isinstance(config, list):
                pass
            else:
                config = [config]
            with open(output_filename, 'w') as json_file:
                    json.dump(config, json_file, indent=4)
            return output_filename
    #THE BELOW FUNCTION IS NOT USED ANYWHERE - TESTING -
    def interface_filtering(self,filtered_data,vdoms,section_name):   
        json_object = filtered_data 
        mgmt_name = "mgmt"
        interface_types_all = [obj.get('type') for obj in json_object if 'type' in obj]  
        interface_types = list(set(interface_types_all))
        filterings ={
                        "vdom":vdoms,
                        "type": interface_types,
                        "vlanid": True,
                        }
    ##--Filter out root VDOM for interface types--##
        '''
        for vdom_value in filterings["vdom"]:
                    for type_value in filterings["type"]:
                        filtered_filename = f"{output_filename}_vdom_{vdom_value}_type_{type_value}.json"
                        filtered_data = [item for item in json_object
                                              if item.get('vdom') == vdom_value
                                              and item.get('type') == type_value
                                              and item.get('name') != mgmt_name]  ##Filter mgmt interface    
                        if filtered_data:
                            with open(filtered_filename, 'w') as json_file:
                                json.dump(filtered_data, json_file, indent=4)                                  
                        print(f"\nFiltered VDOM '{vdom_value}' and interface type '{type_value}' configuration is saved as {filtered_filename}")
    ##--Filter data for objects that have a 'vlanid' key--##
        for vdom_value in filterings["vdom"]:
            if filterings["vlanid"]:
                filtered_filename = f"{output_filename}_vdom_{vdom_value}_vlans.json"
                filtered_data = [item for item in json_object if item.get('vdom') == vdom_value and 'vlanid' in item]
                with open(filtered_filename, 'w') as json_file:
                    json.dump(filtered_data, json_file, indent=4)
                print(f"\nFiltered VDOM '{vdom_value}' and interface type VLANS configuration is saved as {filtered_filename}")
        '''
        
        sorted_json_object = sorted(json_object, key=lambda x: (
                x.get('type') != 'physical',        # Physical interfaces first
                x.get('type') != 'aggregate',       # Aggregate interfaces next
                'vlanid' not in x,                      # VLAN interfaces with 'vlanid' key
                x.get('type') != 'wifi',            # WiFi interfaces
                x.get('type') != 'tunnel',          # Tunnel interfaces
                x.get('type') != 'virtual-wire',    # Virtual Wire interfaces
                x.get('type') != 'loopback',        # Loopback interfaces
                x.get('type') != 'sd-wan',          # SD-WAN interfaces
                x.get('type') or ''                  # Alphabetical order if types are the same
    ))
    
        # Save the sorted list back to a new JSON file
        sorted_output_filename = "system_interface_config.json"
        with open(sorted_output_filename, 'w') as sorted_file:
            json.dump(sorted_json_object, sorted_file, indent=4)
        print(f"\nThe sorted JSON objects have been saved as {sorted_output_filename}")

        while True:
            answer =input("\nDo you see the indivindual objects?(y-> YES / n-> NO)")
            if answer=='y':
                self.get_object_config(sorted_output_filename,section_name)
                break
            if answer=='n':
                break
            else:
                print("\nDo you want to exit?(y-> YES / n-> NO)")
        return 0        

    def get_object_config(self,output_filename,section_name):
        with open(output_filename, 'r') as objects:
            json_object = json.load(objects)
        ##--Extract the "name" value and add it to the list--#
        section_length = [obj.get('name') for obj in json_object ]
        print("\n\n below are the objects of the section: \n\n")
        for index, name in enumerate(section_length, start=1):
            print(f"{index} - {name}")
        while True:
            try:
                select_object = int(input("\nEnter the index of the configuration you want to save(Or press 0 to exit): "))
                if select_object == 0:
                    print("\n")
                    break
                if 1 <= select_object <= len(section_length):
                    selected_config = json_object[select_object - 1]  # Adjust index to zero-based
                    config = [selected_config]
                    if "name" in selected_config:
                        selected_name = selected_config['name']
                    #if "policyid" in selected_config:
                        #selected_name = selected_config['policyid']
                    selected_filename = f"{section_name}_{selected_name}_config.json"
                    with open(selected_filename, 'w') as selected_file:
                        json.dump(config, selected_file, indent=4)
                    print(f"\nSelected configuration '{selected_name}' saved to {selected_filename}")
                else:
                    print("\nInvalid selection. Please choose a valid index.")
            except ValueError:
                print("\nInvalid input. Please enter a valid index number.")

    def logout(self):
        self.api.logout()

    def get_vdoms(self):
        def sort(lst,first):
            return sorted(lst, key=lambda x: (x != first, x))
        parameters =  'with_meta=false&skip=true&exclude-default-values=true'              
        config = self.api.get(path="system", name="vdom", vdom='root',parameters=parameters).get('results', [])
        vdom_names = [obj.get('name') for obj in config if 'name' in obj]
        start = "root"
        sorted_list = sort(vdom_names, start)
        return sorted_list

    def create_object(self, json_filename, section_name):
        success_log_file ="success_log.txt"
        fail_log_file = "fail_log.txt"
        while True:
            update = input("\n\nObject Already exists. Do you want to update the configuration?(y-> YES / n-> NO): ")
            if update=='y':
                    self.update_object(json_filename, section_name)
                    break
            if update=='n':
                    break
        with open(json_filename, 'r') as json_file:
            config_data = json.load(json_file)
        path, name = section_name.split(' ', 1)
        vdom=input("Vdom to apply the configuration: ")
        for obj in config_data:
            mkey = self.api.get_mkey(path=path, name=name, data=obj)
            if vdom=="global":
                response = self.api.post(path=path, name=name, data=obj, mkey=mkey)
                self.config_logging(obj,response,success_log_file, fail_log_file)
            else:
                response = self.api.post(path=path, name=name, data=obj, mkey=mkey,vdom=vdom)
                self.config_logging(obj,response,success_log_file, fail_log_file)
            if 'error' in response:
                if response['status']=='success':
                    print("\n\nObject Created.")
                if response['error'] == -5:
                    while True:
                        update = input("\n\nObject Already exists. Do you want to update the configuration?(y-> YES / n-> NO): ")
                        if update=='y':
                            self.update_object(json_filename, section_name)
                            break
                        if update=='n':
                            break
            else:
                    print(response)   
            return 0

    def update_object(self, json_filename, section_name):
        success_log_file ="success_log.txt"
        fail_log_file = "fail_log.txt"
        with open(json_filename, 'r') as json_file:
            config_data = json.load(json_file)
        
        path, name = section_name.split(' ', 1)
        vdom=input("Vdom to apply the configuration: ")
        for obj in config_data:
            print(type(obj))
            mkey = self.api.get_mkey(path=path, name=name, data=obj)
            if vdom=="global":
                print("global VDOM")
                response = self.api.put(path=path, name=name, data=obj, mkey=mkey)
                self.config_logging(obj,response,success_log_file, fail_log_file)
            else:
                response = self.api.put(path=path, name=name, data=obj, mkey=mkey,vdom=vdom)
                self.config_logging(obj,response,success_log_file, fail_log_file)
            if response['status']=='success':
                print("\n\nObject updated.\n\n")
            else:
                print(response)

    def force_object_apply(self, config, section_name):
        phase=""
        success_log_file ="success_log.txt"
        fail_log_file = "fail_log.txt"
        with open(config, 'r') as json_file:
            config_data = json.load(json_file)
        path, name = section_name.split(' ', 1)
        vdom=input("Vdom to apply the configuration: ")
        for obj in config_data:
            mkey = self.api.get_mkey(path=path, name=name, data=obj)
            if vdom=="global":
                response = self.api.set(path=path, name=name, data=obj,mkey=mkey)
                self.config_logging(obj,response,success_log_file, fail_log_file)
            else:
                response = self.api.set(path=path, name=name, data=obj,vdom=vdom,mkey=mkey)
                self.config_logging(obj,response,success_log_file, fail_log_file)  

            if path=="system" and name=="sdwan":    
                status_zone = [
                    {
                    "status": obj["status"], 
                    "zone": obj["zone"],
                    "members": obj["members"]
                    }
                            ]
                
                with open(f'sdwan.json', 'w') as json_file:
                        json.dump(status_zone, json_file, indent=4)
                            
                with open(f'sdwan.json', 'r') as json_file:
                            config_data = json.load(json_file)  

                response = self.api.put(path=path, name=name, data=config_data, mkey=mkey, vdom=vdom)
                self.logging(status_zone, response, success_log_file, fail_log_file, section_name, phase, vdom)
                optional_keys = ["health-check", "service"]
                for key in optional_keys:
                    if key in obj:
                        status_zone[0][key] = obj[key]
                        with open(f'sdwan_{key}.json', 'w') as json_file:
                            json.dump(status_zone, json_file, indent=4)

                        with open(f'sdwan_{key}.json', 'r') as json_file:
                            config_data = json.load(json_file)                        
                        response = self.api.put(path=path, name=name, data=config_data, mkey=mkey, vdom=vdom)
                        self.logging(status_zone, response, success_log_file, fail_log_file, section_name, phase, vdom)
                                      
    def delete_object(self,json_filename, section_name):
        with open(json_filename, 'r') as file:
            data = json.load(file)
        path,name=section_name.split(" ")
        vdoms = self.get_vdoms()
        num=1
        for vdom_ in vdoms:
            print(f'{num} - {vdom_}')
            num+=1  
        vdom = None 
        while vdom is None:
            try:
                vdom = int(input("Please select a vdom for this configuration section (or '0' to quit): "))
                if vdom == 0:
                    print("\n")
                    break
                if (vdom<1) or (vdom>len(vdoms)):
                    print("Invalid section number.")
                    vdom = None
            except TypeError:
                print("Please select a valid option.")  
            else:
                print(f"Selected vdom: {vdoms[int(vdom)-1]}")
                vdom = vdoms[int(vdom)-1]
                for obj in data:
                    mkey = self.api.get_mkey(path=path, name=name, data=obj)
                    try:
                        response = self.api.delete(path=path, name=name, data=obj, mkey=mkey,vdom=vdom)
                        if response['status']=='success':
                            print("\n\nObject deleted.\n")
                        elif 'Try to put on' in response.get('message', ''):
                            continue
                        else:
                            print("Could not delete the object.")
                    except EOFError:
                        exit()
                    except:
                        print("Error occurred.")

    def vdom_functionality(self,info_file,functionality): 
        try:         
            while True:
                if functionality==1:
                    with open(f'yaml/{info_file}', 'r') as file:
                        info = yaml.safe_load(file)  
                    print("This function enables or disables the multi-vdom functionality. Proceed with caution.")
                    check_vdom = self.api.get(path="system", name="global").get('results', [])
                    if check_vdom["vdom-mode"]=="multi-vdom":
                        print("Multi VDOM already enabled.") 
                        check=1
                    else:
                        print("Multi-VDOM is not enabled.")  
                        check=0
                    if check==0:                 
                        answer =input(f"\nEnable the multi-VDOM function on Fortigate device({info["host"]}? (e-> Enable q->Quit): ")
                        if answer=='e':
                            url = f'https://{info["host"]}/api/v2/monitor/system/admin/change-vdom-mode'
                            params = {
                                "vdom-mode": "multi-vdom"
                                        }
                            headers = {
                                "Authorization": f"Bearer {info["api_key"]}"
                                    }
                            response = self.api._session.post(url=url, headers=headers, params=params, verify=False)
                            print("Action Completed. The results may have not taken effect.")
                            break
                        if answer=="q":
                            break  
                    if check==1:
                        answer =input(f"Disable the multi-VDOM function on Fortigate device({info["host"]}? (d-> Disable q->Quit): ")
                        if answer=='d':
                            url = f'https://{info["host"]}/api/v2/monitor/system/admin/change-vdom-mode'
                            params = {
                                "vdom-mode": "no-vdom"
                                        }
                            headers = {
                                "Authorization": f"Bearer {info["api_key"]}"
                                    }
                            response = self.api._session.post(url=url, headers=headers, params=params, verify=False)
                            print("Action Completed. The results may have not taken effect.")
                            break
                        if answer=="q":
                            break
                        else:
                            print("\nInvalid choice.")   
                else:
                    print("This is only available when one fortigate device has been selected.\n")
                    break
        except EOFError:
            exit()

    def enable_vdom_functionality(self,set_info_file):
        check_vdom = self.api.get(path="system", name="global").get('results', [])
        if check_vdom["vdom-mode"]=="multi-vdom":
            print("Multi VDOM already enabled.")
        else:
            print("Enabling Multi VDOM functionality.")

            with open(f'yaml/{set_info_file}', 'r') as set_file:
                dst_info = yaml.safe_load(set_file)
                url = f'https://{self.host}/api/v2/monitor/system/admin/change-vdom-mode'
                params = {
                        "vdom-mode": "multi-vdom"
                        }
                headers = {
                        "Authorization": f"Bearer {dst_info["api_key"]}"
                        }
                
                response = self.api._session.post(url=url, headers=headers, params=params, verify=False)

    def rename_interface_alias(self):
        parameters = 'with_meta=false&skip=true&exclude-default-values=true'
        interfaces = self.api.get(path="system", name="interface", parameters=parameters).get('results', [])
        snmp_index = "snmp-index"
        devindex = "devindex"
        uuid = "uuid"
        for item in interfaces:
            try:
                if snmp_index in item:
                    item.pop(snmp_index)
                if devindex in item:
                    item.pop(devindex)
                if uuid in item:
                    item.pop(uuid)
            except AttributeError:
                pass
        # Display the interfaces
        interface_names_list = [obj.get('name') for obj in interfaces if 'name' in obj]
        print("\n\nBelow are the interfaces of the device:\n\n")
        for index, name in enumerate(interface_names_list, start=1):
            print(f"{index} - {name}")
        while True:
            try:
                selected_interface = int(input("\nEnter the index of the interface you want to change the name (Or press 0 to exit): "))
                if selected_interface == 0:
                    print("\n")
                    break
                if 1 <= selected_interface <= len(interface_names_list):
                    selected_interface_config = interfaces[selected_interface - 1]  # Adjust index to zero-based
                    selected_interface_name_value = selected_interface_config['name']
                    new_interface_name = input(f"Enter the new name for the interface '{selected_interface_name_value}': ")
                    if 'alias' in selected_interface_config:
                        selected_interface_config['alias'] = new_interface_name
                    else:
                        selected_interface_config['alias'] = new_interface_name
                    with open("temp_file", 'w') as json_file:
                        json.dump([selected_interface_config], json_file, indent=4)
                    self.update_object("temp_file", section_name="system interface")   
                        # Delete the temporary file
                    os.remove("temp_file")
                    print(f"\nInterface '{selected_interface_name_value}' has been renamed to '{new_interface_name}'.\n")
                else:
                    print("\nInvalid selection. Please choose a valid index.")
            except ValueError:
                print("\nInvalid input. Please enter a valid index number.")
        return 0

    def migration_file(self,phase,vdom,fail_directory_path):
        section_list = []
        if phase==1:
            with open('sections/migration_sections.txt', 'r') as f:
                for line in f:
                    section_name = line.strip()
                    section_list.append(section_name)                 
                return section_list 
        else:
            if os.path.exists(f'{fail_directory_path}/phase_{phase-1}_failed_logs/failed_sections_vdom_{vdom}_phase_{phase-1}.txt'):
                    with open(f'{fail_directory_path}/phase_{phase-1}_failed_logs/failed_sections_vdom_{vdom}_phase_{phase-1}.txt', 'r') as f:
                        for line in f:
                            section_name = line.strip()
                            section_list.append(section_name)                 
                        return section_list
            else:
                    return section_list          

    def migrate(self,info_file,set_info_file):
        try:
            src_info , dst_info = self.host_info(info_file,set_info_file)
            vdom_instances = self.get_vdoms()
            multi_vdom = False # Flag for multivdom
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            #Generating parent folder
            parent_directory = f'Migration_{timestamp}'
            if not os.path.exists(parent_directory):
                os.makedirs(parent_directory)
            if len(vdom_instances)>1: #If vdoms > 1, multi vdom flag enabled
                multi_vdom = True
                for i in range(1,3): # making 2 rounds of passing sections
                    for vdom_instance in vdom_instances:
                        if vdom_instance=="root":
                            vdom_instance=""
                        success_log,failed_log,fail_directory_path,vdom_failed_sections = self.create_files_and_directories(i,vdom_instance,parent_directory)
                        section_list = self.migration_file(i,vdom_instance,fail_directory_path)
                        temp_vdom=vdom_instance
                        if vdom_instance=="":
                            print (f'\n\nMigrating from {src_info["host"]} to {dst_info["host"]}, root vdom...\n')
                        else:
                            print (f'\n\nMigrating from {src_info["host"]} to {dst_info["host"]}, {vdom_instance} vdom...\n')
                        total_sections = len(section_list)
                        progress_bar = tqdm(total=total_sections, position=0, leave=True)
                        for section in section_list:
                            split_section = section.split(' ', 1)
                            if len(split_section) == 2:
                                path = split_section[0]
                                name = split_section[1]
                            progress_bar.set_description(f'Migrating section: {path} {name}')
                            config = self.get_config(section_name=section, vdom=vdom_instance,migration_flag=True)
                            section_total_objects = len(config)
                            section_progress_bar = tqdm(total=section_total_objects, desc=f'Section: {path} {name}', position=1, leave=True)
                            with open(config, 'r') as json_file:
                                config_data = json.load(json_file)       
                            for obj in config_data:
                                if path=="system" and name=="sdwan":
                                    if "members" in obj:
                                        status_zone = [
                                            {
                                            "status": obj["status"], 
                                            "zone": obj["zone"],
                                            "members": obj["members"]
                                            }
                                                    ]           
                                        with open(f'sdwan.json', 'w') as json_file:
                                                json.dump(status_zone, json_file, indent=4)                  
                                        with open(f'sdwan.json', 'r') as json_file:
                                                    config_data = json.load(json_file)  
                                        response = self.api.put(path=path, name=name, data=config_data, mkey=mkey, vdom=vdom_instance)
                                        self.migrate_logging(obj,response,success_log,failed_log,section,vdom_failed_sections)
                                        optional_keys = ["health-check", "service"]
                                        for key in optional_keys:
                                            if key in obj:
                                                status_zone[0][key] = obj[key]
                                                with open(f'sdwan_{key}.json', 'w') as json_file:
                                                    json.dump(status_zone, json_file, indent=4)
                                                with open(f'sdwan_{key}.json', 'r') as json_file:
                                                    config_data = json.load(json_file)                        
                                                response = self.api.put(path=path, name=name, data=config_data, mkey=mkey, vdom=vdom_instance)
                                                self.migrate_logging(obj,response,success_log,failed_log,section,vdom_failed_sections)
                                if vdom_instance=="":
                                    mkey = self.api.get_mkey(path=path, name=name, data=obj)                 
                                    response = self.api.set(path=path, name=name, data=obj, mkey=mkey)
                                    self.migrate_logging(obj,response,success_log,failed_log,section,vdom_failed_sections)
                                else:
                                    if path=="system" and (name=="vdom" or name=="vdom-link" or name=="vdom-property" or name=="vdom-radius-server" or name=="vdom-exception" or name=="vdom-link"):
                                        vdom_instance="root"
                                    mkey = self.api.get_mkey(path=path, name=name, data=obj,vdom=vdom_instance)                 
                                    response = self.api.set(path=path, name=name, data=obj, mkey=mkey,vdom=vdom_instance)
                                    self.migrate_logging(obj,response,success_log,failed_log,section,vdom_failed_sections)
                                    vdom_instance=temp_vdom
                                section_progress_bar.update(1)
                            section_progress_bar.close()
                            progress_bar.update(1)
                            os.remove(config) 

                            '''
                            with open(f'completed_sections_{vdom_instance}.txt', 'a') as sections:
                                    sections.write(section)
                                    sections.write('\n')
                                '''
                        if multi_vdom:
                            print("\nChecking multi-vdom, please wait..\n")
                            self.enable_vdom_functionality(set_info_file)
                            time.sleep(5)
                            print("Multi-vdom enabled.\n\n") 
                            multi_vdom = False                
                progress_bar.close()
        except PermissionError:
            with open("Permission_denied.txt", 'a') as output:
                output.write(f'{section} - Object: ')
                json.dump(obj, output)
                output.write('\n\n')
        except TypeError:
            with open("Type_error.txt", 'a') as output:
                output.write(f'{section} - Object: ')
                json.dump(obj, output)
                output.write('\n\n')
        return 0

    def host_info(self,info_file,set_info_file):
        with open(f'yaml/{info_file}', 'r') as get_file:
            src_info = yaml.safe_load(get_file)
        with open(f'yaml/{set_info_file}', 'r') as set_file:
            dst_info = yaml.safe_load(set_file)   
        return src_info, dst_info

    def create_files_and_directories(self,phase,vdom_instance,parent_directory):

        # Generating success logs directory under parent folder     
        success_directory = 'success_logs'
        if not os.path.exists(f'{parent_directory}/{success_directory}'):
            os.makedirs(f'{parent_directory}/{success_directory}')
        # Generating success phases under success directory folder 
        phase_success_directory = f'phase_{phase}_success_logs'
        if not os.path.exists(f'{parent_directory}/{success_directory}/{phase_success_directory}'):
            os.makedirs(f'{parent_directory}/{success_directory}/{phase_success_directory}') 
        #Generating success logs under phase success folder       
        success_log_file = f"log_success_vdom_{vdom_instance}_stage_{phase}.txt"
        success_log =  os.path.join(parent_directory,success_directory, phase_success_directory,success_log_file)
        # Generating failed logs directory under parent folder
        fail_directory = 'failed_logs'
        if not os.path.exists(f'{parent_directory}/{fail_directory}'):
            os.makedirs(f'{parent_directory}/{fail_directory}')
        fail_directory_path = os.path.join(parent_directory,fail_directory)

        # Generating fail phases under success directory folder
        phase_failed_directory = f'phase_{phase}_failed_logs'
        if not os.path.exists(f'{parent_directory}/{fail_directory}/{phase_failed_directory}'):
            os.makedirs(f'{parent_directory}/{fail_directory}/{phase_failed_directory}')
        #Generating fail logs under phase success folder
        fail_log_file = f"log_failed_vdom_{vdom_instance}_stage_{phase}.txt"    
        failed_log = os.path.join(parent_directory,fail_directory, phase_failed_directory,fail_log_file)
        # Generating failed phases under failed phases directory folder
        vdom_failed_log = f'failed_sections_vdom_{vdom_instance}_phase_{phase}.txt'
        vdom_failed_sections =  os.path.join(parent_directory,fail_directory, phase_failed_directory,vdom_failed_log)      
   
        return success_log,failed_log,fail_directory_path,vdom_failed_sections
    
    def migrate_logging(self,obj,response,success_log_file,fail_log_file,section,vdom_failed_sections):
        with open("errors/error_codes.json", 'r') as file:
            error_codes = json.load(file)
        try:
            if 'status' in response:           
                if response.get('status') == 'success':
                    #Writing logs
                    with open(success_log_file, 'a') as success_output:
                        success_output.write(f'{section} - Object: ')
                        json.dump(obj, success_output)
                        success_output.write('\nResponse: ')
                        json.dump(response['status'], success_output)
                        success_output.write('\n\n')
                elif response.get('status') == 'error':      
                    if "error" in response:
                        #pass objects that already exists
                        if response.get('error')==-5:
                            error_code = str(response.get('error'))
                            error_message = error_codes.get(error_code, 'Unknown error code')
                            with open("already_exists.txt", 'a') as output:
                                output.write(f'{section} - Object: ')
                                json.dump(obj, output)
                                output.write('\n')
                                if error_code in error_codes:
                                    output.write(f"Error {error_code}: {error_message}\n\n")
                                else:
                                    json.dump(response, output)
                                    output.write('\n\n')
                        else:
                            if os.path.exists(vdom_failed_sections):
                                with open(vdom_failed_sections, 'r') as input_file:
                                    existing_sections = input_file.readlines()
                            else:
                                existing_sections = []
                            if section + '\n' not in existing_sections:
                                with open(vdom_failed_sections, 'a') as output:
                                    output.write(section)
                                    output.write('\n') 
                            error_code = str(response.get('error'))
                            error_message = error_codes.get(error_code, 'Unknown error code')

                            #Writing logs
                            with open(fail_log_file, 'a') as fail_output:
                                fail_output.write(f'{section} - Object: ')
                                json.dump(obj, fail_output)
                                fail_output.write('\n')
                                if error_code in error_codes:
                                    fail_output.write(f"Error {error_code}: {error_message}\n\n")
                                else:
                                    json.dump(response, fail_output)
                                    fail_output.write('\n\n')
                    else:
                        #Writing logs
                        with open(fail_log_file, 'a') as fail_output:
                            fail_output.write(f'{section} - Object: ')
                            json.dump(obj, fail_output)  # Write the JSON object to the file
                            fail_output.write('\n')
                            fail_output.write('Response: ')
                            json.dump(response, fail_output)  # Write the JSON response to the file
                            fail_output.write('\n\n')                   
                else:
                    #Writing logs
                    with open(fail_log_file, 'a') as fail_output:
                        fail_output.write(f'{section} - Object: ')
                        json.dump(obj, fail_output)
                        fail_output.write('\n')
                        fail_output.write('\nResponse: ')                       
                        json.dump(obj, response)
                        fail_output.write('\n\n')
            else:
                #Writing logs
                with open(f'{fail_log_file}/unknown.txt', 'a') as output:
                    try:
                        response_content = response.json()
                        response_type = 'JSON'
                    except requests.exceptions.JSONDecodeError:
                        # If parsing fails, fall back to raw text
                        response_content = response.text
                        response_type = 'text'
                        # Write the response type
                        output.write(f'{section} - Object: ')
                        output.write(f'Response ({response_type}): ')
                    # Write the response content (use json.dump for JSON, otherwise write raw text)
                    if response_type == 'JSON':
                        json.dump(response_content, output)
                    else:
                        output.write(response_content)
                        output.write('\n\n')               
        except AttributeError:       
                #Writing logs      
                with open(fail_log_file, 'a') as fail_output:
                    fail_output.write(f'{section} - Attribute error. Object: ')
                    json.dump(obj, fail_output)
                    fail_output.write('\n')
                    fail_output.write('\nResponse: ')                    
                    json.dump(obj, response)
                    fail_output.write('\n\n')            

    def config_logging(self,obj,response,success_log_file,fail_log_file,config_directory):
        with open("errors/error_codes.json", 'r') as file:
            error_codes = json.load(file)
        try:
            if 'status' in response:           
                if response.get('status') == 'success':
                    #Writing logs
                    with open(f'{config_directory}/{success_log_file}', 'a') as success_output:
                        json.dump(obj, success_output)
                        success_output.write('\nResponse: ')
                        json.dump(response['status'], success_output)
                        success_output.write('\n\n')
                elif response.get('status') == 'error':      
                    if "error" in response:
                        #pass objects that already exists
                        if response.get('error')==-5:
                            error_code = str(response.get('error'))
                            error_message = error_codes.get(error_code, 'Unknown error code')
                            with open(f"{config_directory}/already_exists.txt", 'a') as output:
                                json.dump(obj, output)
                                output.write('\n')
                                if error_code in error_codes:
                                    output.write(f"Error {error_code}: {error_message}\n\n")
                                else:
                                    json.dump(response, output)
                                    output.write('\n\n')
                        else:
                            error_code = str(response.get('error'))
                            error_message = error_codes.get(error_code, 'Unknown error code')
                            #Writing logs
                            with open(f'{config_directory}/{fail_log_file}', 'a') as fail_output:
                                json.dump(obj, fail_output)
                                fail_output.write('\n')
                                if error_code in error_codes:
                                    fail_output.write(f"Error {error_code}: {error_message}\n\n")
                                else:
                                    json.dump(response, fail_output)
                                    fail_output.write('\n\n')
                    else:
                        #Writing logs
                        with open(f'{config_directory}/{fail_log_file}', 'a') as fail_output:
                            json.dump(obj, fail_output)  # Write the JSON object to the file
                            fail_output.write('\n')
                            fail_output.write('Response: ')
                            json.dump(response, fail_output)  # Write the JSON response to the file
                            fail_output.write('\n\n')                   
                else:
                    #Writing logs
                    with open(f'{config_directory}/{fail_log_file}', 'a') as fail_output:
                        json.dump(obj, fail_output)
                        fail_output.write('\n')
                        fail_output.write('\nResponse: ')                       
                        json.dump(obj, response)
                        fail_output.write('\n\n')
            else:
                #Writing logs
                with open(f'{config_directory}/{fail_log_file}/unknown.txt', 'a') as output:
                    try:
                        response_content = response.json()
                        response_type = 'JSON'
                    except requests.exceptions.JSONDecodeError:
                        # If parsing fails, fall back to raw text
                        response_content = response.text
                        response_type = 'text'
                        # Write the response type
                        output.write(f'Response ({response_type}): ')
                    # Write the response content (use json.dump for JSON, otherwise write raw text)
                    if response_type == 'JSON':
                        json.dump(response_content, output)
                    else:
                        output.write(response_content)
                        output.write('\n\n')               
        except AttributeError:       
                #Writing logs      
                with open(config_directory/fail_log_file, 'a') as fail_output:
                    json.dump(obj, fail_output)
                    fail_output.write('\n')
                    fail_output.write('\nResponse: ')                    
                    json.dump(obj, response)
                    fail_output.write('\n\n')            

    def check_references(self,data):
    #Open migration section files which has the right section format
        with open('sections/migration_sections.txt', 'r') as text_file:
            text_file_contents = text_file.read().splitlines() 
        reference_mapping = {}
        #Modify the file into a format without dots
        for line in text_file_contents:
            modified_line = line.replace(".", " ")
            reference_mapping[modified_line] = line

        references = []
        str_references = ""
        if isinstance(data, list):
            for obj in data:
                if isinstance(obj, dict):
                    q_origin_key = obj.get("q_origin_key")
                    if q_origin_key is not None:
                        pass
                    for key, value in obj.items():
                        if isinstance(value, list):
                            for item in value:
                                #datasource, the value which has the reference section
                                if isinstance(item, dict) and 'datasource' in item:
                                    datasource = item['datasource']
                                    #make it to the same format with the modified migration section
                                    modified_datasource = datasource.replace(".", " ")
                                    name = item.get('name', item.get('interface-name', 'N/A'))
                                    #if equal, take the original value of the migration section
                                    if modified_datasource in reference_mapping:
                                        original_datasource = reference_mapping[modified_datasource]
                                        references.append({original_datasource: name})
                                    str_references += f"Section: {modified_datasource} - Object: {name}\n"
                                    #same applies below
                        elif isinstance(value, dict):
                            if 'datasource' in value:
                                datasource = value['datasource']
                                modified_datasource = datasource.replace(".", " ")
                                name = value.get('name', value.get('interface-name', 'N/A'))
                                if modified_datasource in reference_mapping:
                                        original_datasource = reference_mapping[modified_datasource]
                                        references.append({original_datasource: name})
                                str_references += f"Section: {modified_datasource} - Object: {name}\n"
            if not references:         
                #print("Object has no references.")
                pass

        else:
            print("The JSON data is not a list.")
            #convert to a dict and again to list to remove duplicates
        references = list({frozenset(d.items()): d for d in references}.values())
        return references

    def send_configuration(self,path, name, mkey,configuration):
        config_directory = "results"
        success_log_file ="success_log.txt"
        fail_log_file = "fail_log.txt"
        if not os.path.exists(config_directory):
            os.makedirs(config_directory)
        for obj in configuration:
            response = self.api.post(path=path, name=name, data=obj, mkey=mkey)
            self.config_logging(obj,response,success_log_file, fail_log_file,config_directory)

    def process_references(self,initial_references, vdom,fortigate):
        for initial_reference in initial_references:
            #Take every value of the initial_references and split the appropriate values (path,name,mkey)
            for key, value in initial_reference.items():
                path, name = key.split(' ', 1)
                mkey = value 
                #flag where shows that the last reference
                flag = True
                child_references = [] 
                while flag:
                        #take the config of the initial referece, see if it has references
                        conf = self.fetch_configuration(path, name, mkey, vdom)
                        references= self.check_references(conf)
                        if references:       
                            #add the reference to a list
                            child_references.extend(references)   
                            #for every child reference to the same thing                                       
                        for ref in child_references:
                            for key, value in ref.items():
                                    path, name = key.split(' ', 1)
                                    mkey = value
                                    conf = self.fetch_configuration(path, name, mkey, vdom)
                                    references= self.check_references(conf)
                                    if references:
                                        child_references.extend(references)
                        #Remove duplicates
                        child_references = list({frozenset(d.items()): d for d in child_references}.values())
                        #after all references, add the initial reference
                        child_references.append(initial_reference)
                        #For all child references, fetch and send the configuration.
                        for ref in child_references:
                            for key, value in ref.items():
                                    path, name = key.split(' ', 1)
                                    mkey = value                                 
                                    conf = fortigate.fetch_configuration(path, name, mkey, vdom)
                                    if  'type' in conf[0] and 'interface' in conf[0]:
                                        if path=="system" and name=="interface" and conf[0]["type"]=="tunnel" and conf[0]["interface"]["datasource"]=="system.interface":       
                                                    path="vpn.ipsec"
                                                    name="phase1-interface"
                                                    conf = fortigate.fetch_configuration(path=path, name=name, vdom=vdom, mkey=mkey)
                                                    self.send_configuration(path, name,mkey,conf)
                                                    path="vpn.ipsec"
                                                    name="phase2-interface"
                                                    mkey=""
                                                    conf = fortigate.fetch_configuration(path=path, name=name, vdom=vdom, mkey=mkey)
                                                    for phase2 in conf:
                                                        if phase2["phase1name"]["name"] == value:
                                                            phase2_object = phase2.copy()
                                                            print(f'Object: {value} | config: {phase2_object}')
                                                            if isinstance(phase2_object, list):
                                                                pass
                                                            else:
                                                                phase2_object = [phase2_object]
                                                            self.send_configuration(path, name,mkey,phase2_object)
                                    else:
                                        self.send_configuration(path, name,mkey,conf)
                        #When over, flag changes to take the next initial reference value
                        flag = False                    

    def send_object(self,json_filename, section_name,fortigate):
        #The object you want to send
        with open(json_filename, 'r') as file:
            data = json.load(file)
        path,name=section_name.split(" ")
        vdoms = self.get_vdoms()
        num=1
        for vdom_ in vdoms:
            print(f'{num} - {vdom_}')
            num+=1  
        vdom = None 
        while vdom is None:
            try:
                vdom = int(input("Please select a vdom for this configuration section (or '0' to quit): "))
                if vdom == 0:
                    print("\n")
                    break
                if (vdom<1) or (vdom>len(vdoms)):
                    print("Invalid section number.")
                    vdom = None
            except EOFError:
                exit()
            else:
                print(f"Selected vdom: {vdoms[int(vdom)-1]}")
                vdom = vdoms[int(vdom)-1]
                print("Checking object dependencies..")
                initial_references = self.check_references(data)
                print(f'Dependencies completed. Processing..')
                self.process_references(initial_references, vdom,fortigate)
                print("Process completed. Copying Object. \n")
                for obj in data:
                    mkey = self.api.get_mkey(path=path, name=name, data=obj)
                    self.send_configuration(path,name,mkey,data)
                    print("Action completed. Please check the logs for further details.")
                break

    def download_config(self,fortigate_ip, vdom_to_download, access_token):
        url = f"https://{fortigate_ip}/api/v2/monitor/system/config/backup"
        output_file = (f"{vdom_to_download}_vdom_config.conf")
        if vdom_to_download=="global":
            params = {
            "scope": "global"
                    }
        else:
                params = {
            "vdom": vdom_to_download,
            "scope": "vdom"
                        } 
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        response = requests.get(url, headers=headers, params=params, verify=False)

        if response.status_code == 200:
            if 'Content-Disposition' in response.headers and 'attachment' in response.headers['Content-Disposition']:
                with open(output_file, 'wb') as file:
                    file.write(response.content)
                print(f"Configuration file for VDOM '{vdom_to_download}' has been downloaded successfully as '{output_file}'.")
            else:
                print("The response does not contain a valid file attachment.")
        else:
            print(f"Failed to download configuration file. Status code: {response.status_code}")
            print("Response:", response.text)

    def upload_config(self,file_path,fortigate_ip,vdom):
        with open(file_path, "rb") as file:
            file_content = b64encode(file.read()).decode()
            url = f'https://{fortigate_ip}/api/v2/monitor/system/config/restore'
            headers = {
                'Content-Type': 'application/json',  # Adjust content type if necessary
                    }
            if vdom =="global" or vdom=="Global":
                data={"source": "upload",
                "scope": "global",
                "file_content": file_content}
            else: 
                data={"source": "upload",
                "scope": "vdom",
                "vdom": vdom,
                "file_content": file_content}
        try:
            response = self.api._session.post(url=url, headers=headers, json=data)

        except requests.exceptions.RequestException as e:
                print(f"An error occurred: {e}")
        else:
            print("Upload Completed.")
            return 0
    
    def rename_interface(self):
        print("Warning! This requires the fortigate configuration file since it will modify it accordingly. Be sure to double check the results before upload it.")
        current_directory = os.getcwd()
        all_files = os.listdir(current_directory)
        config_files = [file for file in all_files if file.endswith('.conf')]
        print("\n\nFound the below fortigate configuration files. \n ")
        num=1
        for file in config_files:
            print(f'{num} - {file}')  
            num+=1
        json_filename = None
        while json_filename is None:
            try:
                json_filename = int(input("\n\nEnter the configuration file number to modify (or '0' to quit): "))
                if json_filename == 0:
                        print("\n")
                        break 
                if (json_filename) < 1 or (json_filename)>len(config_files):
                    print("Please select a valid option.")         
                    json_filename = None  
            except EOFError:
                exit()                                                  
            except:
                print("Invalid option.")
                json_filename = None        
            else:
                if json_filename is not None:
                    print(f"Selected file: {config_files[json_filename-1]}")
                    json_filename=config_files[json_filename-1]
                    while True:
                            found = False
                            old_interface_name = input("Please enter the old interface name: ")
                            config_name = f'edit "{old_interface_name}"'
                            with open(json_filename, "r") as file:
                                for line in file:
                                    if config_name in line or found==True:
                                        found = True
                                        print(line.strip())
                                        if "next" in line:
                                            break
                            if found == True:
                                is_right = input("Interface name found! Is the right interface?(y-> YES / n-> NO):")
                                if is_right == 'y':
                                    new_interface_name = input("Enter the new interface name: ")
                                    # Define regex patterns to match the exact interface contexts
                                    patterns = [
                                        r'(^\s*set interface\s+"{}"\s*$)'.format(re.escape(old_interface_name)),
                                        r'(^\s*set srcintf\s+"{}"\s*$)'.format(re.escape(old_interface_name)),
                                        r'(^\s*set dstintf\s+"{}"\s*$)'.format(re.escape(old_interface_name)),
                                        r'(^\s*edit\s+"{}"\s*$)'.format(re.escape(old_interface_name)),
                                        r'(^\s*edit\s+"{}"\s+address\s*$)'.format(re.escape(old_interface_name)),
                                    ]

                                    # Compile all patterns into a single regex
                                    compiled_patterns = re.compile('|'.join(patterns))

                                    # Read the configuration file line by line and modify as necessary
                                    with open(json_filename, "r") as file:
                                        config_lines = file.readlines()

                                    # Prepare a list for the modified lines
                                    modified_lines = []

                                    # Process each line to check if it matches any pattern and replace if needed
                                    for line in config_lines:
                                        if compiled_patterns.search(line):
                                            # Replace only the exact interface name match
                                            modified_line = line.replace(old_interface_name, new_interface_name)
                                            modified_lines.append(modified_line)
                                        else:
                                            # Append the line unchanged if there's no match
                                            modified_lines.append(line)

                                    # Write the modified configuration back to a new file
                                    json_filename_split = json_filename.split(".")[0]
                                    with open(f'{json_filename_split}_modified.conf', "w") as file:
                                        file.writelines(modified_lines)
                                    print(f"Interface name replacement completed. Modified configuration saved to {f'{json_filename_split}_modified.conf'}\n")
                                    break                               
                                if is_right =='n':
                                    break   
                            if found==False:
                                print("Interface name not found. Please check.")
        

def main():
    def start_screen():
        print("\033c", end="")
        print("-" * 50)
        print("=" * 50)
        print(" " * 10 + "! FortiFlex !")
        print(" " * 10 + "Version: 1.0.0")
        print(" " * 10 + "Developed by: PGK")
        print("=" * 50)       
        print("\nWelcome to the FortiFlex!")
        print("This tool helps manage and automate tasks for Fortinet devices.")
    def choose_functionality():
        print("\nPlease select: ")
        print("\n1 - Manage a fortigate device \n2 - Transfer fortigate configuration from a source to a destination")
        functionality = None
        while functionality is None:
            try:
                functionality = int(input("Enter your choice: "))
                if (functionality>2) or (functionality<1):
                    print("Invalid choice.")
                    functionality = None
            except EOFError:
                exit()
            except:  
                print("Invalid")  
                functionality = None 
            else:
                return functionality   
    def yaml_files(functionality):
        def print_yaml():
                current_directory = os.getcwd()
                join_directory = os.path.join(current_directory,"yaml")
                yaml_directory = os.listdir(join_directory)
                y_file = [yaml_file for yaml_file in yaml_directory if yaml_file.endswith('.yaml')]
                num=1
                for file in y_file:
                    print(f'{num} - {file}')
                    num+=1
                return y_file
        if functionality == 1:
            print("\nPlease select the YAML file for the fortigate device:")
            file = print_yaml()
            while True:
                try:
                    get_info = int(input("Option: "))
                    if get_info == 0:
                        sys.exit()
                    source = file[get_info-1]
                except EOFError:
                    exit()
                except:
                    print("Please select a valid option.")
                else:
                    return source
        if functionality == 2:
            print("\nPlease select the YAML file for the source and destination fortigate devices: ")
            file = print_yaml()
            while True:
                try:
                    get_info = int(input("Source: "))
                    source = file[get_info-1]
                    if get_info == 0:
                        exit()
                        break
                    set_info = int(input("Destination: "))
                    if set_info == 0:
                        exit()
                        break
                    print("\n")
                    destination = file[set_info-1]
                except EOFError:
                    exit()
                except:
                    print("Please select a valid option.")
                else:
                    if source!=destination:
                        return source, destination
                    else:
                        print("Source and destination cannot be the same device.")
        return 0
    def load_yamls(**kwargs):
        functionality = kwargs.get("functionality")
        info_file = kwargs.get("info_file")
        set_info_file = kwargs.get("set_info_file")
        if functionality == 1:
            fortigate = Fortigate(info_file)
            with open(f'yaml/{info_file}', 'r') as get_file:
                src_info = yaml.safe_load(get_file)    
                return fortigate,src_info
        if functionality == 2:
            fortigate = Fortigate(info_file)
            dst_fortigate = Fortigate(set_info_file)
            with open(f'yaml/{set_info_file}', 'r') as set_file:
                dst_info = yaml.safe_load(set_file)
            with open(f'yaml/{info_file}', 'r') as get_file:
                src_info = yaml.safe_load(get_file)    
                return fortigate, dst_fortigate,dst_info,src_info
    def login_prompts(**kwargs):
        try:
            functionality = kwargs.get("functionality")
            fortigate= kwargs.get("fortigate")
            info_file= kwargs.get("info_file")
            set_info_file= kwargs.get("set_info_file")
            #Login prompt for source device
            if functionality == 1:
                login = None
                while login is None:
                    source_device_login_type = input(f"Do you want to connect as a local user or as an API user to the {src_info["host"]}? (l -> Local a-> API): ")
                    if source_device_login_type=='l':
                        fortigate.user_login(info_file)
                        break
                    if source_device_login_type=='a':
                        fortigate.login(info_file)
                        break
                    else:
                        print("\nInvalid option.")
                        login = None
            if functionality == 2:
                login = None
                while login is None:
                    source_device_login_type = input(f"Do you want to connect as a local user or as an API user to the {src_info["host"]}? (l -> Local a-> API): ")
                    if source_device_login_type=='l':
                        fortigate.user_login(info_file)
                        break
                    if source_device_login_type=='a':
                        fortigate.login(info_file)
                        break
                    else:
                        print("\nInvalid option.")
                        login = None
                #Login prompt for destination device
                while True:
                    destination_device_login_type = input(f"Do you want to connect as a local user or as an API user to the {dst_info["host"]}? (l -> Local a-> API): ")
                    if destination_device_login_type=='l':
                            dst_fortigate.user_login(set_info_file)
                            break
                    if destination_device_login_type=='a':
                            dst_fortigate.login(set_info_file)
                            break
                    else:
                        print("\nInvalid option.")
        except EOFError:
            exit()
    def main_screen(**kwargs):
        print("\033c", end="")
        functionality = kwargs.get("functionality")
        fortigate= kwargs.get("fortigate")
        dst_fortigate = kwargs.get("dst_fortigate")

        if functionality == 1:
            dst_fortigate = fortigate
        try:
            while True:
                if functionality == 1:
                    print(f"Connected to {src_info["host"]} ")
                if functionality == 2:
                    print(f"Connected to {src_info["host"]} as source and to {dst_info["host"]} as destination.")
                print("\nSelect an option:")
                print("1 - Print device configuration sections")
                print("2 - Check Multi-VDOM option")
                print("3 - Rename Fortigate interfaces(alias)")
                print("4 - Migrate from source Fortigate device")
                print("5 - Configuration Download")
                print("6 - Configuration Upload")
                print("7 - Rename Fortigate interface(altering .conf file)")
                print("0 - Exit")
                choice = input("Enter your choice: ")
                if choice == '1':
                    section_list = fortigate.print_config_sections()
                    section_choice = None
                    while section_choice is None:
                        try:
                            section_choice = int(input(f"\nEnter the section number (1-{len(section_list)}) (or '0' to quit): "))
                            if section_choice == 0:
                                print("\n")
                                break
                            if (section_choice) < 1 or section_choice > len(section_list):
                                print("Invalid section number.")
                                section_choice = None
                            else:    
                                section_name = section_list[section_choice - 1]
                                print(f"Selected section: {section_list[section_choice - 1]}\n")
                                migration_flag = False
                                vdoms = fortigate.get_vdoms()
                                num=1
                                for vdom_ in vdoms:
                                    print(f'{num} - {vdom_}')
                                    num+=1  
                                vdom = None 
                                while vdom is None:
                                    try:
                                        vdom = int(input("Please select a vdom for this configuration section (or '0' to quit): "))
                                        if vdom == 0:
                                            print("\n")
                                            break
                                        if (vdom) < 1 or vdom > len(vdoms):
                                            print("Invalid section number.")
                                            vdom = None
                                        else:
                                            print(f"Selected vdom: {vdoms[int(vdom)-1]}")
                                            vdom = vdoms[int(vdom)-1]
                                            fortigate.get_config(section_name=section_name,migration_flag=migration_flag,vdom=vdom,functionality=functionality)
                                            while True:
                                                print("\nSelected Section Options:")
                                                print("1 - Send JSON file to FortiGate")
                                                print("2 - Delete object on Fortigate")
                                                print("0 - Back to main menu")
                                                section_option = input("Enter your choice: ")
                                                if section_option == '1':
                                                    current_directory = os.getcwd()
                                                    all_files = os.listdir(current_directory)
                                                    config_files = [file for file in all_files if 'config' in file and file.endswith('.json')]
                                                    print("\n\nFound the below JSON configuration files. \n ")
                                                    num=1
                                                    for file in config_files:
                                                        print(f'{num} - {file}')
                                                        num+=1
                                                    json_filename = None
                                                    while json_filename is None:
                                                        try:
                                                            json_filename = int(input("\n\nEnter the JSON file number to send (or '0' to quit): "))
                                                            print(f"input: {json_filename} | length: {len(config_files)}")
                                                            if json_filename == 0:
                                                                    break 
                                                            if (json_filename<1):
                                                                print("Please select a valid option.")         
                                                                json_filename = None 
                                                                continue 
                                                            if json_filename>len(config_files):
                                                                print("Megalitero")
                                                                print("Invalid option.")
                                                                json_filename = None    
                                                                continue                                                              
                                                        except TypeError:
                                                            print("Invalid option.")
                                                            json_filename = None  
                                                            continue  
                                                        except ValueError:
                                                            print("Invalid option.")
                                                            json_filename = None 
                                                            continue                                                                  
                                                        else:
                                                            print(f"Selected file: {config_files[json_filename-1]}")                                                      
                                                    while True:
                                                                if json_filename==0:
                                                                    break
                                                                answer =input("\nAre you sure you want to send the configuration?(y-> YES / n-> NO): ")
                                                                if answer=='y':
                                                                    dst_fortigate.send_object(config_files[json_filename-1], section_name,fortigate)
                                                                    break
                                                                if answer=='n':
                                                                    break          
                                                                else:
                                                                    print("Invalid choice. Please try again.")             
                                                elif section_option == '0':
                                                    print("\033c", end="")
                                                    break
                                                elif section_option == "2":
                                                    current_directory = os.getcwd()
                                                    all_files = os.listdir(current_directory)
                                                    config_files = [file for file in all_files if 'config' in file and file.endswith('.json')]
                                                    print("\n\nFound the below JSON configuration files. \n ")
                                                    num=1
                                                    for file in config_files:
                                                        print(f'{num} - {file}')
                                                        num+=1
                                                    json_filename = None
                                                    while json_filename is None:
                                                        try:
                                                            json_filename = int(input("\n\nEnter the JSON file number to delete (or '0' to quit): "))
                                                            print(f"input: {json_filename} | length: {len(config_files)}")
                                                            if json_filename == 0:
                                                                    print("\n")
                                                                    break 
                                                            if (json_filename<1):
                                                                print("Please select a valid option.")         
                                                                json_filename = None 
                                                                continue 
                                                            if json_filename>len(config_files):
                                                                print("Megalitero")
                                                                print("Invalid option.")
                                                                json_filename = None    
                                                                continue                                                              
                                                        except TypeError:
                                                            print("Invalid option.")
                                                            json_filename = None  
                                                            continue  
                                                        except ValueError:
                                                            print("Invalid option.")
                                                            json_filename = None 
                                                            continue                                                                  
                                                        else:
                                                            print(f"Selected file: {config_files[json_filename-1]}")    
                                                    while True:
                                                        if json_filename==0:
                                                            break                                                                
                                                        answer =input("\nAre you sure you want to delete the configuration?(y-> YES / n-> NO): ")
                                                        if answer=='y':
                                                            dst_fortigate.delete_object(config_files[json_filename-1], section_name)
                                                            break
                                                        if answer=='n':
                                                            break          
                                                        else:
                                                            print("Invalid choice. Please try again.") 
                                    except EOFError:
                                        exit()        

                        except EOFError:
                            exit()

                elif choice == '2':
                    dst_fortigate.vdom_functionality(info_file,functionality)
                elif choice == '3':
                    if functionality == 1:
                        dst_fortigate.rename_interface_alias()
                    else:
                        print("This is only allowed when one fortigate selected.\n")
                elif choice =='4':
                    if functionality == 1:
                        print("This is only allowed when two fortigates are selected.\n")
                    else:
                        dst_fortigate.migrate(info_file,set_info_file)
                elif choice =='5':
                    if functionality==1:
                        print("Warning! This is available only with an API user that has at least rw permissions on System.")
                        fortigate_ip = src_info["host"]
                        access_token = src_info["api_key"]
                        vdoms = fortigate.get_vdoms()
                        num=1
                        for vdom_ in vdoms:
                            print(f'{num} - {vdom_}')
                            num+=1  
                        vdom_to_download = None 
                        while vdom_to_download is None:
                            try:
                                vdom_to_download = int(input("Please select a vdom (10 for global) (or '0' to quit): "))
                                if vdom_to_download == 0:
                                        print("\n")
                                        break
                                elif vdom_to_download == 10:
                                    str(vdom_to_download)
                                elif (vdom_to_download<1):
                                    print("Invalid section number.\n")
                                    vdom_to_download = None
                                    continue
                                elif vdom_to_download>len(vdoms):
                                    print("Invalid section number.\n")
                                    vdom_to_download = None
                                    continue                                    
                            except TypeError:
                                print("Invalid.")
                                vdom_to_download = None
                                continue
                            except ValueError:
                                print("Invalid.")
                                vdom_to_download = None
                                continue
                            else:
                                if vdom_to_download ==10:
                                    vdom_to_download="global"
                                    print(f"Selected vdom: Global\n")
                                    answer =input("\nAre you sure you want to download the configuration?(y-> YES / n-> NO): ")
                                    while True:
                                        if answer=='y':
                                            dst_fortigate.download_config(fortigate_ip, vdom_to_download,access_token)
                                            break
                                        if answer=='n':
                                            break
                                        else:
                                            print("Invald option.")
                                else:
                                    print(f"Selected vdom: {vdoms[vdom_to_download-1]}\n")
                                    answer =input("\nAre you sure you want to download the configuration?(y-> YES / n-> NO): ")
                                    while True:
                                        if answer=='y':
                                            print(vdom_to_download)
                                            vdom = vdoms[vdom_to_download-1]
                                            dst_fortigate.download_config(fortigate_ip, vdom,access_token)
                                            break
                                        if answer=='n':
                                            break
                                        else:
                                            print("Invald option.")                              

                    else:
                        print("This is only available when one fortigate device has been selected.\n")  
                elif choice =='6':  
                    if functionality==1:  
                        print("Warning! This is available only with an API user that has at least rw permissions on System.")       
                        current_directory = os.getcwd()
                        all_files = os.listdir(current_directory)
                        config_files = [file for file in all_files if file.endswith('.conf')]
                        print("\n\nFound the below configuration files at the parent directory. \n ")
                        num=1
                        for file in config_files:
                            print(f'{num} - {file}')
                            num+=1
                        configuration = None
                        while configuration is None:
                            try:
                                configuration = int(input("\n\nEnter the configuration file number to send (or '0' to quit): "))
                                if configuration == 0:
                                    print("\n")
                                    break 
                                elif (configuration<1):
                                    print("Invalid section number.\n")
                                    configuration = None
                                    continue
                                elif configuration>len(config_files):
                                    print("Invalid section number.\n")
                                    configuration = None
                                    continue   
                                                                 
                            except TypeError:
                                print("Invalid.")
                                configuration = None
                                continue
                            except ValueError:
                                print("Invalid.")
                                configuration = None
                                continue                                      
                            else:
                                print(f"Selected file: {config_files[configuration-1]}")
                        fortigate_ip = src_info["host"]
                        configuration = config_files[configuration-1] 
                        vdoms = fortigate.get_vdoms()
                        num=1
                        for vdom_ in vdoms:
                            print(f'{num} - {vdom_}')
                            num+=1  
                        vdom_to_upload = None 
                        while vdom_to_upload is None:
                            if configuration == 0:
                                break 
                            try:
                                vdom_to_upload = int(input("Please select a vdom (10 for global) (or '0' to quit): "))
                                if vdom_to_upload == 0:
                                    print("\n")
                                    break
                                elif vdom_to_upload == 10:
                                    str(vdom_to_upload)
                                elif (vdom_to_upload<1):
                                    print("Invalid section number.\n")
                                    vdom_to_upload = None
                                    continue
                                elif vdom_to_upload>len(vdoms):
                                    print("Invalid section number.\n")
                                    vdom_to_upload = None
                                    continue                                    
                            except TypeError:
                                print("Invalid.")
                                vdom_to_upload = None
                                continue
                            except ValueError:
                                print("Invalid.")
                                vdom_to_upload = None
                                continue
                            else:
                                if vdom_to_upload ==10:
                                    vdom_to_upload="global"
                                    print(f"Selected vdom: Global\n")
                                    answer =input("\nAre you sure you want to upload the configuration?(y-> YES / n-> NO): ")
                                    while True:
                                        if answer=='y':
                                            fortigate.upload_config(configuration,fortigate_ip,vdom_to_upload) 
                                            break
                                        if answer=='n':
                                            break
                                        else:
                                            print("Invald option.")                            
                                else:
                                    vdom = vdoms[int(vdom_to_upload)-1]
                                    print(f"Selected vdom: {vdoms[int(vdom_to_upload)-1]}\n")
                                    answer =input("\nAre you sure you want to upload the configuration?(y-> YES / n-> NO): ")
                                    while True:
                                        if answer=='y':      
                                            fortigate.upload_config(configuration,fortigate_ip,vdom_to_upload)
                                            break                               
                                        if answer=='n':
                                            break
                                        else:
                                            print("Invald option.")
                                    

                            break  
                    else:
                        print("This is only available when one fortigate device has been selected.\n")    
                elif choice == '0':
                    break
                elif choice == '7':
                    print("THIS FUNCTION IS STILL UNDER DEVELOPMENT. USE IT AT YOUR OWN RISK")
                    fortigate.rename_interface()
                else:
                    print("Invalid choice. Please try again.")
        except EOFError:
                exit()
        if functionality == 1:
            fortigate.logout()
        if functionality == 2:
            fortigate.logout()
            dst_fortigate.logout()
    start_screen()
    functionality = choose_functionality()
    if functionality == 1:
        info_file = yaml_files(functionality)
        fortigate,src_info  = load_yamls(functionality=functionality,info_file=info_file)
        login_prompts(functionality=functionality,fortigate=fortigate,info_file=info_file)
        main_screen(functionality=functionality,fortigate=fortigate)
    if functionality == 2:
        info_file, set_info_file = yaml_files(functionality)
        fortigate, dst_fortigate,dst_info,src_info  = load_yamls(functionality=functionality,info_file=info_file,set_info_file=set_info_file)
        login_prompts(functionality=functionality,fortigate=fortigate,info_file=info_file,set_info_file=set_info_file)
        main_screen(functionality=functionality,fortigate=fortigate,dst_fortigate=dst_fortigate)
if __name__ == "__main__":
    main()
