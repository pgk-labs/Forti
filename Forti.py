import sys
import json
import urllib3
import requests
import yaml
from fortiosapi import FortiOSAPI
from fortiosapi.exceptions import NotLogged
from json.decoder import JSONDecodeError
import os
import re
from tqdm import tqdm
from datetime import datetime
import logging
import time
from requests.auth import HTTPBasicAuth
from requests.exceptions import ConnectTimeout, InvalidURL
from base64 import b64encode
import copy
try:
    import readline  # For Linux and macOS
except ImportError:
    import pyreadline as readline  # For Windows
# Disable warnings about unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Set logging level to ERROR
logging.basicConfig(level=logging.ERROR)
sequence=1
class Fortigate:
    global sequence
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
        except InvalidURL:
            print("Invalid URL. Please ensure that your fortigate IP is valid.")
            sys.exit(1)
        except TimeoutError:
            print("Timeout. Please ensure that your fortigate device is accessible via this method.")
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
        except InvalidURL:
            print("Invalid URL. Please ensure that your fortigate IP is valid.")
            sys.exit(1)  
        except TimeoutError:
            print("Timeout. Please ensure that your fortigate device is accessible via this method.")  
        else:
            okmsg = "Connected to destination Fortigate device."
            return okmsg

    def logout(self):
        # Logout from the api device
        self.api.logout()

    def load_commands(self,file_path):
        """Load commands from a text file into a list."""
        with open(file_path, "r") as file:
            return [line.strip() for line in file if line.strip()]

    def cli_interface(self,commands):
        """Simple CLI interface with autocomplete and help functionality."""
        def completer(text, state):
            # Split the input text into words
            parts = readline.get_line_buffer().strip().split()
            if len(parts) <= 1:
                # If it's the first word, match from all commands
                options = sorted(set(cmd.split()[0] for cmd in commands if cmd.startswith(text)))
            else:
                # If there are previous words, filter commands based on the input so far
                prefix = " ".join(parts[:-1])  # Get the part already typed
                options = [cmd[len(prefix) + 1:] for cmd in commands if cmd.startswith(prefix) and cmd[len(prefix) + 1:].startswith(text)]
            return options[state] if state < len(options) else None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")

        print("CLI mode. Enter the configuration section or Type 'exit' to quit.")
        while True:
            try:
                user_input = input("> ").strip()
                
                if user_input.endswith("?"):
                    # Show matching commands
                    prefix = user_input[:-1].strip()
                    options = [cmd for cmd in commands if cmd.startswith(prefix)]
                    print("Possible commands:")
                    print("\n".join(options))  # Print each command on a new line
                elif user_input == "exit":
                    print("Exiting CLI...")
                    return user_input
                elif user_input in commands:
                    print(f"Selected section: {user_input}")
                    return user_input
                elif user_input=="":
                    pass
                else:
                    print(f"Unknown command: {user_input}")
            except (EOFError, KeyboardInterrupt):
                user_input="exit"
                return user_input

    def print_config_sections(self):
        print("\nSupported FortiOS versions:")
        print("1 - v6.4")
        print("2 - v7.4")
        print("If you are using another version, it still will work for the majority of the sections.")
        flag = True
        while flag == True:
            try:
                version = int(input("\nEnter the source fortigate version: "))
                if version == 1:
                    fortiosversion = "sections/migration_sections_v6.4.txt"
                    flag = False
                elif version == 2:
                    fortiosversion = "sections/migration_sections_v7.4.txt"
                    flag = False
                else:
                    print("Invalid Choice.")
                    flag = True
            except ValueError:
                print("Invalid Value.")
                flag = True  
        commands = self.load_commands(fortiosversion)
        section = self.cli_interface(commands)
        return section

    def get_config(self,**kwargs):    
        section_name = kwargs.get("section_name")
        migration_flag = kwargs.get("migration_flag")    
        vdom = kwargs.get("vdom")
        functionality = kwargs.get("functionality")
        dst_fortigate = kwargs.get("dst_fortigate")
        interface_translations = kwargs.get("interface_translations")
        mgmt_interface = kwargs.get("mgmt_interface")
        generic_user_password = kwargs.get("generic_user_password")
        src_host = kwargs.get("src_host")
        path, name = section_name.split(' ')
        parameters =  'with_meta=false&skip=true&exclude-default-values=true&plain-text-password=1&datasource=true&skip=true'  
        if vdom=="global":
            vdom=""
        if path == "system" and name == "vdom":
            config = self.api.get(path=path, name=name,parameters=parameters,vdom=vdom,mkey=vdom).get('results', [])
        else:
            config = self.api.get(path=path, name=name,parameters=parameters,vdom=vdom).get('results', [])
        section_name_underscore = section_name.replace(' ', '_')
        if ":" in src_host:
            src_host,port = src_host.split(":")
        output_filename = section_name_underscore + "_" + src_host + "_" "FortigateTool.json"
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
                            self.get_object_config(output_filename,section_name,src_host)
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
            output = self.config_filtering(path=path,name=name,config=config,output_filename=output_filename,interface_translations=interface_translations,mgmt_interface=mgmt_interface,generic_user_password=generic_user_password)
            return output  

    def global_replace(self,data, search_value, replace_value):
        """
        Recursively replaces occurrences of search_value with replace_value in a nested structure (dict, list, etc.),
        while preserving the condition for 'role' keys with 'lan' or 'wan' values.
        """
        if isinstance(data, dict):
            return {
                key: self.global_replace(value, search_value, replace_value)
                if not (key == "role" and value in ["lan", "wan"]) else value
                for key, value in data.items()
            }
        elif isinstance(data, list):
            return [self.global_replace(item, search_value, replace_value) for item in data]
        elif isinstance(data, (str, int, float, bool)) or data is None:
            return replace_value if data == search_value else data
        else:
            # Handles cases where the value might itself be a nested structure
            return data

    def config_filtering(self,**kwargs): 
        path = kwargs.get("path")
        name = kwargs.get("name")    
        config = kwargs.get("config")
        output_filename = kwargs.get("output_filename")
        dst_fortigate = kwargs.get("dst_fortigate")
        interface_translations = kwargs.get("interface_translations")
        mgmt_interface = kwargs.get("mgmt_interface")
        generic_user_password = kwargs.get("generic_user_password")
        references_flag = kwargs.get("references_flag")
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
        cli_conn_status = "cli-conn-status"

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
                    if cli_conn_status in item:
                        item.pop(cli_conn_status)
                    if path=="firewall" and name=="policy":
                        if 'dstaddr' not in item:
                            item["dstaddr"] = "all"
                    if path=="system" and name =="interface":
                        if 'mode' in item and item["mode"]=="dhcp":
                            if 'ip' in item:
                                item.pop("ip")
                    if path=="router" and name=="static":
                        #Removing default route for safety
                        for item in config:
                            try:
                                if ("dstaddr" not in item) and ("dst" not in item):
                                    if 'seq-num' and 'q_origin_key' and 'gateway' and 'device' in item:
                                        item.pop("seq-num") 
                                        item.pop("q_origin_key")
                                        item.pop("gateway")
                                        item.pop("device")
                                        item["that-route-was-a-default-gateway"] = "safe-mechanism"
                            except AttributeError:
                                pass
                except AttributeError:
                    pass
        if references_flag:
                if interface_translations:
                        for source_intf,dst_intf in interface_translations.items():
                            search_value = source_intf
                            replace_value = dst_intf
                            updated_config = self.global_replace(config, search_value, replace_value)   
                            config = updated_config 
                return config

        '''
        if path=="system" and name=="settings":
        #Enable ssl-vpn setting
                try:   
                    config["gui-sslvpn"]="enable"  
                except AttributeError:
                    pass        
        '''
        if references_flag!=True:                                 
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
                            item["passwd"]=generic_user_password #Forti cannot transfer passwords as appearing as ENC XXXX, so we modify the value
                    except AttributeError:
                        pass 
            if path=="user" and name=="ldap":
                for item in config:
                    try:
                        if "password" in item:
                            item["password"]=generic_user_password
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
                sorted_json_object = sorted(config, key=lambda x: (
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
                if interface_translations:
                    for source_intf,dst_intf in interface_translations.items():
                        search_value = source_intf
                        replace_value = dst_intf
                        updated_config = self.global_replace(sorted_json_object, search_value, replace_value)   
                        sorted_json_object = updated_config 
                for interface in sorted_json_object:
                    if interface["name"]==mgmt_interface:
                        if mgmt_interface != "none":
                            del interface["ip"]
                            del interface["allowaccess"]    
                    with open(output_filename, 'w') as json_file:
                            json.dump(sorted_json_object, json_file, indent=4)  
                return output_filename   
            else:
                #Make it a list if it is not
                if isinstance(config, list):
                    if interface_translations:
                        for source_intf,dst_intf in interface_translations.items():
                            search_value = source_intf
                            replace_value = dst_intf
                            updated_config = self.global_replace(config, search_value, replace_value)   
                            config = updated_config      
                    with open(output_filename, 'w') as json_file:
                        json.dump(config, json_file, indent=4)  
                else:
                    config = [config]
                    if interface_translations:
                        for source_intf,dst_intf in interface_translations.items():
                            search_value = source_intf
                            replace_value = dst_intf
                            updated_config = self.global_replace(config, search_value, replace_value)   
                            config = updated_config      
                    with open(output_filename, 'w') as json_file:
                        json.dump(config, json_file, indent=4)  
                return output_filename

    def get_object_config(self,output_filename,section_name,src_host):
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
                    if ":" in src_host:
                        src_host,port = src_host.split(":")
                    selected_filename = f"{section_name}_{selected_name}_{src_host}_FortigateTool.json"
                    with open(selected_filename, 'w') as selected_file:
                        json.dump(config, selected_file, indent=4)
                    print(f"\nSelected configuration '{selected_name}' saved to {selected_filename}")
                else:
                    print("\nInvalid selection. Please choose a valid index.")
            except ValueError:
                print("\nInvalid input. Please enter a valid index number.")

    def logout(self):
        try:
            self.api.logout()
        except ConnectTimeout:
            pass
        
    def get_vdoms(self):
        def sort(lst,first):
            return sorted(lst, key=lambda x: (x != first, x))
        parameters =  'with_meta=false&skip=true&exclude-default-values=true'              
        config = self.api.get(path="system", name="vdom", vdom='root',parameters=parameters).get('results', [])
        vdom_names = [obj.get('name') for obj in config if 'name' in obj]
        start = "root"
        sorted_list = sort(vdom_names, start)
        return sorted_list

    def update_object(self, json_filename, section_name):
        config_directory = "results"
        success_log_file ="success_log.txt"
        fail_log_file = "fail_log.txt"
        if not os.path.exists(config_directory):
            os.makedirs(config_directory)
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
                vdom = int(input("Please select the VDOM which the configuration exists (or '0' to quit): "))
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
                    try:
                        mkey = self.api.get_mkey(path=path, name=name, data=obj)
                        response = self.api.delete(path=path, name=name, data=obj, mkey=mkey,vdom=vdom)
                        self.config_logging(obj,response,success_log_file, fail_log_file,config_directory)        
                    except EOFError:
                        exit()
                    except KeyboardInterrupt:
                        exit()
                    except JSONDecodeError:
                        print("Could not decode the specified JSON file.")
                    except:
                        print("Error occurred.")
                                     
    def delete_object(self,json_filename, section_name):
        config_directory = "results"
        success_log_file ="success_log.txt"
        fail_log_file = "fail_log.txt"
        if not os.path.exists(config_directory):
            os.makedirs(config_directory)
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
                vdom = int(input("Please select the VDOM which the configuration exists (or '0' to quit): "))
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
                    try:
                        mkey = self.api.get_mkey(path=path, name=name, data=obj)
                        response = self.api.delete(path=path, name=name, data=obj, mkey=mkey,vdom=vdom)
                        self.config_logging(obj,response,success_log_file, fail_log_file,config_directory)        
                    except EOFError:
                        exit()
                    except KeyboardInterrupt:
                        exit()
                    except JSONDecodeError:
                        print("Could not decode the specified JSON file.")
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

    def migration_file(self,phase,vdom,fail_directory_path,fortiosversion):
        section_list = []
        if phase==1:
            with open(f'sections/{fortiosversion}', 'r') as f:
            #with open(f'sections/test.txt', 'r') as f:
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

    def migrate(self,**kwargs):
        info_file = kwargs.get("info_file")
        set_info_file = kwargs.get("set_info_file")
        fortigate = kwargs.get("fortigate")
        dst_fortigate = kwargs.get("dst_fortigate")
        try:
            src_info , dst_info = self.host_info(info_file,set_info_file)
            vdom_instances = fortigate.get_vdoms()
            multi_vdom = False # Flag for multivdom
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            #Generating parent folder
            parent_directory = f'Migration_{timestamp}'
            if not os.path.exists(parent_directory):
                os.makedirs(parent_directory)
            parameters =  'with_meta=false&skip=true&exclude-default-values=true' 
            src_intf = fortigate.api.get(path="system",name="interface", parameters=parameters).get('results', [])
            dst_intf = dst_fortigate.api.get(path="system",name="interface",parameters=parameters).get('results', [])
            source_interfaces = [obj.get('name') for obj in src_intf if obj.get('type') == "physical" or obj.get('type') == "hard-switch"]
            dst_interfaces = [obj.get('name') for obj in dst_intf if obj.get('type') == "physical" or obj.get('type') == "hard-switch"]
            matching_interfaces = []
            non_matching_interfaces = []
            interface_translations = {}
            for intf in source_interfaces:
                if intf in dst_interfaces:
                    matching_interfaces.append(intf)
                else:
                    non_matching_interfaces.append(intf)
            diff = [item for item in dst_interfaces if item not in source_interfaces]
            diff.append("Do Not Migrate This interface")
            if non_matching_interfaces:
                print("\nIt seems that some physical interfaces are not the same between fortigates. Please choose:")
                while non_matching_interfaces:                   
                    for interface in non_matching_interfaces:
                        print(f'\nThe interface {interface} ({src_info["host"]}) will be migrated to {dst_info["host"]}, on port:')
                        for index, name in enumerate(diff, start=1):
                            print(f"{index} - {name}")
                        loop_flag = True
                        while loop_flag == True:
                            try:
                                answer = int(input("\nEnter the interface number: "))
                                if 1 <= answer <= len(diff):
                                    loop_flag = False
                                    selected_interface = diff[answer - 1]                                 
                                    non_matching_interfaces.remove(interface)
                                    if answer == len(diff):
                                        pass
                                    else:
                                        interface_translations[interface] = selected_interface
                                        diff.pop(answer-1)
                                else:
                                    print("Invalid Choice.")
                            except ValueError:
                                print("\nInvalid input. Please enter a valid index number.")
                            except KeyboardInterrupt:
                                exit()
                print("\nThe new interface mapping is: ") 
                for old,new in interface_translations.items():
                    print(f'{old} -> {new}')   
            print("\nThe current management interface may be overlapped from the migration if they have the same interface name. In order to avoid this, you need to type the interface name. If not, please type none.")
            mgmt_interface = input(f"Please type the interface name that corresponds to the destination's fortigate yaml file host field: ")
            print("In case there is a match, the script will loose the connection and crash but the access will be intact, so start again the migration proccess. This will happen once.")
            loop_flag = True
            while loop_flag == True:
                for interface in dst_intf:
                    if (interface["name"]==mgmt_interface) or (mgmt_interface=="none"):
                        loop_flag = False
                if loop_flag == True:
                    print("Did not found this interface name.")
                    mgmt_interface = input(f"Please type the interface name that corresponds to the destination's fortigate yaml file host field: ")                        
            print("FortiOS API cannot copy administrator passwords. They will be coppied without one, so you need to copy paste them from cli.")
            print("FortiOS API cannot transfer passwords as appearing as ENC XXXX, so we modify the value. Please input a generic password. Later you can follow the above procedure.")
            generic_user_password = input("Enter a generic user password: ")
            print("\nSupported FortiOS versions:")
            print("1 - v6.4")
            print("2 - v7.4")
            print("3 - Testing")
            print("If you are using another version, it still will work for the majority of the sections. Some features may not be transfered.")
            flag = True
            while flag == True:
                try:
                    version = int(input("\nEnter the source fortigate version: "))
                    if version == 1:
                        fortiosversion = "migration_sections_v6.4.txt"
                        flag = False
                    elif version == 2:
                        fortiosversion = "migration_sections_v7.4.txt"
                        flag = False
                    elif version == 3:
                        fortiosversion = "test.txt"
                        flag = False
                    else:
                        print("Invalid Choice.")
                        flag = True
                except ValueError:
                    print("Invalid Value.")
                    flag = True                  
            loop_flag = True
            begin =input("\nBegin Migration?(y-> YES / n-> NO): ") 
            while loop_flag == True:
                if begin=='y':      
                    loop_flag = False
                    break                              
                if begin=='n':
                    loop_flag = False
                    exit()
                else:
                    print("Invald option.") 
                    answer =input("\nBegin Migration?(y-> YES / n-> NO): ") 
            if len(vdom_instances)>1: #If vdoms > 1, ask for multivdom migration
                flag = False
                while flag == False:
                    vdom_detection = int(input("\nMulti vdoms detected. Do you want to: \n 1 - Migrate all the vdoms \n 2 - Migrate selected vdom \nPlease select: "))
                    if vdom_detection == 1:
                        multi_vdom = True
                        flag = True
                        break
                    if vdom_detection == 2:
                        num=1
                        print("\n")
                        for vdom_ in vdom_instances:
                            print(f'{num} - {vdom_}')
                            num+=1  
                            vdom = None 
                        while vdom is None:
                            try:
                                vdom = int(input("Please select the vdom to migrate: "))
                                if (vdom) < 1 or vdom > len(vdom_instances):
                                    print("Invalid section number.")
                                    vdom = None
                                else:
                                    print(f"Selected vdom: {vdom_instances[int(vdom)-1]}")
                                    if vdom_instances[int(vdom)-1] =='root':
                                        multi_vdom = False
                                    else:
                                        multi_vdom = False
                                        self.enable_vdom_functionality(set_info_file)
                                        time.sleep(5)                                       
                                    temp_vdom = vdom_instances[int(vdom)-1]  
                                    vdom_instances.clear()
                                    vdom_instances = temp_vdom
                                    vdom_instances = [vdom_instances]
                                    flag = True
                            except TypeError:
                                print("Invalid option.")
                                vdom = None  
                                continue  
                            except ValueError:
                                print("Invalid option.")
                                vdom = None 
                                continue             
                    else:
                        print("Invalid choice")
                        flag = False
            print(f"Migration started using {fortiosversion} file.")
            for i in range(1,3): # making 2 rounds of passing sections
                    for vdom_instance in vdom_instances:
                        if vdom_instance=="root":
                            vdom_instance=""
                        success_log,failed_log,fail_directory_path,vdom_failed_sections = self.create_files_and_directories(i,vdom_instance,parent_directory)
                        section_list = self.migration_file(i,vdom_instance,fail_directory_path,fortiosversion)
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
                            config = fortigate.get_config(section_name=section, vdom=vdom_instance,migration_flag=True,dst_fortigate=dst_fortigate,interface_translations=interface_translations,mgmt_interface=mgmt_interface,generic_user_password=generic_user_password)
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
                                        response = dst_fortigate.api.put(path=path, name=name, data=config_data, mkey=mkey, vdom=vdom_instance)
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
                                    mkey = fortigate.api.get_mkey(path=path, name=name, data=obj)  
                                    response = dst_fortigate.api.set(path=path, name=name, data=obj, mkey=mkey)
                                    self.migrate_logging(obj,response,success_log,failed_log,section,vdom_failed_sections)
                                else:
                                    if path=="system" and (name=="vdom" or name=="vdom-link" or name=="vdom-property" or name=="vdom-radius-server" or name=="vdom-exception" or name=="vdom-link"):
                                        vdom_instance="root"
                                    mkey = fortigate.api.get_mkey(path=path, name=name, data=obj,vdom=vdom_instance)                 
                                    response = dst_fortigate.api.set(path=path, name=name, data=obj, mkey=mkey)
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
                            dst_fortigate.enable_vdom_functionality(set_info_file)
                            time.sleep(5)
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
        except UnicodeDecodeError:
            with open("Unicode_Decode_Error.txt", 'a') as output:
                output.write(f'{section} - Object: ')
                json.dump(obj, output)
                output.write('\n\n')
        except KeyboardInterrupt:
            exit()
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
                            directory_path = os.path.dirname(fail_log_file)
                            path = os.path.join(directory_path, 'already_exists.txt')
                            with open(path, 'a') as output:
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
                directory_path = os.path.dirname(fail_log_file)
                path = os.path.join(directory_path, 'unknown.txt')
                with open(path, 'a') as output:
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
        global sequence
        with open("errors/error_codes.json", 'r') as file:
            error_codes = json.load(file)
        try:
            if 'status' in response:           
                if response.get('status') == 'success':
                    #Writing logs
                    with open(f'{config_directory}/{success_log_file}', 'a') as success_output:
                        json.dump(obj, success_output)
                        success_output.write(f'\nSequence: {sequence} | Response: ')
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
                                    output.write(f"Sequence: {sequence} | Error {error_code}: {error_message}\n\n")
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
                                    fail_output.write(f"Sequence: {sequence} | Error {error_code}: {error_message}\n\n")
                                else:
                                    json.dump(response, fail_output)
                                    fail_output.write(f"\nSequence: {sequence}")
                                    fail_output.write('\n\n')
                    else:
                        #Writing logs
                        with open(f'{config_directory}/{fail_log_file}', 'a') as fail_output:
                            json.dump(obj, fail_output)  # Write the JSON object to the file
                            fail_output.write('\n')
                            fail_output.write(f'Sequence: {sequence} |Response: ')
                            json.dump(response, fail_output)  # Write the JSON response to the file
                            fail_output.write('\n\n')                   
                else:
                    #Writing logs
                    with open(f'{config_directory}/{fail_log_file}', 'a') as fail_output:
                        json.dump(obj, fail_output)
                        fail_output.write('\n')
                        fail_output.write(f'\nSequence: {sequence} |Response: ')                       
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
                        output.write(f'Sequence: {sequence} | Response ({response_type}): ')
                    # Write the response content (use json.dump for JSON, otherwise write raw text)
                    if response_type == 'JSON':
                        json.dump(response_content, output)
                    else:
                        output.write(response_content)
                        output.write('\n\n')  
            sequence+=1             
        except AttributeError:       
                #Writing logs      
                with open(config_directory/fail_log_file, 'a') as fail_output:
                    json.dump(obj, fail_output)
                    fail_output.write('\n')
                    fail_output.write(f'\nSequence: {sequence} |Response: ')                    
                    json.dump(obj, response)
                    fail_output.write('\n\n')            

    def check_references(self,data):
        #Open migration section files which has the right section format
        with open('sections/migration_sections_v7.4.txt', 'r') as text_file:
            text_file_contents = text_file.read().splitlines() 
        reference_mapping = {}
        #Modify the file into a format without dots
        for line in text_file_contents:
            modified_line = line.replace(".", " ")
            reference_mapping[modified_line] = line
        references = []
        str_references = ""
        if isinstance(data, list):
            #obj is the individual json of the file
            for obj in data:
                if isinstance(obj, dict):
                    q_origin_key = obj.get("q_origin_key")
                    if q_origin_key is not None:
                        pass
                    #for each items of each individual json
                    for key, value in obj.items():
                        #If the value of the key is list
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
                                        #insert to the list the reference of the obj
                                        references.append({original_datasource: name})
                                    str_references += f"Section: {modified_datasource} - Object: {name}\n"
                                    #same applies below
                        elif isinstance(value, dict):
                            #If the value of the key is dict
                            if 'datasource' in value:
                                datasource = value['datasource']
                                modified_datasource = datasource.replace(".", " ")
                                name = value.get('name', value.get('interface-name', 'N/A'))
                                if modified_datasource in reference_mapping:
                                        original_datasource = reference_mapping[modified_datasource]
                                        #insert to the list the reference of the obj
                                        references.append({original_datasource: name})
                                str_references += f"Section: {modified_datasource} - Object: {name}\n"
            if not references:         
                #print("Object has no references.")
                pass

        else:
            print("The JSON data is not a list.")
            #convert to a dict and again to list to remove duplicates
        references = list({frozenset(d.items()): d for d in references}.values())
        if "VPN2Athens_local_subnet_1" in references:
            print(references)
        return references

    def send_configuration(self,path, name,configuration):
        config_directory = "results"
        success_log_file ="success_log.txt"
        fail_log_file = "fail_log.txt"
        if not os.path.exists(config_directory):
            os.makedirs(config_directory)
        for obj in configuration:
            response = self.api.set(path=path, name=name, data=obj)
            self.config_logging(obj,response,success_log_file, fail_log_file,config_directory)

    def process_interface_references(self,initial_references,vdom,fortigate,src_host,dst_host):
        parameters ='with_meta=false&skip=true&exclude-default-values=true&plain-text-password=1&datasource=true'
        dst_intf = self.api.get(path="system", name="interface", parameters=parameters, vdom=vdom).get('results', [])
        dst_interfaces = [obj.get('name') for obj in dst_intf if obj.get('type') == "physical" or  obj.get('type') == "hard-switch"]
        matching_interfaces = []
        non_matching_interfaces = []
        interface_translations = {} 
        references_interfaces=[]
        child_references = [] 
        for initial_reference in initial_references:
            #Take every value of the initial_references and split the appropriate values (path,name,mkey)
            for key, value in initial_reference.items():
                path, name = key.split(' ', 1)
                mkey = value 
                #flag where shows that the last reference
                flag = True
                while flag:
                        #take the config of the initial referece, see if it has references
                        config = config = fortigate.api.get(path=path, name=name, parameters=parameters, vdom=vdom, mkey=mkey).get('results', [])
                        conf = fortigate.config_filtering(config=config,references_flag=True)
                        references= self.check_references(conf)
                        if references:       
                            #add the reference to a list
                            child_references.extend(references)   
                        #for every child reference to the same thing                                       
                        for ref in child_references:
                            for key, value in ref.items():
                                    path, name = key.split(' ', 1)
                                    mkey = value
                                    config = config = fortigate.api.get(path=path, name=name, parameters=parameters, vdom=vdom, mkey=mkey).get('results', [])
                                    conf = fortigate.config_filtering(config=config,references_flag=True)
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
                                    if path=="system" and name=="interface":
                                        config = fortigate.api.get(path=path, name=name, parameters=parameters, vdom=vdom, mkey=mkey).get('results', [])
                                        if len(config)>=1:
                                            if 'type' in config[0]:
                                                if config[0]["type"] == "physical" or config[0]["type"] == "hard-switch":
                                                    references_interfaces.append(mkey)
                        flag = False                   
        references_interfaces = list(set(references_interfaces))
        if not references_interfaces:
            print("Did not find any interface dependences.")
        for intf in references_interfaces:
            if intf in dst_interfaces:
                matching_interfaces.append(intf)
            else:
                non_matching_interfaces.append(intf)
            diff = [item for item in dst_interfaces if item not in references_interfaces]  
            if non_matching_interfaces:
                print("\nIt seems that some physical interfaces are not the same between fortigates. Please choose:")
                while non_matching_interfaces:                   
                    for interface in non_matching_interfaces:
                        print(f'\nThe interface {interface} ({src_host}) will be migrated to {dst_host}, on port:')
                        for index, name in enumerate(diff, start=1):
                            print(f"{index} - {name}")
                        loop_flag = True
                        while loop_flag == True:
                            try:
                                answer = int(input("\nEnter the interface number: "))
                                if 1 <= answer <= len(diff):
                                    loop_flag = False
                                    selected_interface = diff[answer - 1]                                 
                                    non_matching_interfaces.remove(interface)
                                    interface_translations[interface] = selected_interface
                                    diff.pop(answer-1)
                                else:
                                    print("Invalid Choice.")
                            except ValueError:
                                print("\nInvalid input. Please enter a valid index number.")
                            except KeyboardInterrupt:
                                exit()
                print("\nThe new interface mapping is: ") 
                for old,new in interface_translations.items():
                    print(f'{old} -> {new}')
        return interface_translations

    def process_references(self,initial_references, vdom,fortigate,interface_translations):
        try:
            child_references = [] 
            temp_references=[] 
            separator="---------"
            custom_order = ["system interface", "firewall address","firewall addrgrp","firewall ippool","router prefix-list","user tacacs+","user adgrp", "user local"]
            '''
            custom_order = ["system vdom", "system vdom-dns", "system vdom-exception", "system vdom-link", "system vdom-netflow", "system vdom-property", 
                            "system vdom-radius-server", "system vdom-sflow", "system settings", "system interface", "alertemail setting", "application custom", 
                            "application group", "application rule-settings", "vpn.certificate crl", "vpn.certificate local", "vpn.certificate ocsp-server", 
                            "vpn.certificate remote", "vpn.certificate setting", "vpn.ipsec concentrator", "vpn.ipsec fec", "vpn.ipsec forticlient", 
                            "vpn.ipsec manualkey", "vpn.ipsec manualkey-interface", "vpn.ipsec phase1", "vpn.ipsec phase1-interface", "vpn.ipsec phase2", 
                            "vpn.ipsec phase2-interface", "vpn.ssl.web host-check-software", "vpn.ssl.web portal", "vpn.ssl.web realm", "vpn.ssl.web user-bookmark", 
                            "vpn.ssl.web user-group-bookmark", "vpn.ssl client", "vpn.ssl settings", "dlp filepattern", "dlp sensitivity", "dnsfilter domain-filter", 
                            "dnsfilter profile", "extension-controller extender", "extension-controller extender-profile", "extension-controller extender-vap", 
                            "extension-controller fortigate", "extension-controller fortigate-profile", "vpn kmip-server", "vpn l2tp", "vpn pptp", "vpn qkd", 
                            "firewall ssh.local-ca", "firewall ssh.local-key", "firewall.ipmacbinding setting", "firewall.ipmacbinding table", "firewall.schedule group", 
                            "firewall.schedule onetime", "firewall.schedule recurring", "firewall.service category", "firewall.service custom", "firewall.service group", 
                            "firewall.shaper per-ip-shaper", "firewall.shaper traffic-shaper", "firewall DoS-policy", "firewall DoS-policy6", "firewall access-proxy", 
                            "firewall access-proxy-ssh-client-cert", "firewall access-proxy-virtual-host", "firewall access-proxy6", "firewall acl", "firewall acl6", 
                            "firewall address", "firewall address6", "firewall address6-template", "firewall addrgrp", "firewall addrgrp6", "firewall auth-portal", 
                            "firewall central-snat-map", "firewall decrypted-traffic-mirror", "firewall dnstranslation", "firewall global", "firewall identity-based-route", 
                            "firewall interface-policy", "firewall interface-policy6", "firewall internet-service-addition", "firewall internet-service-append", 
                            "firewall internet-service-custom", "firewall internet-service-custom-group", "firewall internet-service-definition", 
                            "firewall internet-service-extension", "firewall internet-service-group", "firewall internet-service-subapp", "firewall ip-translation", 
                            "firewall ippool", "firewall ippool6", "firewall ldb-monitor", "firewall local-in-policy", "firewall local-in-policy6", "firewall multicast-address", 
                            "firewall multicast-address6", "firewall multicast-policy", "firewall multicast-policy6", "firewall network-service-dynamic", 
                            "firewall on-demand-sniffer", "firewall profile-group", "firewall profile-protocol-options", "firewall proxy-address", "firewall proxy-addrgrp", 
                            "firewall proxy-policy", "firewall security-policy", "firewall shaping-policy", "firewall shaping-profile", "firewall sniffer", 
                            "firewall ssl-server", "firewall ssl-ssh-profile", "firewall traffic-class", "firewall ttl-policy", "firewall vip", "firewall vip6", 
                            "firewall vipgrp", "firewall vipgrp6", "ftp-proxy explicit", "icap profile", "icap server", "icap server-group", "log custom-field", 
                            "log eventfilter", "log gui-display", "log setting", "log.tacacs+accounting filter", "log.tacacs+accounting setting", "log.tacacs+accounting2 filter", 
                            "log.tacacs+accounting2 setting", "log.tacacs+accounting3 filter", "log.tacacs+accounting3 setting", "log threat-weight", "router access-list", 
                            "router access-list6", "router aspath-list", "router auth-path", "router bfd", "router bfd6", "router bgp", "router community-list", 
                            "router extcommunity-list", "router isis", "router key-chain", "router multicast", "router multicast-flow", "router multicast6", "router ospf", 
                            "router ospf6", "router policy", "router policy6", "router prefix-list", "router prefix-list6", "router rip", "router ripng", "router route-map", 
                            "router setting", "router static6", "ssh-filter profile", "switch-controller.auto-config default", "switch-controller.initial-config template", 
                            "switch-controller.initial-config vlans", "switch-controller.security-policy 802-1X", "switch-controller dynamic-port-policy", 
                            "switch-controller fortilink-settings", "switch-controller global", "switch-controller lldp-profile", "switch-controller lldp-settings", 
                            "switch-controller location", "switch-controller mac-policy", "switch-controller managed-switch", "switch-controller network-monitor-settings",
                             "switch-controller snmp-community", "switch-controller stp-instance", "switch-controller stp-settings", "switch-controller switch-group", 
                             "switch-controller system", "switch-controller vlan-policy", "system.3g-modem custom", "system.autoupdate schedule", "system.autoupdate tunneling", 
                             "system.dhcp server", "system.dhcp6 server", "system.lldp network-policy", "system.replacemsg admin", "system.replacemsg alertmail", 
                             "system.replacemsg auth", "system.replacemsg automation", "system.replacemsg fortiguard-wf", "system.replacemsg ftp", "system.replacemsg http", 
                             "system.replacemsg icap", "system.replacemsg mail", "system.replacemsg nac-quar", "system.replacemsg sslvpn", "system.replacemsg traffic-quota",
                               "system.replacemsg utm", "system.snmp community", "system.snmp mib-view", "system.snmp sysinfo", "system.snmp user", "system alarm", 
                               "system arp-table", "system ddns", "system dedicated-mgmt", "system device-upgrade", "system dns", "system dns-database", "system dns-server", 
                               "system dns64", "system dscp-based-priority", "system email-server", "system evpn", "system external-resource", "system fabric-vpn", 
                               "system federated-upgrade", "system fips-cc", "system fortiguard", "system fortindr", "system fortisandbox", "system fsso-polling", 
                               "system ftm-push", "system geneve", "system gre-tunnel", "system ike", "system ipam", "system ipip-tunnel", "system ips", 
                               "system ips-urlfilter-dns", "system ips-urlfilter-dns6", "system ipsec-aggregate", "system ipv6-neighbor-cache", "system ipv6-tunnel",
                                 "system link-monitor", "system lte-modem", "system mac-address-table", "system mobile-tunnel", "system modem", "system nd-proxy",
                                   "system netflow", "system network-visibility", "system np6", "system npu", "system ntp", "system object-tagging", "system password-policy",
                            "system password-policy-guest-admin", "system pcp-server", "system pppoe-interface", "system probe-response", "system proxy-arp",
                              "system ptp", "system replacemsg-group", "system replacemsg-image", "system resource-limits", "system saml", "system sdn-connector",
                                "system sdn-proxy", "system sdwan", "system session-helper", "system session-ttl", "system sflow", "system sit-tunnel", 
                                "system smc-ntp", "system sms-server", "system speed-test-schedule", "system speed-test-server", "system speed-test-setting", 
                                "system ssh-config", "system sso-admin", "system sso-forticloud-admin", "system sso-fortigate-cloud-admin", "system storage",
                                  "system switch-interface", "system timezone", "system tos-based-priority", "system virtual-wire-pair", "system vne-tunnel",
                                    "system vxlan", "system wccp", "system zone", "videofilter profile", "videofilter youtube-channel-filter", 
                                    "videofilter youtube-key", "voip profile", "waf profile", "waf main-class", "wanopt auth-group", "wanopt cache-service", 
                                    "wanopt content-delivery-network-rule", "wanopt peer", "wanopt profile", "wanopt remote-storage", "wanopt settings",
                            "wanopt webcache", "web-proxy debug-url", "web-proxy explicit", "web-proxy forward-server", "web-proxy forward-server-group", 
                            "web-proxy global", "web-proxy profile", "web-proxy url-match", "web-proxy wisp", "webfilter content", 
                            "webfilter content-header", "webfilter ftgd-local-cat", "webfilter ftgd-local-rating", "webfilter ips-urlfilter-setting", 
                            "webfilter ips-urlfilter-setting6", "webfilter override", "webfilter urlfilter", "wireless-controller access-control-list",
                              "wireless-controller ap-status", "wireless-controller apcfg-profile", "wireless-controller arrp-profile", 
                              "wireless-controller ble-profile", "wireless-controller bonjour-profile", "wireless-controller log", 
                              "wireless-controller mpsk-profile", "wireless-controller nac-profile", "wireless-controller qos-profile",
                                "wireless-controller region", "wireless-controller setting", "wireless-controller snmp", 
                                "wireless-controller ssid-policy", "wireless-controller syslog-profile", "wireless-controller utm-profile",
                                  "wireless-controller vap", "wireless-controller vap-group", "wireless-controller wag-profile", 
                                  "wireless-controller wids-profile", "wireless-controller wtp", "wireless-controller wtp-group", 
                                  "wireless-controller wtp-profile", "application list", "dlp sensor", "file-filter profile", "firewall ssh", 
                                  "firewall wildcard-fqdn", "log fortiguard", "log memory", "sctp-filter profile", "system accprofile", "system acme",
                                    "system admin", "system alias", "system auto-install", "system auto-script", "system automation-action", 
                                    "system automation-destination", "system automation-stitch", "system automation-trigger", "system autoupdate", 
                                    "system central-management", "system console", "system csf", "system custom-language", "system replacemsg", 
                                    "system snmp", "webfilter search-engine", "user tacacs+", "user adgrp", "user certificate", "user domain-controller",
                                      "user exchange", "user external-identity-provider", "user fortitoken", "user fsso", "user fsso-polling", 
                                      "user krb-keytab", "user ldap", "user nac-policy", "user password-policy", "user peer", "user peergrp", "user pop3",
                                        "user quarantine", "user radius", "user saml", "user security-exempt-list", "user setting", "user local", 
                                        "user group", "firewall policy", "emailfilter fortishield", "emailfilter options", "endpoint-control fctems", 
                                        "firewall.ssh setting", "firewall ipv6-eh-filter", "firewall.ssl setting", "log.fortiguard filter", 
                                        "log.fortiguard setting", "log.memory filter", "log.memory setting", "log.fortianalyzer-cloud filter",
                                          "log.fortianalyzer-cloud setting", "log.fortianalyzer filter", "log.fortianalyzer setting",
                                            "log.fortianalyzer2 filter", "log.fortianalyzer2 setting", "log.fortianalyzer3 filter", 
                                            "log.fortianalyzer3 setting", "log.syslogd filter", "log.syslogd setting", "log.syslogd2 filter", 
                                            "log.syslogd2 setting", "log.syslogd3 filter", "log.syslogd3 setting", "log.syslogd4 filter",
                                              "log.syslogd4 setting", "log.webtrends filter", "log.webtrends setting", "log.disk filter", 
                                              "log.disk setting", "log.null-device filter", "log.null-device setting", "monitoring npu-hpe",
                               "webfilter fortiguard", "webfilter ips-urlfilter-cache-setting", "wireless-controller global",
                                 "wireless-controller inter-controller", "wireless-controller timers", "ips global", "firewall.shaper per",
                                   "firewall wildcard", "firewall ipv6", "firewall auth", "firewall multicast", "firewall profile",
                                     "firewall shaping", "firewall ssl", "firewall internet", "log gui", "log threat", "log fortianalyzer", 
                                     "log null", "monitoring npu", "router access", "router prefix", "router route", 
                                     "system.replacemsg fortiguard", "system.replacemsg nac", "system.replacemsg traffic", 
                                     "system dedicated", "system email", "system federated", "system fips", "system fsso", 
                                     "system ftm", "system lte", "system nd", "system network", "system object", "system password",
                                       "system vne", "system auto", "system automation", "system central", "system custom", "waf main", 
                                       "webfilter ips", "firewall.ssh local", "system virtual", 
                                       "wireless-controller.hotspot20 anqp-3gpp-cellular", 
                                       "wireless-controller.hotspot20 anqp-ip-address-type", 
                                       "wireless-controller.hotspot20 anqp-nai-realm", 
                                       "wireless-controller.hotspot20 anqp-network-auth-type",
                                         "wireless-controller.hotspot20 anqp-roaming-consortium", 
                                         "wireless-controller.hotspot20 anqp-venue-name", 
                              "wireless-controller.hotspot20 anqp-venue-url",
                                "wireless-controller.hotspot20 h2qp-advice-of-charge",
                                  "wireless-controller.hotspot20 h2qp-conn-capability",
                                    "wireless-controller.hotspot20 h2qp-operator-name", 
                                    "wireless-controller.hotspot20 h2qp-osu-provider",
                                      "wireless-controller.hotspot20 h2qp-osu-provider-nai", 
                                      "wireless-controller.hotspot20 h2qp-terms-and-conditions",
                                        "wireless-controller.hotspot20 h2qp-wan-metric", 
                                        "wireless-controller.hotspot20 hs-profile",
                                          "wireless-controller.hotspot20 icon", 
                                          "wireless-controller.hotspot20 qos-map",
                                            "wireless-controller access-control-list", 
                             "wireless-controller ap-status", "wireless-controller apcfg-profile",
                               "wireless-controller arrp-profile", "wireless-controller ble-profile",
                                 "wireless-controller bonjour-profile", "wireless-controller global",
                                   "wireless-controller inter-controller", "wireless-controller log",
                                     "wireless-controller mpsk-profile", "wireless-controller nac-profile",
                                       "wireless-controller qos-profile", "wireless-controller region",
                                         "wireless-controller setting", "wireless-controller snmp",
                                           "wireless-controller ssid-policy", "wireless-controller syslog-profile",
                                             "wireless-controller timers", "router static", 
                                             "wireless-controller utm-profile", "wireless-controller vap",
                            "wireless-controller vap-group", "wireless-controller wag-profile",
                              "wireless-controller wids-profile", "wireless-controller wtp", 
                              "wireless-controller wtp-group", "wireless-controller wtp-profile",
                                "system probe", "system session", "system sso"]
                                '''
            interface_type_order = ["physical", "aggregate", "none", "wifi", "tunnel", "virtual-wire", "loopback", "sd-wan"]
            #The below functions are mandatory for the right sorting of the references.
            # Function to determine the interface type from the value
            def get_interface_type(value):
                parts = value.split(separator)
                # Extract the last part as the interface type if it's valid
                if len(parts) > 1 and parts[-1] in interface_type_order:
                    return parts[-1]
                # Default to "none" for entries without a valid interface type
                return "none"
            # Function to assign a priority to each dict based on its key and value
            def sort_priority(d):
                key = next(iter(d.keys()))
                if key in custom_order:
                    key_priority = custom_order.index(key)
                else:
                    key_priority = len(custom_order)  # Other keys go last
                if key == "system interface":
                    value = d[key]
                    interface_type = get_interface_type(value)
                    type_priority = interface_type_order.index(interface_type)
                    return (key_priority, type_priority)  # Tuple for primary and secondary sorting    
                return (key_priority, len(interface_type_order))  # No secondary sort for other keys
            # Function to remove the separator and everything after it
            def remove_separator(data, separator):
                for item in data:
                    for key, value in item.items():
                        if isinstance(value, str) and separator in value:
                            # Keep only the part before the separator
                            item[key] = value.split(separator)[0]
                return data                     
            parameters ='with_meta=false&skip=true&exclude-default-values=true&plain-text-password=1&datasource=true'           
            #Begin examining references
            for initial_reference in initial_references:
                #Take every value of the initial_references and split the appropriate values (path,name,mkey)
                for key, value in initial_reference.items():
                    path, name = key.split(' ', 1)
                    mkey = value 
                    child_references = [] 
                    #take the config of the initial referece, see if it has references
                    config = fortigate.api.get(path=path, name=name, parameters=parameters, vdom=vdom, mkey=mkey).get('results', [])
                    conf = fortigate.config_filtering(config=config,references_flag=True)
                    references= self.check_references(conf)
                    if references:       
                        #add the reference to a list
                        child_references.extend(references)  
                    #add the initial reference
                    temp_references.append(initial_reference) 
                    #for every child reference to the same thing                                    
                    for ref in child_references:
                        for key, value in ref.items():
                                path, name = key.split(' ', 1)
                                mkey = value
                                config = fortigate.api.get(path=path, name=name, parameters=parameters, vdom=vdom, mkey=mkey).get('results', [])
                                conf = fortigate.config_filtering(config=config,references_flag=True)
                                references= self.check_references(conf)
                                if references:
                                    child_references.extend(references) 
                #Before child references get delete, copy variables to a temp list
                temp_references.extend(child_references)                                           
            child_references = temp_references
            #Remove duplicates
            child_references = list({frozenset(d.items()): d for d in child_references}.values())
            #A loop that takes all the interface references, adds a separator that uniqely identifies the value and can be sorted with the interface_type_order
            for ref in child_references:
                for key, value in ref.items():
                    path, name = key.split(' ', 1)
                    mkey = value  
                    intf_type=""
                    if path =="system" and name == "interface":
                        config = fortigate.api.get(path=path, name=name, parameters=parameters, vdom=vdom, mkey=mkey).get('results', [])   
                        for conf in config:
                            if 'type' in conf:
                                intf_type=conf["type"]
                                ref[key] = f'{value}{separator}{intf_type}'
            #sort the refferences accordingly using the custom_order and the interface_type_order
            sorted_list = sorted(child_references, key=sort_priority)
            #removing the separator in order for the objects to be sent
            remove_separator(sorted_list,separator)
            #For all references, fetch and send the configuration.
            for ref in sorted_list:
                                for key, value in ref.items():
                                        path, name = key.split(' ', 1)
                                        mkey = value                         
                                        config = fortigate.api.get(path=path, name=name, parameters=parameters, vdom=vdom, mkey=mkey).get('results', [])
                                        conf = fortigate.config_filtering(config=config,references_flag=True,interface_translations=interface_translations,path=path,name=name)
                                        parameters ='with_meta=false&skip=true&exclude-default-values=true&plain-text-password=1&datasource=true'
                                        for old,new in interface_translations.items():
                                            if old==mkey:
                                                mkey=new
                                        if len(conf)>=1:
                                            if  'type' in conf[0] and 'interface' in conf[0]:
                                                #If there are vpn interfaces, get and send phase1 and phase 2 configuration.
                                                if path=="system" and name=="interface" and conf[0]["type"]=="tunnel" and conf[0]["interface"]["datasource"]=="system.interface":       
                                                            path="vpn.ipsec"
                                                            name="phase1-interface"
                                                            config = fortigate.api.get(path=path, name=name, parameters=parameters, vdom=vdom, mkey=mkey).get('results', [])
                                                            conf = fortigate.config_filtering(config=config,references_flag=True,interface_translations=interface_translations,path=path,name=name)
                                                            self.send_configuration(path, name,conf)
                                                            path="vpn.ipsec"
                                                            name="phase2-interface"
                                                            mkey=""
                                                            config = fortigate.api.get(path=path, name=name, parameters=parameters, vdom=vdom, mkey=mkey).get('results', [])
                                                            conf = fortigate.config_filtering(config=config,references_flag=True,interface_translations=interface_translations,path=path,name=name)
                                                            for phase2 in conf:
                                                                if phase2["phase1name"]["name"] == value:
                                                                    phase2_object = phase2.copy()
                                                                    if isinstance(phase2_object, list):
                                                                        pass
                                                                    else:
                                                                        phase2_object = [phase2_object]
                                                                    self.send_configuration(path, name,phase2_object)
                                            else:
                                                #When creating interfaces through API, it does not auto create interface addresses.
                                                if (path=="system" and name=="interface") and ('ip' in conf[0]):
                                                        intf_addr = [{
                                                            "name": f'{mkey} address',
                                                            "q_origin_key": f'{mkey} address',
                                                            "css-class": "ftnt-address ftnt-color-0",
                                                            "subnet": f'{conf[0]['ip']}',
                                                            "type": "interface-subnet",
                                                            "interface": {
                                                                "q_origin_key": f'{mkey}',
                                                                "name": f'{mkey}'}
                                                        }]
                                                        self.send_configuration(path, name,conf)
                                                        path="firewall"
                                                        name="address"    
                                                        self.send_configuration(path, name,intf_addr)
                                                else:
                                                    self.send_configuration(path, name,conf)
        except EOFError:
            exit()
        except KeyboardInterrupt:
            exit()                   

    def send_object(self,json_filename, section_name,fortigate,functionality,src_host,dst_host):
        global sequence
        sequence=1
        try:
            #The object that will be sent
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
                except TypeError:
                    print("Invalid option.")
                    vdom = None  
                    continue  
                except ValueError:
                    print("Invalid option.")
                    json_filename = None 
                    continue 
                else:
                    print(f"Selected vdom: {vdoms[int(vdom)-1]}")
                    vdom = vdoms[int(vdom)-1]
                    if functionality ==2:
                        print("Checking object dependencies..")
                        initial_references = self.check_references(data)
                        print("Checking if the object has interface dependencies..")
                        interface_translations = self.process_interface_references(initial_references,vdom,fortigate,src_host,dst_host)
                        print(f'Dependencies completed. Processing..')
                        self.process_references(initial_references, vdom,fortigate,interface_translations)
                        print("Process completed. Copying Object. \n")
                        #Interface translation to the actual object
                        if interface_translations:
                            for source_intf,dst_intf in interface_translations.items():
                                search_value = source_intf
                                replace_value = dst_intf
                                updated_config = self.global_replace(data, search_value, replace_value)   
                                data = updated_config
                        self.config_filtering(path=path,name=name,config=data,references_flag=True)
                        self.send_configuration(path,name,data)
                        print("Action completed. Please check the logs for further details.")
                        break
                    if functionality ==1:
                        self.send_configuration(path,name,data)
        except EOFError:
            exit()
        except KeyboardInterrupt:
            exit()
        except JSONDecodeError:
            print("Could not decode the specified JSON file.")

    def download_config(self,fortigate_ip, vdom_to_download, access_token):
        try:
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
        except EOFError:
            exit()
        except KeyboardInterrupt:
            exit()      

    def upload_config(self,file_path,fortigate_ip,vdom):
        try:
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
        except EOFError:
            exit()
        except KeyboardInterrupt:
            exit()      

    def rename_interface(self):
        try:
            print("Warning! This requires the fortigate configuration file since it will modify it accordingly. Be sure to double check the results before upload it.")
            current_directory = os.getcwd()
            all_files = os.listdir(current_directory)
            config_files = [file for file in all_files if file.endswith('.conf')]
            print("\n\nFound the below fortigate configuration files. \n ")
            num=1
            for file in config_files:
                print(f'{num} - {file}')  
                num+=1
            conf_filename = None
            while conf_filename is None:
                try:
                    conf_filename = int(input("\n\nEnter the configuration file number to modify (or '0' to quit): "))
                    if conf_filename == 0:
                            print("\n")
                            break 
                    if (conf_filename) < 1 or (conf_filename)>len(config_files):
                        print("Please select a valid option.")         
                        conf_filename = None  
                except EOFError:
                    exit()                                                  
                except:
                    print("Invalid option.")
                    conf_filename = None        
                else:
                    if conf_filename is not None:
                        print(f"Selected file: {config_files[conf_filename-1]}")
                        conf_filename=config_files[conf_filename-1]
                        while True:
                                found = False
                                old_interface_name = input("Please enter the old interface name: ")
                                config_name = f'edit "{old_interface_name}"'
                                with open(conf_filename, "r") as file:
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
                                            r'^\s*edit\s+("{})?\s*address"\s*$'.format(re.escape(old_interface_name)),
                                            r'(^\s*set associated-interface\s+"{}"\s*$)'.format(re.escape(old_interface_name)),
                                            r'(^\s*set device\s+"{}"\s*$)'.format(re.escape(old_interface_name)),
                                        ]

                                        # Compile all patterns into a single regex
                                        compiled_patterns = re.compile('|'.join(patterns))

                                        # Read the configuration file line by line and modify as necessary
                                        with open(conf_filename, "r",encoding="utf-8") as file:
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
                                        json_filename_split = conf_filename.split(".")[0]
                                        with open(f'{json_filename_split}_modified.conf', "w",encoding="utf-8",newline='\n') as file:
                                            file.writelines(modified_lines)
                                        print(f"Interface name replacement completed. Modified configuration saved to {f'{json_filename_split}_modified.conf'}\n")
                                        break                               
                                    if is_right =='n':
                                        break   
                                if found==False:
                                    print("Interface name not found. Please check.")
        except EOFError:
            exit()
        except KeyboardInterrupt:
            exit()      

    def renumber_fw_rules(self):
        try:
            parameters =  'with_meta=false&skip=true&exclude-default-values=true' 
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
                    if (vdom) < 1 or vdom > len(vdoms):
                        print("Invalid section number.")
                        vdom = None
                    else:
                        print(f"Selected vdom: {vdoms[int(vdom)-1]}")
                        vdom = vdoms[int(vdom)-1]
                except EOFError:
                    exit() 
                except TypeError:
                    print("Invalid option.")
                    vdom = None  
                    continue  
                except ValueError:
                    print("Invalid option.")
                    vdom = None 
                    continue 
            fw_rules = self.api.get(path="firewall", name="policy",parameters=parameters,vdom=vdom).get('results', []) 
            with open("backup.json", 'w') as backup:
                    json.dump(fw_rules, backup, indent=4)
            new_policies = copy.deepcopy(fw_rules)
            original_policyid = []
            renumber = int(input("Enter the value that the policy ids will start: "))
            for i, fw_rule in enumerate(new_policies, start=renumber): 
                    fw_rule["policyid"] = i
                    fw_rule["q_origin_key"] = i
            for fw_rule in fw_rules:
                original_policyid.append(fw_rule["policyid"]) 
            for old_policy_id in original_policyid:
                del_fw_rule = self.api.delete(path="firewall", name="policy", parameters=parameters,vdom=vdom,mkey=old_policy_id)
            #Post the new rules with new IDs
            for new_policy_id in new_policies:
                response = self.api.post(path="firewall", name="policy", data=new_policy_id)
        except EOFError:
            exit()
        except KeyboardInterrupt:
            exit()      

    def renumber_fw_rules_live(self):
        try:
            parameters =  'with_meta=false&skip=true&exclude-default-values=true' 
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
                    if (vdom) < 1 or vdom > len(vdoms):
                        print("Invalid section number.")
                        vdom = None
                    else:
                        print(f"Selected vdom: {vdoms[int(vdom)-1]}")
                        vdom = vdoms[int(vdom)-1]
                except EOFError:
                    exit() 
                except TypeError:
                    print("Invalid option.")
                    vdom = None  
                    continue  
                except ValueError:
                    print("Invalid option.")
                    vdom = None 
                    continue 
            fw_rules = self.api.get(path="firewall", name="policy",parameters=parameters,vdom=vdom).get('results', []) 
            with open("backup.json", 'w') as backup:
                    json.dump(fw_rules, backup, indent=4)
            new_policies = copy.deepcopy(fw_rules)
            temp_new_policies = copy.deepcopy(fw_rules)
            original_policyid = []
            modified_policyid = []
            max_policy_id = max(fw_rules, key=lambda x: x['policyid'])['policyid']
            if max_policy_id + max_policy_id +1 >= 4294967293:
                print("Cannot use this method because the numbers exceeds the maximum policy id number.")
            else:
                for fw_rule in temp_new_policies:
                    original_policyid.append(fw_rule["policyid"]) 
                    fw_rule["policyid"] = fw_rule["policyid"] + max_policy_id
                    fw_rule["q_origin_key"] = fw_rule["policyid"] + max_policy_id
                    if "name" in fw_rule:
                        fw_rule["name"] = f'{fw_rule["name"]}_temp'
                    modified_policyid.append(fw_rule["policyid"])
                renumber = int(input("Enter the value that the policy ids will start: "))
                #Post temp new policies
                print("Applying the temporary new rules...")
                for temp_new_policy in temp_new_policies:
                        add_fw_rule = self.api.post(path="firewall", name="policy", data=temp_new_policy) 
                #Delete the old rules
                print("Deleting the old rules...")
                for old_policy_id in original_policyid:
                        del_fw_rule = self.api.delete(path="firewall", name="policy", parameters=parameters,vdom=vdom,mkey=old_policy_id)
                for i, fw_rule in enumerate(new_policies, start=renumber): 
                        fw_rule["policyid"] = i
                        fw_rule["q_origin_key"] = i
                #Post the new rules with new IDs
                print("Applying the rules with the desired numbering...")
                for new_policy_id in new_policies:
                        add_fw_rule = self.api.post(path="firewall", name="policy", data=new_policy_id)
                #Delete the new temp rules
                print("Deleting the temporary rules...")
                for temp_new_policy in modified_policyid:
                        del_fw_rule = self.api.delete(path="firewall", name="policy", parameters=parameters,vdom=vdom,mkey=temp_new_policy)
        except EOFError:
            exit()
        except KeyboardInterrupt:
            exit()      

def main():
    def start_screen():
        print("\033c", end="")    
        print("\nWelcome!")
        print("This tool helps manage and automate tasks for Fortigate devices.")
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
                        sys.exit()
                    set_info = int(input("Destination: "))
                    if set_info == 0:
                        sys.exit()
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
        src_host = src_info["host"]
        if functionality == 1:
            dst_fortigate = fortigate
        def configuration_sections():
                try:
                    section_name = fortigate.print_config_sections()
                    if section_name!="exit":
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
                                    fortigate.get_config(section_name=section_name,migration_flag=migration_flag,vdom=vdom,functionality=functionality,src_host=src_host)
                                    while True:
                                        print("\nSelected Section Options:")
                                        print("1 - Send JSON file to FortiGate")
                                        print("2 - Delete object on Fortigate")
                                        print("0 - Back to main menu")
                                        section_option = input("Enter your choice: ")
                                        if section_option == '1':
                                            current_directory = os.getcwd()
                                            all_files = os.listdir(current_directory)
                                            config_files = [file for file in all_files if file.endswith('.json')]
                                            print("\n\nFound the below JSON configuration files. \n ")
                                            num=1
                                            for file in config_files:
                                                print(f'{num} - {file}')
                                                num+=1
                                            json_filename = None
                                            while json_filename is None:
                                                try:
                                                    json_filename = int(input("\n\nEnter the JSON file number to send (or '0' to quit): "))
                                                    if json_filename == 0:
                                                            break 
                                                    if (json_filename<1):
                                                        print("Please select a valid option.")         
                                                        json_filename = None 
                                                        continue 
                                                    if json_filename>len(config_files):
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
                                                            dst_fortigate.send_object(config_files[json_filename-1], section_name,fortigate,functionality,src_host,dst_info["host"])
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
                                            config_files = [file for file in all_files if file.endswith('.json')]
                                            print("\n\nFound the below JSON configuration files. \n ")
                                            num=1
                                            for file in config_files:
                                                print(f'{num} - {file}')
                                                num+=1
                                            json_filename = None
                                            while json_filename is None:
                                                try:
                                                    json_filename = int(input("\n\nEnter the JSON file number to delete (or '0' to quit): "))
                                                    if json_filename == 0:
                                                            print("\n")
                                                            break 
                                                    if (json_filename<1):
                                                        print("Please select a valid option.")         
                                                        json_filename = None 
                                                        continue 
                                                    if json_filename>len(config_files):
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
                            except ValueError:
                                print("Invalid choice.")
                                vdom = None
                                continue
                except EOFError:
                    exit()
        try:
            while True:
                if functionality == 1:
                    print(f"Connected to {src_host} ")
                    print("\nSelect an option:")
                    print("1 - Enter device configuration sections")
                    print("2 - Check Multi-VDOM option")
                    print("3 - Rename Fortigate interfaces")
                    print("4 - Configuration Download")
                    print("5 - Configuration Upload")
                    print("6 - Renumber Firewall Rules")
                    print("0 - Exit")
                if functionality == 2:
                    print(f"Connected to {src_host} as source and to {dst_info["host"]} as destination.")
                    print("\nSelect an option:")
                    print("1 - Transfer configuration from source Fortigate device")
                    print("2 - Migrate from source Fortigate device")
                    print("0 - Exit")
                choice = input("Enter your choice: ")
                if functionality == 1:
                    if choice == '1':
                        configuration_sections()
                    elif choice == '2':
                        if functionality==1:
                            dst_fortigate.vdom_functionality(info_file,functionality)
                        else:
                            print("This is only available when one fortigate device has been selected.\n")  
                    elif choice == '3':
                        if functionality==1:
                            print("\n")
                            print("1 - Rename Fortigate interfaces(alias)")
                            print("2 - Rename Fortigate interface(altering .conf file)")
                            user_choice = None 
                            while user_choice is None:
                                try:
                                    user_choice = int(input("Please select an option (or '0' to quit): "))
                                    if user_choice == 1:
                                        if functionality == 1:
                                            dst_fortigate.rename_interface_alias()
                                        else:
                                            print("This is only allowed when one fortigate selected.\n")
                                    elif user_choice == 2:
                                        if functionality == 1:
                                            print("THIS FUNCTION IS STILL UNDER DEVELOPMENT. USE IT AT YOUR OWN RISK")
                                            fortigate.rename_interface()
                                        else:
                                            print("This is only allowed when one fortigate selected.\n")
                                    elif user_choice == 0:
                                        print("\033c", end="")
                                        break
                                    else:
                                        print("Invalid choice.")
                                        user_choice = None
                                except ValueError:
                                    print("Invalid choice.")
                                    user_choice = None
                        else:
                            print("This is only available when one fortigate device has been selected.\n")  

                    elif choice =='4':
                        if functionality==1:
                            print("Warning! Required rw permissions on System. Then it depends on other permissions, what configuration you will get.")
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
                                                vdom = vdoms[vdom_to_download-1]
                                                dst_fortigate.download_config(fortigate_ip, vdom,access_token)
                                                break
                                            if answer=='n':
                                                break
                                            else:
                                                print("Invald option.")                              

                        else:
                            print("This is only available when one fortigate device has been selected.\n")  
                    elif choice =='5':  
                        if functionality==1:         
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
                                        exit() 
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
                    elif choice =="6":
                        if functionality==1:
                            print("\n")
                            print("1 - Renumber firewall rules on a fortigate that it is not in production.")
                            print("2 - Renumber firewall rules on a fortigate that it is in production.")
                            user_choice = None 
                            while user_choice is None:
                                try:
                                    user_choice = int(input("Please select an option (or '0' to quit): "))
                                    if user_choice == 1:
                                            fortigate.renumber_fw_rules()
                                    elif user_choice == 2:
                                            print("USE IT AT YOUR OWN RISK.")
                                            print("This function creates another set of the same rules while renumbering the original ones.")
                                            fortigate.renumber_fw_rules_live()
                                    elif user_choice == 0:
                                        print("\033c", end="")
                                        break
                                    else:
                                        print("Invalid choice.")
                                        user_choice = None
                                except ValueError:
                                    print("Invalid choice.")
                                    user_choice = None                      
                        else:
                            print("This is only available when one fortigate device has been selected.\n") 
                    elif choice == '0':
                        break
                    else:
                        print("Invalid choice. Please try again.")
                elif functionality==2:
                    if choice == '1':
                        configuration_sections()            
                    elif choice =='2':
                        if functionality == 1:
                            print("This is only allowed when two fortigates are selected.\n")
                        else:
                            dst_fortigate.migrate(info_file=info_file,set_info_file=set_info_file,fortigate=fortigate, dst_fortigate=dst_fortigate)       
                    elif choice == '0':
                        break
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