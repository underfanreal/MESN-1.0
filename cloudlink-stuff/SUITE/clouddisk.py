#!/usr/bin/env python3

# CloudLink 3.0 - CloudDisk

from cloudlink import CloudLink
import time
import os
import json
import sys
from disk import filesysapi

userlist = []
old_userlist = ["%CD%"]
auths = {}
fsapi = filesysapi()

def packetHandler(cmd, val, origin):
    # Requisite commands for authentication / networking utilities
    if cmd == "ping":
        try:
            cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "pong", "origin": "%CD%"})
        except Exception as e:
            print("[ ! ] Error: {0}".format(e))
            cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CD%"})
    
    if cmd == "returntoken":
        try:
            id = val["id"]
            if val == "ERR":
                cl.sendPacket({"cmd": "pmsg", "id":id, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CD%"})
            else:
                cl.sendPacket({"cmd": "pmsg", "id":id, "val": json.dumps({"authed": str(val["val"])}), "origin": "%CD%"})
                auths[id]["valid"] = bool(val["val"])
                if bool(val["val"]):
                    print("[ i ] Adding {0} to auths".format(id))
        except Exception as e:
            print("[ ! ] Error: {0}".format(e))
            cl.sendPacket({"cmd": "pmsg", "id":id, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CD%"})
    
    if cmd == "checkauth":
        try:
            if origin in auths:
                cl.sendPacket({"cmd": "pmsg", "id":origin, "val": json.dumps({"authed": str(auths[origin]["valid"])}), "origin": "%CD%"})
            else:
                cl.sendPacket({"cmd": "pmsg", "id":origin, "val": json.dumps({"authed": "False"}), "origin": "%CD%"})
        except Exception as e:
            print("[ ! ] Error: {0}".format(e))
            cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CD%"})
    
    if cmd == "auth":
        global userlist
        try:
            if "%CA%" in userlist:
                if not origin in auths:
                    auths[origin] = {"token": val, "valid": False}
                    cl.sendPacket({"cmd": "verifytoken", "id":"%CA%", "val": {"origin": origin, "token": val}, "origin": "%CD%"})
                else:
                    if not auths[origin]["valid"]:
                        auths[origin] = {"token": val, "valid": False}
                        cl.sendPacket({"cmd": "verifytoken", "id":"%CA%", "val": {"origin": origin, "token": val}, "origin": "%CD%"})
                    else:
                        cl.sendPacket({"cmd": "pmsg", "id":origin, "val": json.dumps({"authed": "True"}), "origin": "%CD%"})
            else:
                cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:AUTH_DOWN", "origin": "%CD%"})
        except Exception as e:
            print("[ ! ] Error: {0}".format(e))
            cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CD%"})
    
    if cmd == "deauth":
        try:
            if origin in auths:
                del auths[origin]
                print("[ i ] Removing {0} from auths".format(origin))
                cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "OK", "origin": "%CD%"})
        except Exception as e:
            print("[ ! ] Error: {0}".format(e))
            cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CD%"})

    # Custom commands for this appserver
    
    if cmd == "getftpdir":
        if (origin in auths) and (auths[origin]["valid"]):
            try:
                result, ddata = fsapi.lsdir(val)
                read_directory(val, ddata)
                if result:
                    cl.sendPacket({"cmd": "pmsg", "id":origin, "val": ddata, "origin": "%CD%"})
                else:
                    cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CD%"})
            except Exception as e:
                print("[ ! ] Error: {0}".format(e))
                cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CD%"})
        else:
            cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:NOT_AUTHED", "origin": "%CD%"})
    
    if cmd == "getftpfile":
        if (origin in auths) and (auths[origin]["valid"]):
            try:
                result, ddata = fsapi.read(val)
                ddata = str(ddata)
                
                if result:
                    cl.sendPacket({"cmd": "pmsg", "id":origin, "val": ddata, "origin": "%CD%"})
                else:
                    cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CD%"})
            except Exception as e:
                print("[ ! ] Error: {0}".format(e))
                cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CD%"})
        else:
            cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:NOT_AUTHED", "origin": "%CD%"})
            
    if cmd == "putftp":
        # Check if the user is authenticated
        if (origin in auths) and (auths[origin]["valid"]):
            # Check if the val dict has the correct keys
            if ("dir" in val) and ("filename" in val) and ("data" in val):
                try:
                    print("[ i ] Storing '" + str(val["filename"]) + "' in directory '" + str(val["dir"]) + "', storing " + str(len(str(val["data"]))) + " bytes")
                    result = fsapi.write(fdir = val["dir"], fname = val["filename"], data = val["data"])
                    if result:
                        cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "OK", "origin": "%CD%"})
                    else:
                        cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:SAVE_ERR", "origin": "%CD%"})
                except Exception as e:
                    print("[ ! ] Error: {0}".format(e))
                    cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CD%"})
            else:
                cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:MISSING_PARAMS", "origin": "%CD%"})
        else:
            cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:NOT_AUTHED", "origin": "%CD%"})
    
    if cmd == "ftpmkdir":
        if (origin in auths) and (auths[origin]["valid"]):
            try:
                result = fsapi.mkdir(val)
                if result:
                    cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "OK", "origin": "%CD%"})
                else:
                    cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:MKDIR_ERR", "origin": "%CD%"})
            except Exception as e:
                print("[ ! ] Error: {0}".format(e))
                cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CD%"})
        else:
            cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:NOT_AUTHED", "origin": "%CD%"})

def read_directory(directory, items):
    # If a blank directory is used assume the root
    if directory == "":
        directory = "/"
    print("[ i ] Listing directory {0}".format(directory))
    #print(directory, items)
    # Hide the security.json file if present in the directory
    if "SECURITY.json" in items:
        items.remove("SECURITY.json")
    
    # Read the directory and hide files
    hidden = []
    for item in items:
        # Read output of directory and filetypes
        # Check if a directory contains a security.json file
        result, dtype = fsapi.chktype(directory, item)
        #print(item, dtype)
        if dtype == 2:
            #print("A", (directory + item))
            result2, ddata2 = fsapi.lsdir(directory + "/" + item)
            if result2:
                #print("B", ddata2)
                if "SECURITY.json" in ddata2:
                    #print("C", (directory + "/" + item + "/SECURITY.json"))
                    result3, ddata3 = fsapi.read(directory + "/" + item + "/SECURITY.json")
                    try:
                        ddata3 = json.loads(ddata3)
                        #print("D", (result3, ddata3))
                        # Hide the directory from readback if the isHidden param is present and true
                        if "isHidden" in ddata3:
                            if ddata3["isHidden"]:
                                hidden.append(item)
                                print("[ i ] Hiding DIR", item)
                    except:
                        print("[ i ] Parse error while reading security.json in '{0}'. Checking if it's already JSON...".format(directory + "/" + item))
                        if type(ddata3) == dict:
                            print("[ i ] Looks like it's already JSON.")
                            #print("D", (result3, ddata3))
                            if ddata3["isHidden"]:
                                hidden.append(item)
                                print("[ i ] Hiding DIR", item)
                        else:
                            print("[ i ] It's not JSON. it's {0}".format(type(ddata3)))
                            #print("D", ddata3)
                            print("[ i ] Since the security.json file is invalid, assuming the directory is hidden.")
                            hidden.append(item)
                    
    #print(hidden)
    for item in hidden:
        if item in items:
            items.remove(item)

def on_new_packet(message):
    print(message)
    if message["cmd"] == "pmsg":
        try:
            cmd = json.loads(message["val"])["cmd"]
            if "val" in json.loads(message["val"]):
                val = json.loads(message["val"])["val"]
            else:
                val = ""
            origin = message["origin"]
            packetHandler(cmd, val, origin)
        except Exception as e:
            print("[ ! ] Error! {0}".format(e))
            cmd = ""
            data = ""
            origin = ""
    
    elif message["cmd"] == "direct":
        if message["val"]["cmd"] == "vers":
            print("[ i ] Server version: {0}".format(message["val"]["val"]))
        elif message["val"]["cmd"] == "motd":
            print("[ i ] Server MOTD: {0}".format(message["val"]["val"]))
    
    elif message["cmd"] == "ulist":
        global old_userlist, userlist
        userlist = message["val"].split(";")
        del userlist[-1]
        for id in old_userlist:
            if not id in userlist:
                if id in auths:
                    del auths[id]
                    print("[ i ] Removing {0} from auths".format(id))
        old_userlist = userlist
    
    else:
        cmdlist = ["clear", "setid", "gmsg", "pmsg", "gvar", "pvar", "ds", "ulist"]
        if ("cmd" in message) and ("val" in message) and ("origin" in message):
            if not message["cmd"] in cmdlist:
                packetHandler(message["cmd"], message["val"], message["origin"])

def on_connect():
    cl.sendPacket({"cmd": "setid", "val": "%CD%"})
    print("[ i ] Connected to main link.")

def on_error(error):
    print(error)

def init_files():
    try:
        os.mkdir("./DISK") # Create directory for CloudDisk
    except:
        pass
    try:
        os.mkdir("./DISK/FTP") # Create a directory for FTP data
    except:
        pass
    try:
        os.mkdir("./DISK/SLOTS") # Create a directory for save slot data
    except:
        pass
    print("[ i ] Initialized files.")

if __name__ == "__main__":
    init_files() # Initialize the directory
    try:
        cl = CloudLink() # instanciate the CloudLink module
        cl.client("ws://127.0.0.1:3000", on_new_packet = on_new_packet, on_connect = on_connect, on_error = on_error) #define callbacks, and connect to server
        while cl.mode == 2:
            pass 
        del cl

    except KeyboardInterrupt:
        cl.stop() # Stops the client and exits
        sys.exit()