#!/usr/bin/env python3

# CloudLink 3.0 - CloudAccount

from cloudlink import CloudLink
from scratch2py import Scratch2Py
import time
import os
import json
import sys
from hashlib import sha256

linked_to_auth = False
userlist = []
old_userlist = ["%CA%"]

try: # Import token generator
    from token_gen import gen_key
    from token_gen import gen_token
    print("[ i ] Imported token generator.")
except:
    print("[ ! ] Failed to import token generator!")
    sys.exit()

try: # Authenticate session for use with verifying Scratchers using 2-Factor Authentication
    global s2py
    s2py = Scratch2Py(str(input("Enter a Scratch username: ")), str(input("Enter your password: ")))
    print("[ i ] Session ready.")
except Exception as e:
    print("[ ! ] Session error! {0}".format(e))
    sys.exit()

def packetHandler(cmd, data, origin):
    if cmd == "ping":
        try:
            cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "pong", "origin": "%CA%"})
        except Exception as e:
            print("[ ! ] Error: {0}".format(e))
            cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CA%"})
    
    if cmd == "auth":
        try:
            authenticate({"mode": "pswd", "key": data, "origin": origin})
        except Exception as e:
            print("[ ! ] Error: {0}".format(e))
            cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CA%"})
    
    if cmd == "verifytoken": # for CloudLink Suite
        try:
            id = data["origin"]
            print("[ i ] Service checking token for user {0}".format(id))
            result = ((userExists(id) and userAuthed(id)) and (str(readUserFile(str(id))['latestToken']) == data["token"]))
            cl.sendPacket({'cmd': "returntoken", "val": {"id": id, "val": result}, "id": origin, "origin": "%CA%"})
        except Exception as e: 
            print("[ ! ] Error: {0}".format(e))
            cl.sendPacket({'cmd': "returntoken", "val": {"id": id, "val": "ERR"}, "id": origin, "origin": "%CA%"})
        
    if cmd == "auth2fa": # create a key, store it into tokencache, send key to user to use in the authenticator
        fresh_key_gen = False
        keys = os.listdir("./ACCOUNT/TOKENCACHE")
        while fresh_key_gen == False:
            key = gen_key()
            fresh_key_gen = "{0}.key".format(str(key)) not in keys
        cl.sendPacket({"cmd": "pmsg", "id":origin, "val": json.dumps({'key': str(key)}), "origin": "%CA%"})
        token_tmp = open("./ACCOUNT/TOKENCACHE/{0}.key".format(str(key)), "w")
        token_tmp.write(str(origin))
        token_tmp.close()
    
    if cmd == "deauth":
        if userExists(str(origin)):
            if userAuthed(str(origin)):
                try:
                    pswd = str(readUserFile(str(origin))['pswd'])
                    writeUserFile(str(origin), {"isAuth": False, "latestToken": "", "pswd": pswd})
                    cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "OK", "origin": "%CA%"})
                    print("[ i ] {0} has been deauthed.".format(origin))
                except Exception as e:
                    print("[ ! ] Error: {0}".format(e))
                    cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CA%"})
            else:
                print(origin, "is not authed")
                cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "OK", "origin": "%CA%"})
        else:
            print(origin, "does not exist")
    
    if cmd == "checkauth":
        try:
            if userExists(origin):
                cl.sendPacket({"cmd": "pmsg", "id":origin, "val": json.dumps({'exists': True, 'authed': userAuthed(origin)}), "origin": "%CA%"})
            else:
                cl.sendPacket({"cmd": "pmsg", "id":origin, "val": json.dumps({'exists': False}), "origin": "%CA%"})
        except Exception as e:
            print("[ ! ] Error: {0}".format(e))
            cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CA%"})
    
    if cmd == "checkkeys":
        if not userAuthed(origin):
            print("[ i ] Fetching auth data...")
            try:
                global session, s2py
                authData = session.readCloudVar("AUTH", 10)
                userKeyCheck = False
                if authData == "Sorry, there was an error.":
                    print("[ ! ] Authenticator fetch error.")
                    cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CA%"})
                    userKeyCheck = True
                else:
                    for item in authData:
                        try:
                            worked = authenticate({"mode": "2fa", "key": item['value'], "user": item['user'], "origin": origin})
                            if worked == "authed":
                                return
                            else:
                                if not worked: # Only becomes a false value if the authentication fails due to username missmatch
                                    userKeyCheck = True
                                else:
                                    if not userKeyCheck:
                                        userKeyCheck = userAuthed(origin)
                        except Exception as e: 
                            print("[ ! ] Error: {0}".format(e))
                            cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CA%"})
                            return
                    if not userKeyCheck:
                        cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:RETRY", "origin": "%CA%"})
            except Exception as e:
                print("[ ! ] Error: {0}".format(e))
                cl.sendPacket({"cmd": "pmsg", "id":origin, "val": "E:INTERNAL_SERVER_ERR", "origin": "%CA%"})

def on_new_packet(message): # message value is automatically converted into a dictionary datatype
    print(message)
    if message["cmd"] == "pmsg":
        try:
            cmd = json.loads(message["val"])["cmd"]
            if "val" in json.loads(message["val"]):
                data = json.loads(message["val"])["val"]
            else:
                data = ""
            origin = message["origin"]
            packetHandler(cmd, data, origin)
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
        global userlist, old_userlist
        userlist = message["val"].split(";")
        del userlist[-1]
        #print(userlist)
        for id in old_userlist:
            if not id in userlist:
                if userExists(id) and userAuthed(id):
                    writeUserFile(id, {"isAuth": False, "latestToken": "", "pswd": readUserFile(id)['pswd']})
                    print("[ i ] {0} has been deauthed.".format(id))
        old_userlist = userlist
    
    else:
        cmdlist = ["clear", "setid", "gmsg", "pmsg", "gvar", "pvar", "ds", "ulist"]
        if ("cmd" in message) and ("val" in message) and ("origin" in message):
            if not message["cmd"] in cmdlist:
                packetHandler(message["cmd"], message["val"], message["origin"])

def on_connect():
    cl.sendPacket({"cmd": "setid", "val": "%CA%"})
    global linked_to_auth
    if not linked_to_auth:
        print("[ i ] Connected to main link, trying to connect to authenticator...")
        try:
            global session, s2py
            session = s2py.scratchConnect("561076533")
            print("[ i ] Session connected to authenticator.")
            linked_to_auth = True
        except Exception as e:
            print("[ ! ] Error: {0}".format(e))
            cl.stop()
            sys.exit()
    else:
        print("[ i ] Restored connection.")

def authenticate(args):
    if args["mode"] == "2fa":
        if "key" in args:
            if "{0}.key".format(args["key"]) in os.listdir("./ACCOUNT/TOKENCACHE"):
                origin = open("./ACCOUNT/TOKENCACHE/{0}.key".format(args["key"])).read()
                os.remove("./ACCOUNT/TOKENCACHE/{0}.key".format(args["key"]))
                if args["origin"] == args["user"]:
                    fresh_token_gen = False
                    tokens = os.listdir("./ACCOUNT/TOKENCACHE")
                    while fresh_token_gen == False:
                        token = gen_token()
                        fresh_token_gen = "{0}.token".format(str(token)) not in tokens
                    cl.sendPacket({"cmd": "pmsg", "id":args["origin"], "val": json.dumps({'token': str(token)}), "origin": "%CA%"})
                    pswd = readUserFile(args['origin'])['pswd']
                    writeUserFile(str(args["origin"]), {"isAuth": True, "latestToken": str(token), 'pswd': pswd})
                    print("[ i ] {0} has been authed using 2-Factor Authentication.".format(str(args["origin"])))
                    return "authed"
                else:
                    cl.sendPacket({"cmd": "pmsg", "id":args["origin"], "val": "E:USERNAME_MISSMATCH_SESSION_INVALID", "origin": "%CA%"})
                    return False
            else:
                pass
    elif args["mode"] == "pswd":
        if "key" in args:
            pswd = str(sha256(str(args["key"]).encode('utf-8')).hexdigest())
            if userExists(args["origin"]):
                if sha256(str(args["key"]).encode('utf-8')).hexdigest() == readUserFile(args["origin"])["pswd"]:
                    fresh_token_gen = False
                    tokens = os.listdir("./ACCOUNT/TOKENCACHE")
                    while fresh_token_gen == False:
                        token = gen_token()
                        fresh_token_gen = "{0}.token".format(str(token)) not in tokens
                    writeUserFile(str(args["origin"]), {"isAuth": True, "latestToken": str(token), "pswd": pswd})
                    print("[ i ] {0} has been authed using password.".format(str(args["origin"])))
                    cl.sendPacket({"cmd": "pmsg", "id":args["origin"], "val": json.dumps({'token': str(token)}), "origin": "%CA%"})
                else:
                    cl.sendPacket({"cmd": "pmsg", "id":args["origin"], "val": "E:INVALID_PASSWORD", "origin": "%CA%"})
            else:
                fresh_token_gen = False
                tokens = os.listdir("./ACCOUNT/TOKENCACHE")
                while fresh_token_gen == False:
                    token = gen_token()
                    fresh_token_gen = "{0}.token".format(str(token)) not in tokens
                writeUserFile(str(args["origin"]), {"isAuth": True, "latestToken": str(token), "pswd": pswd})
                print("[ i ] {0} has been authed using password.".format(str(args["origin"])))
                cl.sendPacket({"cmd": "pmsg", "id":args["origin"], "val": json.dumps({'token': str(token)}), "origin": "%CA%"})
        else:
            cl.sendPacket({"cmd": "pmsg", "id":args["origin"], "val": "E:INTERNAL_SERVER_ERR", "origin": "%CA%"})
    return True

def writeUserFile(id, data):
    if "./ACCOUNT/USERDATA/{0}".format(id) in os.listdir("./ACCOUNT/USERDATA"):
        f1 = open("./ACCOUNT/USERDATA/{0}".format(id), "r").read()
    else:
        f1 = open("./ACCOUNT/USERDATA/{0}".format(id), "w")
        f1.write(json.dumps({"isAuth": False, "latestToken": "", "pswd": ""}))
        f1.close()
        f1 = open("./ACCOUNT/USERDATA/{0}".format(id), "r")
        data_tmp = f1.read()
    if len(data_tmp) == 0:
        data_user_tmp = {}
    else:
        data_user_tmp = json.loads(data_tmp)
    f1.close()
    for obj in data:
        data_user_tmp[str(obj)] = data[str(obj)]
    f2 = open("./ACCOUNT/USERDATA/{0}".format(id), "w")
    f2.write(json.dumps(data_user_tmp))
    print("[ i ] Writing {0} bytes to disk".format(len(str(data_user_tmp))))
    f2.close()

def userExists(id):
    return id in os.listdir("./ACCOUNT/USERDATA")

def userAuthed(id):
    if id in os.listdir("./ACCOUNT/USERDATA"):
        return json.loads(open("./ACCOUNT/USERDATA/{0}".format(id), "r").read())["isAuth"]
    else:
        return False

def readUserFile(id):
    if id in os.listdir("./ACCOUNT/USERDATA"):
        print("[ i ] Reading {0} bytes from disk".format(len(str(json.loads(open("./ACCOUNT/USERDATA/{0}".format(id), "r").read())))))
        return json.loads(open("./ACCOUNT/USERDATA/{0}".format(id), "r").read())
    else:
        return False
    
def error(error): # does this do something?
    print(error)

def init_files():
    try:
        os.mkdir("./ACCOUNT") # Create directory for CloudAccount
    except FileExistsError:
        pass
    try:
        os.mkdir("./ACCOUNT/TOKENCACHE") # Create a directory for token cache data
    except FileExistsError:
        pass
    try:
        os.mkdir("./ACCOUNT/USERDATA") # Create a directory for user data
    except FileExistsError:
        pass
    
    cache = os.listdir("./ACCOUNT/TOKENCACHE")
    if not len(cache) == 0:
        for file in cache:
            os.remove("./ACCOUNT/TOKENCACHE/{0}".format(file))
        print("[ i ] Cleared old token cache data.")
    
    userindex = os.listdir("./ACCOUNT/USERDATA")
    if not len(userindex) == 0:
        for user in userindex:
            if userAuthed(user):
                pswd = str(readUserFile(str(user))['pswd'])
                writeUserFile(str(user), {"isAuth": False, "latestToken": "", "pswd": pswd})
                print("[ i ] Deauthed user {0}.".format(user))
    print("[ i ] Initialized files.")

if __name__ == "__main__":
    init_files() # Initialize the directory
    try:
        cl = CloudLink()
        cl.client("ws://127.0.0.1:3000/", on_new_packet = on_new_packet, on_connect = on_connect, on_error = error)
        while cl.mode == 2: # check for new authenticator packets and handle them
            pass 
        del cl

    except KeyboardInterrupt:
        cl.stop() # Stops the client and exits
        sys.exit()