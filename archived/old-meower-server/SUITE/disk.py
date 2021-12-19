import json, os

class filesysapi:
    def __init__(self):
        self.dirpath = os.path.dirname(os.path.abspath(__file__)) + "/DISK"
        self.defaultsecparams = {
            "isHidden": False,
            "isSecure": False,
            "accessKey": "",
            "limitProjectAccess": False,
            "permittedProjectIDs": {}
           }
        print("Current DIR is {0}".format(self.dirpath))
    
    def write(self, fdir, fname, data):
        try:
            if os.path.exists(self.dirpath + "/" + fdir):
                #print("TYPE:", type(data))
                if type(data) == str:
                    f = open((self.dirpath + "/" + fdir + "/" + fname), "w")
                    f.write(data)
                    f.close()
                elif type(data) == dict:
                    f = open((self.dirpath + "/" + fdir + "/" + fname), "w")
                    f.write(json.dumps(data))
                    f.close()
                else:
                    f = open((self.dirpath + "/" + fdir + "/" + fname), "w")
                    f.write(str(data))
                    f.close()
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
    
    def mkdir(self, directory):
        check1 = False
        try:
            os.makedirs((self.dirpath + "/" + directory), exist_ok=True)
            check1 = True
        except Exception as e:
            print(e)
            return False
        if check1:
            try:
                if os.path.exists(self.dirpath + "/" + directory):
                    with open((self.dirpath + "/" + directory + "/SECURITY.json"), "w") as f:
                        json.dump(self.defaultsecparams, f)
                    return True
                else:
                    return False
            except Exception as e:
                print(e)
                return False
            
        else:
            return False
    
    def rm(self, file):
        try:
            os.remove((self.dirpath + "/" + file))
            return True
        except Exception as e:
            print(e)
            return False
    
    def rmdir(self, directory):
        try:
            check1 = self.deletefile((directory + "/SECURITY.json"))
            if check1:
                os.rmdir((self.dirpath + "/" + directory))
                return True
            else:
                return False, 2
        except Exception as e:
            print(e)
            return False, 1
    
    def read(self, fname):
        try:
            if os.path.exists(self.dirpath + "/" + fname):
                dataout = open(self.dirpath + "/" + fname).read()
                return True, dataout
            else:
                return False, None
        except Exception as e:
            print(e)
            return False, None
    
    def chkfile(self, file):
        try:
            return True, os.path.exists(self.dirpath + "/" + file)
        except Exception as e:
            return False, None
    
    def lsdir(self, directory):
        try:
            return True, os.listdir(self.dirpath + "/" +directory)
        except Exception as e:
            print(e)
            return False, None
    
    def chktype(self, directory, file):
        try:
            if os.path.isfile(self.dirpath + "/" + directory + "/" + file):
                return True, 1
            elif os.path.isdir(self.dirpath + "/" + directory + "/" + file):
                return True,  2
            else:
                return False, None
        except Exception as e:
            print(e)
            return False, None