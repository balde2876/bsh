import json
from lib.Crypto.Hash import SHA512
pnfssettings = {}
globalsboxposition = ""
settingsLocation = 'packages/server/serversettings.txt'

def loadSettings():
    global pnfssettings
    try:
        with open(settingsLocation,'r') as dataFile:
            pnfssettings = json.load(dataFile)
    except Exception:
        resetData()

def resetData():
    with open(settingsLocation,'w') as dataFile:
        dataFile.write(json.dumps({"serverPassword": "null","subusers": False,"tcpPort": 2924}))
    loadSettings()

def saveData():
    global pnfssettings
    with open(settingsLocation,'w') as dataFile:
        dataFile.write(json.dumps(pnfssettings))

def newPassword():
    global pnfssettings
    npass = input("Password > ")
    hashalgo = SHA512.new()
    hashalgo.update(bytes(npass,"UTF-8"))
    pnfssettings["serverPassword"] = hashalgo.hexdigest()
    saveData()

def configWizard():
    global pnfssettings
    try:
        if pnfssettings["serverPassword"] == "null":
            print("No server password set")
            print("Create a password now:")
            newPassword()
    except Exception:
        resetData()

def bshHookBegin(args):
    global globalsboxposition
    #print(globalsboxposition)
    loadSettings()
    configWizard()
    print("Server should work")
    print("---")
    print("Commands:")
    print("reset - Resets the server config file and starts the configuration wizard")
    print("npass - Change the server password")
    print("---")
    while True:
        input1 = str.lower(input(">"))
        if input1 == "reset":
            resetData()
            configWizard()
        if input1 == "npass":
            newPassword()
            configWizard()
