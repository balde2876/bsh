import socket
import struct
import os
import lib.Crypto
#from lib.Crypto.Cipher import AES
from lib.blowfish import blowfish
from lib.Crypto.Hash import SHA256
from lib.Crypto.Hash import SHA512
import os
import random
import json
import importlib
from threading import Thread

globalsboxposition = ""
pnfssettings = {}
serveropen = False
tcp_port = 0
buffer = 1280
recevinfo = {}
timeout = 1000
serverIDs = 0
serverVersion = 3
minClientVersion = 3
canStart = True
parent = None
serversocket = None

def bshHookBegin(args):
    global pnfssettings
    global globalsboxposition
    global tcp_port
    global canStart
    global serveropen
    global serversocket

    #print(globalsboxposition)

    if len(args) > 0 :
        if args[0] == "setup" :
            func = importlib.import_module(globalsboxposition.replace("/",".").replace("\\",".") + "bshServerConfig")
            func.globalsboxposition = globalsboxposition
            #func.parent = self
            func.bshHookBegin()

    with open(globalsboxposition + 'serversettings.txt') as data_file:
        pnfssettings = json.load(data_file)

    if "tcpPort" in pnfssettings:
        tcp_port = pnfssettings["tcpPort"]
        print("[INFO] TCP recieve port:" + str(tcp_port))
    else:
        print("[CRITICAL] No tcp port set")
        print("[CRITICAL] The server will not start without a assigned port")
        canStart = False

    if pnfssettings["serverPassword"] == "null":
        print("[CRITICAL] No server password set")
        print("[CRITICAL] Use the server configurator script to change this")
        print("[CRITICAL] The server will not start without a valid password")
        canStart = False

    if pnfssettings["serverPassword"] == True:
        print("[INFO] Subusers enabled")
        print("[INFO] Subusers still need the server password for initial connect")
        print("[INFO] Subsequent connections can be made using the server passhash & subuser password")
    else:
        print("[INFO] Subusers disabled")
        print("[INFO] Users need the server password every time to connect")

    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(("", tcp_port))
    serversocket.listen(1)

    if canStart:
        while True:
            #if serveropen == False:
                #serveropen = True
                clientsocket,address = serversocket.accept()
                thread = Thread(target = openServer, args = (clientsocket,address))
                thread.start()

def sendPlainText(message,cs):
    message = bytes(message,"utf-8")
    cs.send(message)

def sendMessage(message,cs,obj,siv):
    message = bytes(message,"utf-8")
    cs.send(encryptData(message,obj,siv))

def sendBytes(bytes1,cs):
    cs.send(bytes1)

def encryptData(bytes1,obj,siv):
    return b"".join(obj.encrypt_cfb(bytes1,siv))

def decryptData(bytes1,obj,siv):
    return b"".join(obj.decrypt_cfb(bytes1,siv))

def base256_encode(n, minwidth=0): # int/long to byte array
    if n > 0:
        arr = []
        while n:
            n, rem = divmod(n, 256)
            arr.append(rem)
        b = bytearray(reversed(arr))
    elif n == 0:
        b = bytearray(b'\x00')
    else:
        raise ValueError

    if minwidth > 0 and len(b) < minwidth: # zero padding needed?
        b = (minwidth-len(b)) * '\x00' + b
    return b

def openServer(clientsocket,address):
    global serverIDs
    serverID = serverIDs
    serverIDs = serverIDs + 1
    try:
        global serveropen
        global serversocket
        encryptedTunnel = False
        mode = 0
        sharedSecret = 0
        initVector = 0
        initVectorb = None
        # accept connections from outside
        #print("[STATUS] Ready for new client")
        username = "NULL"
        macAddr = "NULL"

        #(clientsocket, address) = serversocket.accept()
        ip = address[0]
        port = address[1]
        aesobj = None
        #serversocket.close()



        print("@"+str(serverID)+" [STATUS] Client connecting...")
        

        while mode > -1:
            data = clientsocket.recv(buffer)
            if (mode == 1) :
                #print("Mode 1")
                prog1 = 0
                sourceLength = recevinfo["length"]
                file = open(recevinfo["dest"], "a+b")
                while prog1 < sourceLength:
                    dag = True
                    while dag:
                        try:
                            file.write(decryptData(data,aesobj,initVectorb))
                            prog1 = prog1 + len(data)
                            #print(str(round(prog1/sourceLength) * 100) + "% Uploaded")
                            sendMessage("ACK",clientsocket,aesobj,initVectorb)
                            if prog1 < sourceLength:
                                data = clientsocket.recv(buffer)
                            dag = False
                        except Exception:
                            dag = True
                file.close()
                print("@"+str(serverID)+" [STATUS] Data Stream Stop")
                sendMessage("FLRC",clientsocket,aesobj,initVectorb)
                data = clientsocket.recv(buffer)
                data = str(decryptData(data,aesobj,initVectorb),"utf-8")
                if data == "FFTF":
                    mode = 0
                    print("@"+str(serverID)+" [STATUS] File Recieved")
                data = clientsocket.recv(buffer)

            if (mode == 2) :
                #print("Mode 2")
                sourceLength = recevinfo["length"]
                #sendMessage(str(sourceLength),clientsocket,aesobj)
                prog1 = 0
                try:
                    fs = open(recevinfo["source"], "rb")
                    fs.seek(0)
                    while prog1 < sourceLength:
                        #print("Waiting for NFCH")
                        message = str(decryptData(data,aesobj,initVectorb),"utf-8")
                        #print("msg" + message)
                        parsedata = message.split("///")
                        fcn = parsedata[0]
                        if fcn == "NFCH":
                            b = bytearray(encryptData(fs.read(buffer),aesobj,initVectorb))
                            sendBytes(b,clientsocket)
                            prog1 = prog1 + len(b)
                        data = clientsocket.recv(buffer)
                    print("@"+str(serverID)+" [STATUS] Delivered file")
                except Exception as ex:
                    print("@"+str(serverID)+" [SEVERE] Cannot send file data")
                    print("@"+str(serverID)+" [DETAIL] File Send "+"Error: {0}".format(ex))
                mode = 0
                data = clientsocket.recv(buffer)

            if (mode == 0) :
                if encryptedTunnel:
                    data = str(decryptData(data,aesobj,initVectorb),"utf-8")
                    #print("DATA")
                    parsedata = data.split("///")
                    fcn = parsedata[0]
                    #print(fcn)
                    if (fcn == "ECR") :
                        command = parsedata[1]
                        cmds = command.split(" ")
                        with open("packages/hooks.txt", "r") as hooksFile:
                            hooks = hooksFile.read()
                            strs = hooks.split("\n")
                            for str1 in strs:
                                strs2 = str1.split(" ")
                                if cmds[0].lower() == strs2[0].lower():
                                    #print("packages/"+strs2[1].lower())
                                    args1 = None
                                    try:
                                        args1 = cmds[1:]
                                    except:
                                        args1 = None
                                    with open("packages/" + strs2[1].lower() + "/packageInfo.txt", "r") as f2:
                                        packageInfo = json.load(f2)
                                        mainFile = "packages." + strs2[1] + "." + packageInfo["mainFile"].replace(".py", "")
                                        #print(mainFile)
                                        func = importlib.import_module(mainFile)
                                        func.globalsboxposition = "packages/" + strs2[1] + "/"
                                        func.parent = parent
                                        func.isServer = True
                                        func.cs = clientsocket
                                        func.eo = aesobj
                                        func.iv = initVectorb
                                        func.sendMessageServerToClient = sendMessage
                                        if hasattr(func, "globalCipher"):
                                            if "globalCipher" in globals():
                                                func.globalCipher = globalCipher
                                            else:
                                                func.globalCipher = None
                                        try:
                                            func.bshHookBegin(args1)
                                        except Exception as ex:
                                            print("[ SEVERE ] Exception in " + mainFile)
                                            print("           " + format(ex))
                    if (fcn == "ICFL") :
                        print("@"+str(serverID)+" [STATUS] Receiving File : " + parsedata[1])
                        #print(parsedata[2])
                        mode = 1
                        recevinfo = {"dest":parsedata[1],"length":int(parsedata[2])}
                        file = open(recevinfo["dest"], "w+b")
                        file.close()
                        prog = 0
                    if (fcn == "RCFL") :
                        print("@"+str(serverID)+" [STATUS] Sending File : " + parsedata[1])
                        try:
                            sourceLength = os.path.getsize(parsedata[1])
                            recevinfo = {"source":parsedata[1],"length":int(sourceLength)}
                            sendMessage("FLEN" + "///" + str(sourceLength),clientsocket,aesobj,initVectorb)
                        except Exception as ex:
                            print("@"+str(serverID)+" [SEVERE] Cannot send file - no access")
                            print("@"+str(serverID)+" [DETAIL] File Send "+"Error: {0}".format(ex))
                            sendMessage("ERROR" + "///" + str(ex),clientsocket,aesobj,initVectorb)
                        mode = 2
                        prog = 0
                    if (fcn == "DCON") :
                        clientsocket.close()
                        serveropen = False
                        print("@"+str(serverID)+" [STATUS] Disconnected Legally")
                    if (fcn == "RTDS") :
                        print("@"+str(serverID)+" [STATUS] Sending Directory Structure for " + parsedata[1])
                        try:
                            dirls = parsedata[1]
                            if dirls == "#":
                                items = os.listdir()
                            else:
                                items = os.listdir(dirls)
                            for item in items:
                                sendMessage("PTRH" + "///" + item,clientsocket,aesobj,initVectorb)
                                data = clientsocket.recv(buffer)
                                data = str(decryptData(data,aesobj,initVectorb),"utf-8")
                                if data != "ACK":
                                    print("@"+str(serverID)+" [STATUS] No acknowledge signal")
                        except:
                            sendMessage("PTRH" + "///" + "Cannot access directory",clientsocket,aesobj,initVectorb)
                        sendMessage("FNCM",clientsocket,aesobj,initVectorb)
                        
                else:
                    data = str(data,"utf-8")
                    parsedata = data.split("///")
                    fcn = parsedata[0]
                    #print(fcn)
                    if (fcn == "DHKE") :
                        print("@"+str(serverID)+" [STATUS] Creating encrypted tunnel")
                        hashalgo = SHA512.new()
                        passwordHash = pnfssettings["serverPassword"]
                        commonKeySrc = random.SystemRandom().randint(0,2**2048)
                        #print("passwordHash = " + passwordHash)
                        #print("commonKeySrc = " + str(commonKeySrc))
                        sendPlainText(str(commonKeySrc),clientsocket)
                        hashalgo.update(bytes((str(commonKeySrc) + passwordHash),"UTF-8"))
                        #print("digest = " + str(int.from_bytes(hashalgo.digest(),byteorder='little')))
                        commonKey = int.from_bytes(hashalgo.digest(),byteorder='little')
                        #commonKey = commonKeySrc
                        secretKey = random.SystemRandom().randint(0,2**2048)
                        initVector = random.SystemRandom().randint(0,2**(8))
                        initVectorb = bytes(base256_encode(initVector)).ljust(8)[:8]
                        #print("==[ CC  ]==")
                        #print(commonKey)
                        #print("==[ END ]==")
                        sendPlainText(str(commonKey),clientsocket)

                        genKeyA = commonKey * secretKey
                        recKeyA = int(str(clientsocket.recv(buffer),"utf-8"))
                        sendPlainText(str(genKeyA),clientsocket)
                        sharedSecret = recKeyA * secretKey
                        #print("==Shared==")
                        #print(sharedSecret)
                        #print("==Shared==")
                        ack1 = str(clientsocket.recv(buffer),"utf-8")
                        #print(ack1)
                        sendPlainText(str(initVector),clientsocket)
                        aesobj = blowfish.Cipher(bytes(base256_encode(sharedSecret)).ljust(48)[:48])
                        saltA = random.SystemRandom().randint(0,2**(16*8))
                        sendPlainText(str(saltA),clientsocket)
                        hashalgo = SHA256.new()
                        hashalgo.update(bytes(str(saltA) + passwordHash,"UTF-8"))
                        hashA = str(clientsocket.recv(buffer),"utf-8")
                        sendPlainText("ACK",clientsocket)
                        hashB = hashalgo.hexdigest()
                        #print(hashA)
                        #print(hashB)
                        if hashA == hashB:
                            print("@"+str(serverID)+" [STATUS] Client accepted and authenticated")
                            encryptedTunnel = True
                            saltB = str(clientsocket.recv(buffer),"utf-8")
                            hashalgo = SHA256.new()
                            hashalgo.update(bytes(str(saltB) + passwordHash,"UTF-8"))
                            hashD = hashalgo.hexdigest()
                            sendPlainText(hashD,clientsocket)
                            print("@"+str(serverID)+" [STATUS] Client secured")
                            print("@"+str(serverID)+" [STATUS] Finished client setup")
                        else:
                            print("@"+str(serverID)+" [SEVERE] Invalid Password")
                            sendPlainText("IVPW///",clientsocket)
                            raise Exception("Invalid Password")
                            encryptedTunnel = False
                    #print(sharedSecret)
                    #print(str(recKeyA))
            #print(parsedata[1])
            #rint(parsedata[2])

        mode = 0
    except Exception as ex:
        try:
            clientsocket.close()
            print("@"+str(serverID)+" [STATUS] Socket terminated")
        except:
            print("@"+str(serverID)+" [STATUS] Socket does not exist")
        print("@"+str(serverID)+" [STATUS] Client removed")
        print("@"+str(serverID)+" [DETAIL] Main "+"Error: {0}".format(ex))
        serveropen = False
