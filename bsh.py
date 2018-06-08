import socket
import lib.Crypto
#from lib.Crypto.Cipher import AES
from lib.blowfish import blowfish
from lib.Crypto.Hash import SHA256
from lib.Crypto.Hash import SHA512
import os
import time
import random
import json
import importlib
import sys

class bsh:
    tcp_port = 2924
    buffer = 1280
    prog1 = 0
    sourceLength = 0
    clientsocket = None
    sharedSecret = 0
    initVector = 0
    initVectorb = None
    encryptedTunnel = False
    verifiedTunnel = False
    globalCipher = None
    clientVersion = 3
    minServerVersion = 3

    def base256_encode(self, n, minwidth=0): # int/long to byte array
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

    def sendFile(self, destinationFile,sourceFile):
        #prepareConnection()
        global globalCipher
        try:
            sourceLength = os.path.getsize(sourceFile)
            print("Uploading...")
            self.sendMessage("ICFL" + "///" + destinationFile + "///" + str(sourceLength) + "///",globalCipher)
            prog1 = 0
            try:
                fs = open(sourceFile, "rb")
                fs.seek(0)

                while prog1 < sourceLength:
                    b = self.encryptData(bytes(bytearray(fs.read(self.buffer))),globalCipher)
                    self.sendBytes(b)
                    prog1 = prog1 + len(b)
                    dta = self.getMessage(globalCipher)
                    #print(dta)
                    #parsedata = dta.split("///")
                    #fcn = parsedata[0]
                    sys.stdout.write("\033[F")
                    print(str(round((prog1/sourceLength) * 100)) + "% " + str(round(prog1/1024)) + "/" + str(round(sourceLength/1024)) + "KB")
                    if not (dta == "ACK") :
                        raise Exception('ACK command not recieved')
                dta = self.getMessage(globalCipher)
                if dta == "FLRC":
                    print("Sent File")
            except Exception as exb:
                print("[ SEVERE ] Cannot send file - do you have permission?")
                print("           " + str(exb))
        except Exception as ex:
            print("[ SEVERE ] Cannot send file - does it exist?")
            print("           " + str(ex))
        self.sendMessage("FFTF",globalCipher)
        #encryptedTunnel = False

    def getFile(self, destinationFile,sourceFile):
        #prepareConnection()
        global globalCipher
        self.sendMessage("RCFL" + "///" + sourceFile,globalCipher)
        data = self.getMessage(globalCipher)
        #print("meem : " + data)
        parsedata = data.split("///")
        fileLength = 1
        if parsedata[0] == "FLEN":
            fileLength = int(parsedata[1])

        try:
            f = open(destinationFile,"wb")
            f.seek(fileLength-1)
            f.write(b"\0")
            f.close()
        except Exception as ex:
            print("[ SEVERE ] Cannot write file - do you have permission?")
            print("           " + str(ex))
            fileRecv = True
            self.sendMessage("FFTF",globalCipher)

        fileRecv = False
        prog = 0
        if parsedata[0] == "FLEN":
            print("Downloading...")
            while fileRecv == False:
                dag = True
                self.sendMessage("NFCH",globalCipher)
                #print("NFCH")
                #print("Downloading...")
                data = self.getBytes()
                while dag:
                    try:
                        file = open(destinationFile, "r+b")
                        file.seek(prog)
                        file.write(self.decryptData(data,globalCipher))
                        prog = prog + len(data)
                        #print(str(round(prog/recevinfo["length"]) * 100) + "% Downloaded")
                        
                        file.close()
                        dag = False
                    except Exception:
                        ##print("err,try again")
                        dag = True
                #print("written chunk")
                sys.stdout.write("\033[F")
                print(str(round((prog/fileLength) * 100)) + "% " + str(round(prog/1024)) + "/" + str(round(fileLength/1024)) + "KB")
                if (prog >= fileLength):
                    fileRecv = True
                    print("File Recieved")
                    self.sendMessage("FFTF",globalCipher)
        else:
            print("[ SEVERE ] Cannot get file - do you have permission?")
            print("           " + parsedata[1])
            #raise Exception("ERROR")
        #encryptedTunnel = False
        
    def getDir(self, directory = "#"):
        #prepareConnection()
        global globalCipher
        try:
            self.sendMessage("RTDS" + "///" + directory,globalCipher)
            recdata = True
            print("[ "+directory+" ]")
            print("")
            try:
                while recdata:
                    dta = self.getMessage(globalCipher)
                    self.sendMessage("ACK",globalCipher)
                    parsedata = dta.split("///")
                    fcn = parsedata[0]
                    if (fcn == "PTRH") :
                        print(parsedata[1])
                    if (fcn == "FNCM") :
                        recdata = False
            except Exception as exb:
                print("[ SEVERE ] Exception Parsing Data")
                print("           " + str(exb))
            print("")
        except Exception as ex:
            print("[ SEVERE ] Unknown Fail")
            print("           " + str(ex))
        self.sendMessage("FNCM",globalCipher)

    def sendMessage(self, message,obj):
        message2 = self.encryptData(bytes(message,"utf-8"),obj)
        self.clientsocket.send(message2)

    def sendMessagePlain(self, message):
        message = bytes(message,"utf-8")
        self.clientsocket.send(message)

    def sendBytes(self, bytes1):
        self.clientsocket.send(bytes1)

    def getMessage(self, obj):
        message = str(self.decryptData(self.clientsocket.recv(self.buffer),obj),"utf-8")
        return message

    def getMessagePlain(self):
        message = str(self.clientsocket.recv(self.buffer),"utf-8")
        return message

    def getBytes(self):
        return self.clientsocket.recv(self.buffer)

    def encryptData(self, bytes1,obj):
        return b"".join(obj.encrypt_cfb(bytes1,initVectorb))

    def decryptData(self, bytes1,obj):
        return b"".join(obj.decrypt_cfb(bytes1,initVectorb))

    def prepareConnection(self):
        global sharedSecret
        global initVector
        global initVectorb
        global encryptedTunnel
        global globalCipher
        npass = input("Server Password > ")
        hashalgo = SHA512.new()
        hashalgo.update(bytes(npass,"UTF-8"))
        passwordHash = hashalgo.hexdigest()

        self.sendMessagePlain("DHKE")
        hashalgo = SHA512.new()
        commonKeySrc = int(self.getMessagePlain())
        #print("passwordHash = " + passwordHash)
        #print("commonKeySrc = " + str(commonKeySrc))
        lmesg = self.getMessagePlain()
        #print("lmesg = " + lmesg)
        commonKey = int(lmesg)
        hashalgo.update(bytes((str(commonKeySrc) + passwordHash),"UTF-8"))
        #print("digest = " + str(int.from_bytes(hashalgo.digest(),byteorder='little')))
        commonKeyVerif = int.from_bytes(hashalgo.digest(),byteorder='little')
        secretKey = random.SystemRandom().randint(0,2**2048)

        genKeyA = commonKey * secretKey
        self.sendMessagePlain(str(genKeyA))
        recKeyA = int(self.getMessagePlain())
        #print(str(recKeyA))
        sharedSecret = int(recKeyA * secretKey)
        self.sendMessagePlain("ACK")
        initVector = int(self.getMessagePlain())
        initVectorb = bytes(self.base256_encode(initVector)).ljust(8)[:8]
        #print("==[ CC  ]==")
        #print(commonKey)
        #print("==[ END ]==")
        #print("==[ CCV ]==")
        #print(commonKeyVerif)
        #print("==[ END ]==")
        #print("==Shared==")
        #print(sharedSecret)
        #print("==Shared==")
        if commonKey == commonKeyVerif:
            encryptedTunnel = True
            print("Encrypted tunnel established")
        else:
            encryptedTunnel = False
            print("Invalid server password")
        if encryptedTunnel:
            saltA = int(self.getMessagePlain())
            hashalgo = SHA256.new()
            hashalgo.update(bytes(str(saltA) + passwordHash,"UTF-8"))
            hashA = hashalgo.hexdigest()
            self.sendMessagePlain(str(hashA))
            cfm = self.getMessagePlain()
            #print(cfm)
            saltB = random.SystemRandom().randint(0,2**(16*8))
            hashalgo = SHA256.new()
            hashalgo.update(bytes(str(saltB) + passwordHash,"UTF-8"))
            hashC = hashalgo.hexdigest()
            self.sendMessagePlain(str(saltB))
            hashD = self.getMessagePlain()
            #print(hashC)
            #print(hashD)
            if hashC == hashD:
                print("Server accepted and authenticated")
                globalCipher = blowfish.Cipher(bytes(self.base256_encode(sharedSecret)).ljust(48)[:48])
                print("Connection now secure")
            else:
                if hashD.split("///")[0] == "IVPW":
                    print("Invalid Password")
                else:
                    print("Invalid Server")
                time.sleep(5)
                raise Exception("Invalid Password / Invalid Server")
        else:
            #raise Exception("Could not establish encrypted tunnel")
            print("Connection Aborted")
        #print(sharedSecret)
        #getMessage()

    def initConn(self, tcp_ip):
        print("Closing existing connections")
        try:
            try:
                self.sendMessage("DCON",globalCipher)
            except:
                print("Unclean Disconnect")
            self.clientsocket.close()
            self.clientsocket=None
        except:
            print("No current connection")
        print("Connecting to " + tcp_ip + ":" + str(self.tcp_port))
        try:
            self.clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.clientsocket.connect((tcp_ip, self.tcp_port))
            self.prepareConnection()
            self.verifiedTunnel = True
        except:
            print("Can't connect to server - no response")

    #initConn()
    #getFile("2.mp3","m.mp3")

    def runBshScript(self, file):
        with open(file, "r") as cmds:
            cmds = cmds.read()
            strs = cmds.split("\n")
            for str1 in strs:
                self.cmdProc(str1)


    def cmdProc(self, cmd1):
            global globalCipher
            cmds = cmd1.split(" ")
        #try:
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
                            func.parent = self
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
            if cmds[0].lower() == "conn":
                if len(cmds) > 1:
                    self.initConn(cmds[1])
                else:
                    print("IP address required")
            if cmds[0].lower() == "exit":
                print("Closing existing connections")
                try:
                    try:
                        self.sendMessage("DCON",globalCipher)
                    except:
                        print("Unclean Disconnect")
                    self.clientsocket.close()
                    self.clientsocket=None
                    self.verifiedTunnel=False
                except:
                    print("No current connection")
            if cmds[0].lower() == "get":
                if len(cmds) > 2:
                    if self.verifiedTunnel:
                        self.getFile(cmds[2],cmds[1])
                    else:
                        print("No current connection, use CONN <ip address>")
                else:
                    print("Usage : GET <source> <destination>")
            if cmds[0].lower() == "send":
                if len(cmds) > 2:
                    if self.verifiedTunnel:
                        self.sendFile(cmds[2],cmds[1])
                    else:
                        print("No current connection, use CONN <ip address>")
                else:
                    print("Usage : SEND <source> <destination>")
            if cmds[0].lower() == "dir":
                if len(cmds) > 1:
                    if self.verifiedTunnel:
                        self.getDir(cmds[1])
                    else:
                        print("No current connection, use CONN <ip address>")
                else:
                    if self.verifiedTunnel:
                        self.getDir()
                    else:
                        print("No current connection, use CONN <ip address>")
            if cmds[0].lower() == "run":
                if len(cmds) > 1:
                    try:
                        self.runBshScript(cmds[1])
                    except Exception as ex:
                        print("[ ERROR  ] Cannot run script")
                        print("           " + str(ex))
                else:
                    print("Usage : Run <file name>")
            if cmds[0].lower() == "help":
                if len(cmds) > 1:
                    fpkg = False
                    with open("packages/hooks.txt", "r") as f:
                        str1 = f.read()
                        strs = str1.split("\n")
                        for str2 in strs:
                            strs2 = str2.split(" ")
                            if strs2[0].lower() == cmds[1].lower():
                                fpkg = True
                                print(strs2[1])
                                print("Accessed as : " + strs2[0])
                                with open("packages/" + strs2[1] + "/help.txt", "r") as f2:
                                    str1 = f2.read()
                                    strs = str1.split("\n")
                                    print("Attached Helpfile : ")
                                    for str2 in strs:
                                        print("    " + str2)
                        if fpkg == False:
                            print("Invalid command")

                else:
                    with open("coreHelp.txt", "r") as f:
                        str1 = f.read()
                        strs = str1.split("\n")
                        print("Commands : ")
                        for str2 in strs:
                            print("    " + str2)
                        print("Installed Packages : ")
                        with open("packages/hooks.txt", "r") as f2:
                            str1 = f2.read()
                            strs = str1.split("\n")
                            for str2 in strs:
                                try:
                                    strs2 = str2.split(" ")
                                    print("    " + strs2[1])
                                    print("    " + "Accessed as : " + strs2[0])
                                except:
                                    print("err")
        #except:
            #print("Uncaught error")
                #print("HELP [subcommand] - Prints this help message or the help message for the given subcommand")
                #print("CONN <ip address> - Connects to a server")
                #print("GET <source (on server)> <destination> - Retrieves a file from the server")
                #print("SEND <source (on client)> <destination> - Prints this help message")
                #print("PKG - Used to access the package manager")

    # Startup commands

    # Startup commands
    def __init__(self):
        print("Backdoor SHell v"+str(self.clientVersion))
        print("")
        print("Software under the Apache Open Source Licence")
        print("")
        print("THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.")
        print("")
        #self.cmdProc("CONN 192.168.1.100")
        #self.cmdProc("get vanillaachance.mp3 meem.mp3")
        #self.runBshScript("startup.bsh")
        #self.runBshScript("server.bsh")
        while True:
            self.cmdProc(input("bsh > "))


bsh()

    ##try:
    ##    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ##    clientsocket.connect((tcp_ip, tcp_port))
    ##    sendFile("l.mp3","m.mp3")
    ##    clientsocket.close()
    ##    clientsocket=None
    ##except Exception:
    ##    print("Fatal error")
