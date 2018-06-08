globalsboxposition = ""
parent = None
sendMessageServerToClient = None
globalCipher = None
returnedText = ""
isServer = False
cs = None
eo = None
iv = None

def bshHookBegin(args):
    global globalsboxposition
    global parent
    global globalCipher
    print("[ Package Manager ]")
    #print(parent.tcp_port)
    if isServer:
        if args[0].lower() == "list":
            print("Packages installed on the local machine:")
            with open("packages/hooks.txt", "r") as f:
                str1 = f.read()
                strs = str1.split("\n")
                fout = ""
                for str2 in strs:
                    try:
                        strs2 = str2.split(" ")
                        fout = fout + strs2[1] + "\n"
                        fout = fout + "Accessed as : " + strs2[0] + "\n\n"
                    except:
                        None
                sendMessageServerToClient(fout,cs,eo,iv)
    else:
        if args[0].lower() == "list":
            print("Packages installed on the local machine:")
            with open("packages/hooks.txt", "r") as f:
                str1 = f.read()
                strs = str1.split("\n")
                for str2 in strs:
                    try:
                        strs2 = str2.split(" ")
                        print("")
                        print(strs2[1])
                        print("Accessed as : " + strs2[0])
                    except:
                        None
            print("")
            if parent.verifiedTunnel:
                print("Fetching server info...")
                print("")
                print("Packages installed on the server:")
                parent.sendMessage("ECR///PKGM LIST",globalCipher)
                data = parent.getMessage(globalCipher)
                print(data)

    
        
