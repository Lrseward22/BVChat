from socket import *
import threading
#Server

#List/Dict of connect clients
clients = []

#MOTD
motdmsg = "Welcome to the chat server\n"

def getLine(conn):
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            break
    return msg.decode()

def who():
    pass

def exit(clientConn):
    # TODO: officially log out user

    print("Exiting...")
    clientConn.close()
    return

def tell(user, message):
    pass

def motd(clientConn):
    clientConn.send(motdmsg.encode())

def me(message):
    pass

def help():
    pass

def kick():
    pass

def ban():
    pass

def unban():
    pass

def login(conn):
    username = "Cartman"
    password = "111"
    print("Logging in...")

    #Send a message telling the client to enter username
    usermsg = "Enter your username:\n"
    conn.send(usermsg.encode())
    getUsername = getLine(conn).strip('\n')

    #send a message telling the client to enter password
    passmsg = "Enter your password:\n"
    conn.send(passmsg.encode())
    getPassword = getLine(conn).strip('\n')

    if username == getUsername and password == getPassword:
        #add user to list of clients
        clients.append(conn)

        #broadcast to all clients that user has joined
        joinmsg = getUsername + " has joined the chat\n"

        return True, getUsername
    return False

#threads for each client
def handleClient(clientConn, peerAddr):
    print("Client Connected")
    #login protocol
    while True:
        loginResult, username = login(clientConn)

        if loginResult:
            break
        else:
            failedLoginMsg = "Your username or password is incorrect\n"
            clientConn.send(failedLoginMsg.encode())

    print("Client logged in successfully")
    loggedinMsg = "Logged in\n"
    clientConn.send(loggedinMsg.encode())

    # add user to list of clients
    clients.append(username)

    # broadcast to all clients that user has joined
    joinmsg = username + " has joined the chat\n"

    #Send MOTD
    clientConn.send(motdmsg.encode())

    connected = True
    try:
        while connected:
            #get input from client, handle commands
            command = getLine(clientConn).strip('\n').split(' ')
            print(command)

            # if command starts with "/" then it is a command
            # that will call a function, otherwise it is a message
            if command[0].startswith("/"):
                if command[0] == "/who": who()
                if command[0] == "/exit":
                    exit(clientConn)
                    connected = False
                if command[0] == "/tell": tell(command[1], command[2])
                if command[0] == "/motd": motd(clientConn)
                if command[0] == "/me": me(command[1])
                if command[0] == "/help": help()
            else:
                #broadcast message to all clients
                pass

    except ConnectionResetError:
        print("Client Disconnected")
        pass

# Initial socket setup
serverPort = 12345
serverSock = socket(AF_INET, SOCK_STREAM)
serverSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSock.bind( ('', serverPort) )
serverSock.listen(16)

print("Client running...")
print("Listening on port:", serverPort)

try:
    while True:
        #make a client connects - send to handleclient
        threading.Thread(target=handleClient, args=(*serverSock.accept(),), daemon=True).start()
except KeyboardInterrupt:
    print("\n Server Shutting down...")
    serverSock.close()

