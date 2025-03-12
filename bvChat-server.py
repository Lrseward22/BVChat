from socket import *
import threading
#Server

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

def exit():
    pass

def tell(user, message):
    pass

def motd():
    pass

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
    getUsername = getLine(conn).strip('\n')
    getPassword = getLine(conn).strip('\n')
    if username == getUsername and password == getPassword:
        return True
    return False

#threads for each client
def handleClient(clientConn, peerAddr):
    print("Client Connected")
    #login protocol
    while not login(clientConn):
        failedLoginMsg = "Your username or password is incorrect\n"
        clientConn.send(failedLoginMsg.encode())

    print("Client logged in successfully")

    while True:
        #get input from client, handle commands
        command = getLine(clientConn).strip('\n')
        print(command)
        if command == "quit":
            break
    clientConn.close()
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

