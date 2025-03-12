from socket import *
import threading
import sys
#Client
serverIP = sys.argv[1]
serverPort = int(sys.argv[2])

serverSock = socket(AF_INET, SOCK_STREAM)

# Event that allows listening thread to be stopped early
stop_event = threading.Event()

def getLine(conn):
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            break
    return msg.decode()

#separate thread handling incoming messages
def listen(conn):
    while not stop_event.is_set():
        msg = getLine(conn)
        print(msg)

#connect to server - login protocol

try:
    serverSock.connect( (serverIP, serverPort) )
    #make thread for incoming messages
    threading.Thread(target=listen, args=(serverSock, ), daemon=True).start()

    while True:
        #get input from user, send to server
        command = input("> ") + '\n'
        serverSock.send( command.encode() )

        #until /quit from user or keyboard interrupt
        if command.strip('\n') == "quit":
            stop_event.set()
            serverSock.close()
            break

except KeyboardInterrupt:
    print("Client Shutting Down...")
    stop_event.set()
    serverSock.close()
