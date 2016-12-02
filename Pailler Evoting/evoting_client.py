from __future__ import print_function

import eventlet


def main():
    tcp_ip = '127.0.0.1' #set up a tcp server
    tcp_port = 5005
    # buffer_size = 1024
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.bind((tcp_ip,tcp_port))


    print("server socket listening on port",tcp_port)
    client = eventlet.connect((tcp_ip, tcp_port))
    message = json.dumps({"TYPE":"REQUEST CANIDATES"})
    client.sendall(message)
    response = client.recv(1024)
    print("response",response)


if __name__ == "__main__":
    main()
