#!/usr/bin/env python

import socket
from paillier.paillier import paillier as p

class EB:
    def __init__(self, reg_list):
        self.public, self.private = p.generate_keypair(512) # paillier key pair for signing votes
        self.reg_voters = reg_list # list of ids for registered voters
    def get_public(self): # func to get the public key
        return self.public
    def decrypt_sum(self, csum): #used for decrypting the sum at the end
        return p.decrypt(self.private,self.public,csum)
    def is_registered(self, voter_id):
        return voter_id in self.reg_voters
    def send_vote(self, voter, vote, b):
        b.set_row(voter, [ p.encrypt(self.public, v) for v in vote ])

class BB:
    def __init__(self, n, m):
        self.table = [ [ x for x in range(0, m) ] for y in range (0, n) ]
    def get_row(self, i):
        return self.table[i]
    def get_column(self, i):
        return [ self.table[x][i] for x in range(len(self.table)) ]

class CA:
    def get_sum(self, list):
        return sum(list)

def __main__():
    e = EB([0,1,2,3,4]) #initialize EB, BB, CA
    b = BB(10, 5)
    c = CA()

    tcp_ip = '127.0.0.1' #set up a tcp server
    tcp_port = 5005
    buffer_size = 1024
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(tcp_ip,tcp_port)

    while(1):
        s.listen(1)
        conn, addr = s.accept() # accept a voting client connection
        voter_id = conn.recv(buffer_size) # receive the voter's id
        conn.send(e.get_public()) # send the public paillier key over to the voter
                # encrypt these votes with the public paillier
                # encrypt with own key
                # send to the EB
        vote_array = conn.recv(buffer_size) # get a vote array from a voter
        if (!(e.is_registered(voter_id))): # if the voter isn't registered...
            conn.send("ERROR: UNREGISTERED VOTER\n")
            conn.close()
            break
        vote_array.append("verifiedxxxxx") # tack the verification token onto the end of the vote array
        #wait for response, break if vote denied
        #decrypt response with own key
        #send to BB and do zero knowledge proof stuff
