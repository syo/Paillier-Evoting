#!/usr/bin/env python

from __future__ import print_function

import eventlet

import socket
import paillier
import paillier.paillier as p
import rsa
import json
import pickle
from pprint import pprint

class EB:
    def __init__(self, voters, canidates):

        private_keyfile = open("keyserver/Private/EB_paillier.key", 'r')
        public_keyfile = open("keyserver/Public/EB_paillier_public.key", 'r')

        self.public = pickle.load(private_keyfile)
        self.private = pickle.load(public_keyfile)

        RSA_private_keyfile = open("keyserver/Private/EB_RSA.key", 'r')
        RSA_public_keyfile = open("keyserver/Public/EB_RSA_public.key", 'r')

        self.publicRSA = pickle.load(RSA_private_keyfile)
        self.privateRSA = pickle.load(RSA_public_keyfile)

        self.reg_voters = voters # list of ids for registered voters
        self.canidates = canidates
    def get_public(self): # func to get the public key
        return self.public
    def arr_decrypt(self, vlist):
        result = [0 for x in range(len(vlist))]
        for i in range(len(vlist)):
            [i] = p.decrypt(self.private,self.public,vlist[i])
        announce_results(result)
    def announce_results(self, results): #used for decrypting the sum at the end
        for i in range(len(results)):
            print("Choice " + str(i) + " received " + str(results[i]) + " votes ")
    def is_registered(self, voter_id):
        return voter_id in self.reg_voters

class BB:
    def __init__(self, n_voters, n_canidates):
        self.table = [ [ 0 for _ in range(0, n_canidates) ] for _ in range (0, n_voters) ]
        self.has_voted = []
        self.votes = []

        RSA_private_keyfile = open("keyserver/Private/EB_RSA.key", 'r')
        RSA_public_keyfile = open("keyserver/Public/EB_RSA_public.key", 'r')

        self.publicRSA = pickle.load(RSA_private_keyfile)
        self.privateRSA = pickle.load(RSA_public_keyfile)
    def get_votes(self):
        return self.votes
    def receive_vote(self, v):
        if (v[len(v)-1] in self.has_voted): # if you have already received this persons vote...
            return False # exit out
        self.has_voted.append(v[len(v)-1]) # add this id to list of those who've voted
        self.votes.append(v[:-1]) # add their votes to the votes

class CA:
    def get_sum(self, vlist, pub):
        totals = [p.encrypt(pub,0) for x in range(len(vlist))] #initialize totals, leave out verification token
        for v in vlist: #add up encrypted vote totals
            totals = encrypted_arr_add(pub,totals,v)
        return totals

class Election:
    def __init__(self,voters,canidates):
        self.eb = EB(voters, canidates) #initialize EB, BB, CA
        self.bb = BB(len(voters), len(canidates))
        self.ca = CA()
        self.canidates = canidates

    def get_canidates(self):
        return self.canidates

    def get_response(self,message):
        m = json.loads(message)
        if m["TYPE"] == "REQUEST CANIDATES":
            return json.dumps({"DATA":self.get_canidates()})

    def handle(self,fd):
        print("client connected")
        while True:
            # pass through every non-eof line
            x = fd.readline()
            if not x:
                break
            res = self.get_response(x)
            fd.write(res+"\n")
            fd.flush()
            print("echoed", x, end=' ')
        print("client disconnected")


def encrypted_arr_add(pub,list1,list2):
    list3 = [0 for x in range(len(vlist) - 1)]
    for i in range(len(list1)):
        list3[i] = p.e_add(pub,list1[i],list2[i])
    return list3

def main():
    with open('database/registered.json') as data_file:
        voters = json.load(data_file)
    with open('database/canidates.json') as data_file2:
        canidates = json.load(data_file2)
    pprint(voters)
    pprint(canidates)

    E = Election(voters, canidates)

    tcp_ip = '127.0.0.1' #set up a tcp server
    tcp_port = 5005
    # buffer_size = 1024
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.bind((tcp_ip,tcp_port))


    print("server socket listening on port",tcp_port)
    server = eventlet.listen((tcp_ip, tcp_port))
    pool = eventlet.GreenPool()
    while True:
        try:
            new_sock, address = server.accept()
            print("accepted", address)
            pool.spawn_n(E.handle, new_sock.makefile('rw'))
        except (SystemExit, KeyboardInterrupt):
            break


    # tmp = 0
    # while(tmp < 10): #need a better loop condition
    #     print "listening " + str(tmp)
    #     s.listen(1)
    #     conn, addr = s.accept() # accept a voting client connection
    #     voter_id = conn.recv(buffer_size) # receive the voter's id
    #     conn.send(e.get_public()) # send the public paillier key over to the voter
    #             # encrypt these votes with the public paillier
    #             # encrypt with own key
    #             # send to the EB
    #     vote_array = conn.recv(buffer_size) # get a vote array from a voter
    #     if not (e.is_registered(voter_id)): # if the voter isn't registered...
    #         conn.send("ERROR: UNREGISTERED VOTER\n")
    #         conn.close()
    #         continue # go back to listening
    #     vote_array.append("verifiedxxxxx") # tack the verification token onto the end of the vote array
    #     conn.send(vote_array) # send it back to the client so they can unwrap their layer and pass it to the BB
    #     bb_array = conn.recv(buffer_size) # bb receives the array from the client
    #     if not (b.receive_vote(bb_array)): #ignore duplicate votes
    #         conn.send("ERROR: DUPLICATE VOTE\n")
    #         conn.close()
    #         continue # go back to listening
    #     tmp += 1

    # c.get_sum(b.get_votes(),e.get_public())

"""
TODO:
Deal with registration/candidate selection and init stuff for BB/EB/CA
Create the voting client and everything it does
Zero Knowledge Proof stuff
Figure out how we wanna do the voting period

bug test
"""

if __name__ == "__main__":
    main()
