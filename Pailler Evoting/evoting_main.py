#!/usr/bin/env python

import socket
from paillier.paillier import paillier as p

class EB:
    def __init__(self, reg_list):
        self.public, self.private = p.generate_keypair(512) # paillier key pair for signing votes
        self.reg_voters = reg_list # list of ids for registered voters
    def get_public(self): # func to get the public key
        return self.public
    def arr_decrypt(self, vlist):
        result = [0 for x in range(len(vlist))]
        for i in range(len(vlist)):
            [i] = p.decrypt(self.private,self.public,vlist[i])
        announce_results(result)
    def announce_results(self, results): #used for decrypting the sum at the end
        for i in range(len(results)):
            print "Choice " + str(i) + " received " + str(results[i]) + " votes "
    def is_registered(self, voter_id):
        return voter_id in self.reg_voters
    def send_vote(self, voter, vote, b):
        b.set_row(voter, [ p.encrypt(self.public, v) for v in vote ])

class BB:
    def __init__(self, n, m):
        self.table = [ [ x for x in range(0, m) ] for y in range (0, n) ]
        self.has_voted = []
        self.votes = []
    def get_row(self, i):
        return self.table[i]
    def get_column(self, i):
        return [ self.table[x][i] for x in range(len(self.table)) ]
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

def encrypted_arr_add(pub,list1,list2):
    list3 = [0 for x in range(len(vlist) - 1)]
    for i in range(len(list1)):
        list3[i] = p.e_add(pub,list1[i],list2[i])
    return list3

def __main__():
    e = EB([0,1,2,3,4]) #initialize EB, BB, CA
    b = BB(10, 5)
    c = CA()

    tcp_ip = '127.0.0.1' #set up a tcp server
    tcp_port = 5005
    buffer_size = 1024
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(tcp_ip,tcp_port)

    tmp = 0
    while(tmp < 10): #need a better loop condition
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
            continue # go back to listening
        vote_array.append("verifiedxxxxx") # tack the verification token onto the end of the vote array
        conn.send(vote_array) # send it back to the client so they can unwrap their layer and pass it to the BB
        bb_array = conn.recv(buffer_size) # bb receives the array from the client
        if (!(b.receive_vote(bb_array))): #ignore duplicate votes
            conn.send("ERROR: DUPLICATE VOTE\n")
            conn.close()
            continue # go back to listening
        tmp += 1

    c.get_sum(b.get_votes(),e.get_public())
