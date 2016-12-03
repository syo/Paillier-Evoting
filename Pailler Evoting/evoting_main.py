#!/usr/bin/env python

from __future__ import print_function

import eventlet

import socket
import paillier.paillier as p
from Crypto.PublicKey import RSA
from Crypto.Util.number import getRandomRange, bytes_to_long, long_to_bytes, size, inverse, GCD
import json
import pickle
from pprint import pprint
import base64
import time
import sys
import hashlib
class EB:
    def __init__(self, voters, candidates):

        private_keyfile = open("keyserver/Private/EB_paillier.key", 'r')
        public_keyfile = open("keyserver/Public/EB_paillier_public.key", 'r')

        self.public = pickle.load(public_keyfile)
        self.private = pickle.load(private_keyfile)

        private_keyfile.close()
        public_keyfile.close()

        RSA_private_keyfile = open("keyserver/Private/EB_RSA.key", 'r')
        RSA_public_keyfile = open("keyserver/Public/EB_RSA_public.key", 'r')

        self.privateRSA = RSA.importKey(RSA_private_keyfile.read())
        self.publicRSA = RSA.importKey(RSA_public_keyfile.read())

        RSA_private_keyfile.close()
        RSA_public_keyfile.close()

        self.reg_voters = voters # list of ids for registered voters
        self.candidates = candidates
    def get_public(self): # func to get the public key
        return self.public
    def arr_decrypt(self, vlist):
        result = [0 for x in range(len(vlist))]
        for i in range(len(vlist)):
            [i] = p.decrypt(self.private,self.public,vlist[i])
        return result
    def announce_results(self, vlist): #used for decrypting the sum at the end
        results = self.arr_decrypt(vlist)
        for i in range(len(results)):
            print("Choice " + str(i) + " received " + str(results[i]) + " votes ")
    def is_registered(self, voter_id):
        return voter_id in self.reg_voters

    def register_voter(self, vote, auth, encrypted_id):
        found = True
        voter_id = self.privateRSA.decrypt(base64.b64decode(encrypted_id))
        for person in self.reg_voters:
            if (person["voter_id"] == voter_id):
                if "voted" in person and person["voted"]:
                    return json.dumps({"MESSAGE":"Not a valid VOTERID for voting at this time", "SUCCESS":False})
                found = True
                person["voted"] = True
                break
        if found:
            signed_vote = []
            for v in vote:
                try:
                    blinded = long(base64.b64decode(v))
                    signed = self.privateRSA.sign(blinded, 0)[0]
                    signed_vote.append(base64.b64encode(str(signed)))
                except OverflowError:
                    return json.dumps({"MESSAGE":"VOTE is too long to sign", "SUCCESS":False})

            signed_auth = ""

            try:
                blinded = long(base64.b64decode(auth))
                signed_auth = self.privateRSA.sign(blinded, 0)[0]
            except OverflowError:
                return json.dumps({"MESSAGE":"AUTH is too long to sign", "SUCCESS":False})

            return json.dumps({"MESSAGE":"Successful registration", "SUCCESS":True,"VOTE":signed_vote, "AUTH":base64.b64encode(str(signed_auth))})
        else:
            return json.dumps({"MESSAGE":"Not a valid VOTERID for voting at this time", "SUCCESS":False})

class BB:
    def __init__(self, n_voters, n_candidates):
        self.votes = []
        self.has_voted = []
        self.n_candidates = n_candidates
        self.n_voters = n_voters

        RSA_public_keyfile= open("keyserver/Public/EB_RSA_public.key", 'r')
        self.publicRSA = RSA.importKey(RSA_public_keyfile.read())
        RSA_public_keyfile.close()

    def get_votes(self):
        return self.votes
    def receive_vote(self, vote, auth):
        value = long(base64.b64decode(auth))
        decoded = long_to_bytes(self.publicRSA.encrypt(value,0)[0])
        # print("Auth:",decoded)
        if (auth in self.has_voted): # if you have already received this persons vote...
            return json.dumps({"MESSAGE":"Not a valid AUTH for voting at this time", "SUCCESS":False})

        if not decoded.startswith("Authorized Voter"):
            return json.dumps({"MESSAGE":"Not a valid AUTH for voting at this time", "SUCCESS":False})

        hash = hashlib.sha224()
        votes_enc = []
        for v in vote:
            val = long(base64.b64decode(v))
            enc = self.publicRSA.encrypt(value,0)[0]
            votes_enc.append(enc)
            hash.update(str(enc))

        authorization_token = "Authorized Voter "+hash.hexdigest()
        # if not decoded == authorization_token:
        #     print(decoded, authorization_token)
        #     return json.dumps({"MESSAGE":"Not a valid AUTH for your votes", "SUCCESS":False})

        if len(votes_enc) != self.n_candidates+1:
            return json.dumps({"MESSAGE":"Not a valid number of votes", "SUCCESS":False})

        if len(self.votes) == self.n_voters:
            return json.dumps({"MESSAGE":"All votes have already been submitted", "SUCCESS":False})

        self.has_voted.append(auth)
        self.votes.append(votes_enc)

        return json.dumps({"MESSAGE":"Votes recorded", "SUCCESS":True})

class CA:
    def __init__(self):
        public_keyfile = open("keyserver/Public/EB_paillier_public.key", 'r')
        self.public = pickle.load(public_keyfile)
        public_keyfile.close()

    def get_sum(self, vlist):
        totals = [p.encrypt(self.public,0) for x in range(len(vlist))] #initialize totals, leave out verification token
        for v in vlist: #add up encrypted vote totals
            totals = encrypted_arr_add(self.public,totals,v)
        return totals

class Election:
    def __init__(self,voters,candidates):
        self.eb = EB(voters, candidates) #initialize EB, BB, CA
        self.bb = BB(len(voters), len(candidates))
        self.ca = CA()
        self.candidates = candidates
        self.open = True

    def end_election(self):
        self.open = False
        totals = self.ca.get_sum(self.bb.votes)
        print("Election is over")
        self.eb.announce_results(totals)
        sys.exit(0)

    def get_candidates(self):
        return self.candidates

    def register_voter(self, m):
        vote = ""
        try:
            vote = m["VOTE"]
        except KeyError:
            return json.dumps({"MESSAGE":"Must include VOTE field", "SUCCESS":False})


        auth = ""
        try:
            auth = m["AUTHORIZATION"]
        except KeyError:
            return json.dumps({"MESSAGE":"Must include AUTHORIZATION field", "SUCCESS":False})
        voter_id = ""
        try:
            voter_id = m["VOTERID"]
        except KeyError:
            return json.dumps({"MESSAGE":"Must include VOTERID field", "SUCCESS":False})

        return self.eb.register_voter(vote, auth, voter_id)

    def receive_vote(self, m):
        vote = ""
        try:
            vote = m["VOTE"]
        except KeyError:
            return json.dumps({"MESSAGE":"Must include VOTE field", "SUCCESS":False})

        auth = ""
        try:
            auth = m["AUTHORIZATION"]
        except KeyError:
            return json.dumps({"MESSAGE":"Must include AUTHORIZATION field", "SUCCESS":False})
        voter_id = ""

        return self.bb.receive_vote(vote, auth)

    def get_response(self,message):
        m = json.loads(message)
        if not self.open:
            return json.dumps({"MESSAGE":"Election is Closed", "SUCCESS":False})

        type = ""
        try:
            type = m["TYPE"]
        except KeyError:
            return json.dumps({"MESSAGE":"Must include TYPE field", "SUCCESS":False})

        if type == "REQUEST CANDIDATES":
            return json.dumps({"MESSAGE":"CANIDATE DATA","DATA":self.get_candidates(), "SUCCESS":True})
        elif type == "REGISTER":
            return self.register_voter(m)
        elif type == "VOTE":
            return self.receive_vote(m)
        else:
            return json.dumps({"MESSAGE":"TYPE did not match any expected operation", "SUCCESS":False})

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
            # print("echoed", res, end=' ')
        print("client disconnected")


def encrypted_arr_add(pub,list1,list2):
    list3 = [0 for x in range(len(vlist) - 1)]
    for i in range(len(list1)):
        list3[i] = p.e_add(pub,list1[i],list2[i])
    return list3

def main():
    with open('database/registered.json') as data_file:
        voters = json.load(data_file)
    with open('database/candidates.json') as data_file2:
        candidates = json.load(data_file2)

    E = Election(voters, candidates)

    tcp_ip = '127.0.0.1' #set up a tcp server
    tcp_port = 5005

    time = 1
    # buffer_size = 1024
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.bind((tcp_ip,tcp_port))


    print("server socket listening on port",tcp_port)
    print("Election will be open for",time,"minutes")
    print("There are", len(candidates),"canidates and",len(voters),"registered voters")
    server = eventlet.listen((tcp_ip, tcp_port))
    pool = eventlet.GreenPool()
    eventlet.greenthread.spawn_after(time * 60, E.end_election)
    while E.open:
        try:
            new_sock, address = server.accept()
            # print("accepted", address)
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
Deal with registration/candidates selection and init stuff for BB/EB/CA
Create the voting client and everything it does
Zero Knowledge Proof stuff
Figure out how we wanna do the voting period

bug test
"""

if __name__ == "__main__":
    main()
