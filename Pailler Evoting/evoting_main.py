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
        return [p.decrypt(self.private,self.public,x) for x in vlist]
    def announce_results(self, vlist): #used for decrypting the sum at the end
        results = self.arr_decrypt(vlist)
        max_votes = 0
        canidate_num = []
        for i in xrange(1,len(results)):
            if results[i] > max_votes:
                canidate_num = [i]
                max_votes = results[i]
            elif results[i] == max_votes:
                canidate_num.append(i)


        if max_votes == 0:
            print("No winner in the election.")
        elif len(canidate_num) == 1:
            winner = self.candidates[canidate_num[0]-1]
            print(winner["name"] + " won the election, with " + str(max_votes) + " votes")
        elif len(canidate_num) > 1:
            print(len(canidate_num), "canidates tied in the election, with", max_votes, "votes:")
            for c in canidate_num:
                winner = self.candidates[c-1]
                print(winner["name"])

    def is_registered(self, voter_id):
        return voter_id in self.reg_voters

    def register_voter(self, vote, auth, encrypted_id):
        found = False
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

        public_keyfile = open("keyserver/Public/EB_paillier_public.key", 'r')
        self.public = pickle.load(public_keyfile)
        public_keyfile.close()

    def get_votes(self):
        return self.votes
    def receive_vote(self, vote, auth, znp, znp_set):
        value = long(base64.b64decode(auth))
        decoded = long_to_bytes(self.publicRSA.encrypt(value,0)[0])
        # print("Auth:",decoded)
        if (auth in self.has_voted): # if you have already received this persons vote...
            return json.dumps({"MESSAGE":"Not a valid AUTH for voting at this time", "SUCCESS":False})

        if not decoded.startswith("Authorized Voter"):
            return json.dumps({"MESSAGE":"Not a valid AUTH for voting at this time", "SUCCESS":False})

        votes_enc = []

        for v in vote:
            val = long(base64.b64decode(v))
            enc = self.publicRSA.encrypt(val, 0)[0]
            votes_enc.append(enc)

        if len(votes_enc) != self.n_candidates+1:
            return json.dumps({"MESSAGE":"Not a valid number of votes", "SUCCESS":False})

        if len(self.votes) == self.n_voters:
            return json.dumps({"MESSAGE":"All votes have already been submitted", "SUCCESS":False})

        for i, proof in enumerate(znp): # Proof of knowledge of message contents
            try:
                n = self.public.n
                n_sq = self.public.n_sq
                g = self.public.g
                x = proof["x"]
                s = proof["s"]
                u = proof["u"]
                e = proof["e"]
                v = proof["v"]
                w = proof["w"]

                if not p.inModN(x,n) or not p.inModNStar(s,n) or not p.inModN(e,n):
                    return json.dumps({"MESSAGE":"Invalid ZNP (inModN)", "SUCCESS":False})

                if not e == p.hash(x,s) % n:
                    return json.dumps({"MESSAGE":"Invalid ZNP (e)", "SUCCESS":False})

                if not u == (pow(g, x, n_sq) * pow(s, n, n_sq)) % n_sq:
                    return json.dumps({"MESSAGE":"Invalid ZNP (u)", "SUCCESS":False})


                result = (pow(g, v, n_sq)*pow(votes_enc[i], e, n_sq)*pow(w, n, n_sq)) % n_sq
                if not result == u:
                    return json.dumps({"MESSAGE":"Invalid ZNP(result)", "SUCCESS":False})

            except KeyError:
                return json.dumps({"MESSAGE":"Invalid ZNP", "SUCCESS":False})

        for i, proof in enumerate(znp_set): # Proof of message is 0 or 1
            try:
                n = self.public.n
                n_sq = self.public.n_sq
                g = self.public.g
                Set = proof["S"]
                eTotal = proof["e"]

                if not eTotal == (p.hash(Set[0]["u"],Set[1]["u"]) % n):
                    return json.dumps({"MESSAGE":"Invalid ZNPSET (e generation)", "SUCCESS":False})

                if not eTotal == ((Set[0]["e"] + Set[1]["e"]) % n):
                    return json.dumps({"MESSAGE":"Invalid ZNPSET (e sum)", "SUCCESS":False})

                for j,msg in enumerate(Set):
                    u = msg["u"]
                    v = msg["v"]
                    e = msg["e"]
                    m = msg["m"]

                    nume = pow(votes_enc[i],e,n_sq)
                    denom = pow(g,m*e,n_sq)
                    result = (u * nume * p.invmod(denom,n_sq)) % n_sq
                    if not m == j:
                        return json.dumps({"MESSAGE":"Invalid ZNPSET (order)", "SUCCESS":False})

                    if not v == result:
                        return json.dumps({"MESSAGE":"Invalid ZNPSET (result)", "SUCCESS":False})

            except KeyError:
                return json.dumps({"MESSAGE":"Invalid ZNPSET", "SUCCESS":False})




        self.has_voted.append(auth)
        self.votes.append(votes_enc)

        return json.dumps({"MESSAGE":"Votes recorded", "SUCCESS":True})

class CA:
    def __init__(self):
        public_keyfile = open("keyserver/Public/EB_paillier_public.key", 'r')
        self.public = pickle.load(public_keyfile)
        public_keyfile.close()

    def get_sum(self, vlist):
        totals = []
        if (len(vlist)) < 1:
            return totals
        for i in range(len(vlist[0])): #add up encrypted vote totals
            totals.append(self.get_candidate_total(i, vlist))
        return totals

    def get_candidate_total(self, i, vlist):
        candidate_votes = [vlist[x][i] for x in range(len(vlist))]
        return reduce(lambda x, y: p.e_add(self.public, x, y), candidate_votes)

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
        znp = ""
        try:
            znp = m["ZNP"]
        except KeyError:
            return json.dumps({"MESSAGE":"Must include ZNP field", "SUCCESS":False})

        znp_set = ""
        try:
            znp_set = m["ZNPSET"]
        except KeyError:
            return json.dumps({"MESSAGE":"Must include ZNPSET field", "SUCCESS":False})

        return self.bb.receive_vote(vote, auth, znp, znp_set)

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


def main():
    with open('database/registered.json') as data_file:
        voters = json.load(data_file)
    with open('database/candidates.json') as data_file2:
        candidates = json.load(data_file2)

    E = Election(voters, candidates)

    tcp_ip = '127.0.0.1' #set up a tcp server
    tcp_port = 5005

    time = 10 # How many minutes the election runs for

    print("server socket listening on port",tcp_port)
    print("Election will be open for",time,"minutes")
    print("There are", len(candidates),"canidates and",len(voters),"registered voters")
    server = eventlet.listen((tcp_ip, tcp_port))
    pool = eventlet.GreenPool()
    eventlet.greenthread.spawn_after(time * 60, E.end_election)
    while E.open:
        try:
            new_sock, address = server.accept()
            # Spawn a new co-routine per client connection
            pool.spawn_n(E.handle, new_sock.makefile('rw'))
        except (SystemExit, KeyboardInterrupt):
            break


if __name__ == "__main__":
    main()
