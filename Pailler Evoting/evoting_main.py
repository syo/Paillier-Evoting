#!/usr/bin/env python

from paillier.paillier import paillier as p

class EB:
    def __init__(self):
        self.public, self.private = p.generate_keypair(512)
    def get_public(self):
        return self.public
    def decrypt_sum(self, csum):
        return p.decrypt(self.private,self.public,csum)
    def send_vote(self, voter, vote, b):
        b.set_row(voter, [ p.encrypt(self.public, v) for v in vote ])

class BB:
    def __init__(self, n, m):
        self.table = [ [ x for x in range(0, m) ] for y in range (0, n) ]
        self.voters = [ 0, 1, 2, 3, 4 ] # replace with ids or whatever
    def get_row(self, i):
        return self.table[i]
    def get_column(self, i):
        return [ self.table[x][i] for x in range(len(self.table)) ]

class CA:
    def get_sum(self, list):
        return sum(list)

def __main__():
    e = EB()
    b = BB(10, 5)
    c = CA()
