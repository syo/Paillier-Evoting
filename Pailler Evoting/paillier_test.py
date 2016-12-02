#!/usr/bin/env python

import paillier
import paillier.paillier as p



has_voted = [] #store people who have voted in an array

print "Generating keypair..."
priv, pub = p.generate_keypair(1024) #generate public and private keys
#public key gets given to voters to encrypt their votes

csum = p.encrypt(pub, 0) #store the encrypted sum of all votes, turn this into an array with slots for each candidate later

x = int(input("Enter 1 to vote yes and 0 to vote no: ")) #have user input their votes somehow and store the encrypted votes in some array cx
print "x =", x
print "Encrypting x..."
cx = p.encrypt(pub, x)
print "cx =", cx
csum = p.e_add(pub, cx, csum) #add the encrypted votes to the encrypted sum

y = int(input("Enter 1 to vote yes and 0 to vote no: "))
print "y =", y
print "Encrypting y..."
cy = p.encrypt(pub, y)
print "cy =", cy
csum = p.e_add(pub, cy, csum)

print "Computing encrypted total..."
print "csum = ", csum

print "Decrypting csum..."
dsum = p.decrypt(priv, pub, csum) #decrypt the sum using both keys to find the total votes while preserving privacy
print "vote total =", dsum




# THE PROCESS
# Voter registers to vote, gets given public key by EB, encrypts vote with EB key then that with own key
# encrypts his votes with the EB's public paillier key and sends it to the EB
# id also gets sent over with just ssh encryption or whatever
# EB verifies that the id is registered and signs last slot of vote array with "verifiedxxxxx" or whatever, some hash value or something based on the id
# this gets sent back to voter, who decrypts with his own key
# zero knowledge proof with BB, make sure vote is 1 or 0
# encrypted votes get sent to the BB
# BB checks to make sure your votes are verified by the EB
# check for duplicates, reject if duplicate
# once all votes are in/voting period is done, send all encrypted votes to the counting authority
# counting authority basically just gets encrypted votes and outputs encrypted sums to the EB
# encrypted sums are sent to the EB which decrypts them and announces the results
