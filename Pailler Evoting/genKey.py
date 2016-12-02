#!/usr/bin/env python

import paillier
import paillier.paillier as p
import rsa
import pickle

res = raw_input("Enter '1' for EB_paillier, '2' for EB_RSA, or '3' for BB_RSA: ")

if (res == "1"): #EB_paillier
    print "Generating keypair..."
    priv, pub = p.generate_keypair(1024) #generate public and private keys
    #public key gets given to voters to encrypt their votes

    private_keyfile = open("keyserver/Private/EB_paillier.key", 'w')
    public_keyfile = open("keyserver/Public/EB_paillier_public.key", 'w')

    pickle.dump(priv,private_keyfile)
    pickle.dump(pub,public_keyfile)


if (res == "2"): #EB_RSA
    print "Generating keypair..."
    (priv, pub) = rsa.newkeys(1024)
    #public key gets given to voters to encrypt their votes

    private_keyfile = open("keyserver/Private/EB_RSA.key", 'w')
    public_keyfile = open("keyserver/Public/EB_RSA_public.key", 'w')

    pickle.dump(priv,private_keyfile)
    pickle.dump(pub,public_keyfile)

if (res == "3"): #EB_RSA
    print "Generating keypair..."
    (priv, pub) = rsa.newkeys(1024)
    #public key gets given to voters to encrypt their votes

    private_keyfile = open("keyserver/Private/BB_RSA.key", 'w')
    public_keyfile = open("keyserver/Public/BB_RSA_public.key", 'w')

    pickle.dump(priv,private_keyfile)
    pickle.dump(pub,public_keyfile)

private_keyfile.close()
public_keyfile.close()
