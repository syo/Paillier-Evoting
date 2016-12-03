#!/usr/bin/env python

import paillier.paillier as p
from Crypto.PublicKey import RSA
import pickle

res = raw_input("Enter '1' for EB_paillier, '2' for EB_RSA, or '3' for BB_RSA: ")

if (res == "1"): #EB_paillier
    print "Generating keypair..."
    priv, pub = p.generate_keypair(512) #generate public and private keys
    #public key gets given to voters to encrypt their votes

    private_keyfile = open("keyserver/Private/EB_paillier.key", 'w')
    public_keyfile = open("keyserver/Public/EB_paillier_public.key", 'w')

    pickle.dump(priv,private_keyfile)
    pickle.dump(pub,public_keyfile)


if (res == "2"): #EB_RSA
    print "Generating keypair..."
    priv = RSA.generate(2048)
    pub = priv.publickey()
    #public key gets given to voters to encrypt their votes

    private_keyfile = open("keyserver/Private/EB_RSA.key", 'w')
    public_keyfile = open("keyserver/Public/EB_RSA_public.key", 'w')
    private_keyfile.write(priv.exportKey('PEM'))
    public_keyfile.write(pub.exportKey('PEM'))

if (res == "3"): #EB_RSA
    print "Generating keypair..."
    priv = RSA.generate(2048)
    pub = priv.publickey()
    #public key gets given to voters to encrypt their votes

    private_keyfile = open("keyserver/Private/BB_RSA.key", 'w')
    public_keyfile = open("keyserver/Public/BB_RSA_public.key", 'w')

    private_keyfile.write(priv.exportKey('PEM'))
    public_keyfile.write(pub.exportKey('PEM'))

private_keyfile.close()
public_keyfile.close()
