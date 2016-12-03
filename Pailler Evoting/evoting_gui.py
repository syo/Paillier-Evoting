from __future__ import print_function

import eventlet
import pickle
import json
import paillier.paillier as p
from pprint import pprint
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Util.number import getRandomRange, bytes_to_long, long_to_bytes, size, inverse, GCD
import base64

from Tkinter import *

root = Tk()

def submit_vote(choice_val, voter_id, candidates):
    paillierKeyfile = open("keyserver/Public/EB_paillier_public.key", 'r')
    paillierKey = pickle.load(paillierKeyfile)
    paillierKeyfile.close()

    rsaKeyfile = open("keyserver/Public/EB_RSA_public.key", 'r')
    rsaKey = RSA.importKey(rsaKeyfile.read())
    rsaKeyfile.close()

    blindKey = p.getRandomModNStar(rsaKey.n)

    statusLabel = Label(root)
    statusLabel.pack(side=LEFT)

    vote = [0 for i in xrange(len(candidates)+1)]
    vote[choice_val] = 1
    authorization_token = "Voter"
    encrypted_vote = []
    hash = hashlib.sha224()
    znp = []
    statusLabel["text"] = "Encrypting Vote"
    root.update_idletasks()
    for i,v in enumerate(vote):
        # crypto = rsa.encrypt(v, key1)
        crypto,r = p.encryptFactors(paillierKey, v)
        proof = p.genZKP(paillierKey, v, crypto, r)
        znp.append(proof)
        encrypted_vote.append(crypto)
        hash.update(str(crypto))

    authorization_token = "Authorized Voter "+hash.hexdigest()

    blinded_vote = []
    blinded_r = []
    for i,v in enumerate(encrypted_vote):
        rand = getRandomRange(1, rsaKey.key.n-1, randfunc=rsaKey._randfunc)
        blinded_r.append(rand)

        blinded = rsaKey.key._blind(v, rand)
        # h = rsaKeyPriv.sign(blinded, 0)[0]
        # i = rsaKey.key._unblind(h, rand)
        # j = rsaKey.encrypt(i, 0)[0]
        blinded_vote.append(base64.b64encode(str(blinded)))

    auth_r = getRandomRange(1, rsaKey.key.n-1, randfunc=rsaKey._randfunc)

    a = bytes_to_long(authorization_token)
    # blinded = (a * pow(auth_r, rsaKeyPriv.e, rsaKeyPriv.n)) % rsaKeyPriv.n #blind
    blinded = rsaKey.key._blind(a, auth_r)
    # h = pow(blinded,rsaKeyPriv.d,rsaKeyPriv.n) #sign
    # h = rsaKeyPriv.sign(blinded, 0)[0]
    # i =  inverse(auth_r, rsaKey.n) * h % rsaKey.n #unblind
    # i = rsaKey.key._unblind(h, auth_r)
    # j = pow(i,rsaKey.e,rsaKey.n) #decrypt
    # j = rsaKey.encrypt(i, 0)[0]

    encrypted_id = rsaKey.encrypt(voter_id, 0)
    statusLabel["text"] = "Registering your vote"
    root.update_idletasks()

    message = json.dumps({"TYPE":"REGISTER", "VOTE":blinded_vote, "AUTHORIZATION":base64.b64encode(str(blinded)), "VOTERID": base64.b64encode(encrypted_id[0])})

    client.sendall(message+"\n")
    response = client.recv(buffer_size)
    r = json.loads(response)
    if not "SUCCESS" in r or not r["SUCCESS"]:
        statusLabel["text"] = "Operation Failed.", r["MESSAGE"]
        root.update_idletasks()
        return

    signed_blinded_vote = r["VOTE"]
    signed_vote = []

    for i in xrange(len(signed_blinded_vote)):
        v = long(base64.b64decode(signed_blinded_vote[i]))
        rand = blinded_r[i]

        unblinded = rsaKey.key._unblind(v, rand)

        signed_vote.append(base64.b64encode(str(unblinded)))


    signed_blinded_auth = long(base64.b64decode(r["AUTH"]))
    signed_auth = rsaKey.key._unblind(signed_blinded_auth, auth_r)
    statusLabel["text"] = "Submitting your vote"
    root.update_idletasks()

    message = json.dumps({"TYPE":"VOTE", "ZNP":znp,"VOTE":signed_vote, "AUTHORIZATION":base64.b64encode(str(signed_auth))})

    client.sendall(message+"\n")
    response = client.recv(buffer_size)
    r = json.loads(response)
    if not "SUCCESS" in r or not r["SUCCESS"]:
        statusLabel["text"] = "Operation Failed.", r["MESSAGE"]
        root.update_idletasks()
        return
    else:
        statusLabel["text"] = "Successful vote"
        root.update_idletasks()

def main():
    choice_val = IntVar()

    # Get candidates
    message = json.dumps({"TYPE":"REQUEST CANDIDATES"})
    client.sendall(message+"\n")
    response = client.recv(buffer_size)
    r = json.loads(response)
    if not "SUCCESS" in r or not r["SUCCESS"]:
        statusLabel["text"] = "Operation Failed.", r["MESSAGE"]
        root.update_idletasks()
        return

    candidates = r["DATA"]

    buttons = []

    buttons.append(Radiobutton(root, text ="None", variable=choice_val, value=0))
    buttons[0].pack(anchor = W)
    for i, can in enumerate(candidates):
        buttons.append(Radiobutton(root, text ="{}".format(can["name"]), variable=choice_val, value=i+1))
        buttons[i+1].pack(anchor = W)

    idLabel = Label(root)
    idLabel["text"] = "Enter your voter id:"
    idLabel.pack(side=LEFT)
    voter_id = Entry(root)
    voter_id["width"] = 50
    voter_id.pack(side=LEFT)

    vote = Button(root, text="Send Vote", command=lambda: submit_vote(choice_val.get(), voter_id.get().strip(), candidates))
    vote.pack()

    label = Label(root)
    label.pack()
    root.mainloop()

if __name__ == "__main__":
    tcp_ip = '127.0.0.1' #set up a tcp server
    tcp_port = 5005
    buffer_size = 4096
    client = eventlet.connect((tcp_ip, tcp_port))
    main()
