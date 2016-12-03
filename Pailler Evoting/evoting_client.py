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

def main():
    tcp_ip = '127.0.0.1' #set up a tcp server
    tcp_port = 5005
    buffer_size = 4096
    print("Connecting to the server")
    client = eventlet.connect((tcp_ip, tcp_port))
    paillierKeyfile = open("keyserver/Public/EB_paillier_public.key", 'r')
    paillierKey = pickle.load(paillierKeyfile)
    paillierKeyfile.close()

    rsaKeyfile = open("keyserver/Public/EB_RSA_public.key", 'r')
    rsaKey = RSA.importKey(rsaKeyfile.read())
    rsaKeyfile.close()

    blindKey = p.getRandomModNStar(rsaKey.n)
    # voter_id = raw_input("Enter your voter ID to start voting:\n")
    voter_id = "95f173b7-d072-4700-9d64-857e79c12ff1"

    print("Getting canidates")
    # Get candidates
    message = json.dumps({"TYPE":"REQUEST CANDIDATES"})
    client.sendall(message+"\n")
    response = client.recv(buffer_size)
    r = json.loads(response)
    if not "SUCCESS" in r or not r["SUCCESS"]:
        print("Operation Failed.", r["MESSAGE"])
        return

    candidates = r["DATA"]

    print("Your candidates for this election are:")
    for i, can in enumerate(candidates):
        print(str(i+1)+") "+can["name"])

    done = False
    choice_val = -1
    while not done:
        # choice = raw_input("Enter the number of your chosen canidate:\n")
        choice = 1
        try:
            choice_val = int(choice)
            if (choice_val > len(candidates)+1) or (choice_val < 1):
                print("Invalid number, try again")
            else:
                print("You chose candidate "+str(choice_val)+": "+candidates[choice_val-1]["name"]+". Is this correct?")
                # accept = raw_input("Enter 'yes' to accept, or 'no' to return to selection:\n")
                accept = "yes"
                if (accept == "yes"):
                    done = True

        except ValueError:
           print("Invalid entry, try again")

    vote = [0 for i in xrange(len(candidates)+1)]
    vote[choice_val] = 1
    authorization_token = "Voter"
    encrypted_vote = []
    hash = hashlib.sha224()
    znp = []
    znp_set = []
    print("Encrypting vote")
    for i,v in enumerate(vote):
        print(str(i+1)+"/"+str(len(vote)))
        # crypto = rsa.encrypt(v, key1)
        crypto,r = p.encryptFactors(paillierKey, v)
        proof = p.genZKP(paillierKey, v, crypto, r)
        proof_set = p.genZKPset(paillierKey, v, crypto, r)
        znp.append(proof)
        znp_set.append(proof_set)
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
    print("Registering your vote")

    message = json.dumps({"TYPE":"REGISTER", "VOTE":blinded_vote, "AUTHORIZATION":base64.b64encode(str(blinded)), "VOTERID": base64.b64encode(encrypted_id[0])})

    client.sendall(message+"\n")
    response = client.recv(buffer_size)
    r = json.loads(response)
    if not "SUCCESS" in r or not r["SUCCESS"]:
        print("Operation Failed.", r["MESSAGE"])
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
    print("Submitting your vote")

    message = json.dumps({"TYPE":"VOTE", "ZNP":znp,"ZNPSET":znp_set,"VOTE":signed_vote, "AUTHORIZATION":base64.b64encode(str(signed_auth))})

    client.sendall(message+"\n")
    response = client.recv(buffer_size)
    r = json.loads(response)
    if not "SUCCESS" in r or not r["SUCCESS"]:
        print("Operation Failed.", r["MESSAGE"])
        return
    else:
        print("Successful vote")

if __name__ == "__main__":
    main()
