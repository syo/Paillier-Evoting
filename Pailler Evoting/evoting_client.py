from __future__ import print_function

import eventlet
import pickle
import json
import paillier.paillier as p
from pprint import pprint
import hashlib
import rsa
import base64
def main():
    tcp_ip = '127.0.0.1' #set up a tcp server
    tcp_port = 5005
    # buffer_size = 1024
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.bind((tcp_ip,tcp_port))
    print("Generating keypair...")
    # (key1, key2) = rsa.newkeys(4096,poolsize=4)
    paillierKeyfile = open("keyserver/Public/EB_paillier_public.key", 'r')
    paillierKey = pickle.load(paillierKeyfile)
    rsaKeyfile = open("keyserver/Public/EB_RSA_public.key", 'r')
    rsaKey = pickle.load(rsaKeyfile)

    blindKey = p.getRandomModNStar(rsaKey.n)

    rsaKeyfile = open("keyserver/Public/BB_RSA_public.key", 'r')
    rsaKeyBB = pickle.load(rsaKeyfile)

    # voter_id = raw_input("Enter your voter ID to start voting:\n")
    voter_id = "95f173b7-d072-4700-9d64-857e79c12ff1"
    client = eventlet.connect((tcp_ip, tcp_port))

    # Get candidates
    message = json.dumps({"TYPE":"REQUEST CANDIDATES"})
    client.sendall(message+"\n")
    response = client.recv(1024)
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
        choice = raw_input("Enter the number of your chosen canidate:\n")
        try:
            choice_val = int(choice)
            if (choice_val > len(candidates)+1) or (choice_val < 1):
                print("Invalid number, try again")
            else:
                print("You chose candidate "+str(choice_val)+": "+candidates[choice_val-1]["name"]+". Is this correct?")
                accept = raw_input("Enter 'yes' to accept, or 'no' to return to selection:\n")
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
    print("Encrypting vote")
    for i,v in enumerate(vote):
        print(str(i+1)+"/"+str(len(vote)))
        # crypto = rsa.encrypt(v, key1)
        crypto,r = p.encryptFactors(paillierKey, v)
        proof = {"c":crypto, "r":r, "m":v}

        znp.append(proof)
        encrypted_vote.append(crypto)
        hash.update(str(crypto))
    authorization_token = "Authorized Voter "+hash.hexdigest()

    print("Blinding vote")
    blinded_vote = []
    for i,v in enumerate(encrypted_vote):
        crypto = p.blind(blindKey, rsaKey,str(v))
        blinded_vote.append(base64.b64encode(crypto))
        print(str(i+1)+"/"+str(len(vote)))

    print("Blinding auth & ID")
    blinded_auth = base64.b64encode(p.blind(blindKey, rsaKey,authorization_token))
    encrypted_id = base64.b64encode(rsa.encrypt(voter_id, rsaKey))

    message = json.dumps({"TYPE":"REGISTER", "VOTE":blinded_vote, "AUTHORIZATION":authorization_token, "VOTERID": encrypted_id})

    client.sendall(message+"\n")
    response = client.recv(1024)
    r = json.loads(response)
    if not "SUCCESS" in r or not r["SUCCESS"]:
        print("Operation Failed.", r["MESSAGE"])
        return

    signed_blinded_vote = r["VOTE"]
    signed_vote = []
    print("Unblind votes")
    for v in signed_blinded_vote:
        v2 = p.unblind(blindKey, rsaKey,base64.b64decode(v))
        signed_vote.append(v2)
        print(len(signed_vote),":",rsa.decrypt(vs,rsaKey))

    print("Unblind auth")
    signed_blinded_auth = base64.b64decode(r["AUTH"])
    signed_auth= p.unblind(blindKey, rsaKey,signed_blinded_auth)
    print("auth:",rsa.decrypt(signed_auth,rsaKey))

    print("Encrypt auth for bb")
    encrypted_auth = base64.b64encode(rsa.encrypt(signed_auth,rsaKeyBB))
    print("Encrypt votes for bb")
    encrypted_vote = []

    for v in signed_vote:
        v2 = rsa.encrypt(v,rsaKeyBB)
        encrypted_vote.append(base64.b64encode(v2))

if __name__ == "__main__":
    main()
