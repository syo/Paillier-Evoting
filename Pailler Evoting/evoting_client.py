from __future__ import print_function

import eventlet
import pickle
import json
import paillier
import paillier.paillier as p
from pprint import pprint
import hashlib
import rsa

def main():
    tcp_ip = '127.0.0.1' #set up a tcp server
    tcp_port = 5005
    # buffer_size = 1024
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.bind((tcp_ip,tcp_port))

    (key1, key2) = rsa.newkeys(1024)
    paillierKeyfile = open("keyserver/Public/EB_paillier_public.key", 'r')
    paillierKey = pickle.load(paillierKeyfile)
    rsaKeyfile = open("keyserver/Public/EB_RSA_public.key", 'r')
    rsaKey = pickle.load(rsaKeyfile)

    voter_id = raw_input("Enter your voter ID to start voting:\n")
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

    print("Encrypting vote")
    for i,v in enumerate(vote):
        # crypto = rsa.encrypt(v, key1)
        crypto = p.encrypt(paillierKey, v)
        encrypted_vote.append(crypto)
        hash.update(str(crypto))
        print(str(i)+"/"+len(vote))
    authorization_token = "Authorized Voter "+hash.hexdigest()

    print("Blinding vote")
    blinded_vote = []
    for i,v in enumerate(encrypted_vote):
        crypto = rsa.encrypt(v, key1)
        blinded_vote.append(str(crypto))
        print(str(i)+"/"+len(vote))

    blinded_auth = rsa.encrypt(authorization_token,key1)
    encrypted_id = rsa.encrypt(voter_id, rsaKey)

    message = json.dumps({"TYPE":"REGISTER", "VOTE":blinded_vote, "AUTHORIZATION":authorization_token, "VOTERID": encrypted_id})
    client.sendall(message+"\n")
    response = client.recv(1024)
    r = json.loads(response)
    if not "SUCCESS" in r or not r["SUCCESS"]:
        print("Operation Failed.", r["MESSAGE"])
        return



if __name__ == "__main__":
    main()
