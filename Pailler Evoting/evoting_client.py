from __future__ import print_function

import eventlet
import pickle
import json
import paillier
import paillier.paillier as p
from pprint import pprint


def main():
    tcp_ip = '127.0.0.1' #set up a tcp server
    tcp_port = 5005
    # buffer_size = 1024
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.bind((tcp_ip,tcp_port))


    raw_input("Press enter to start voting")
    client = eventlet.connect((tcp_ip, tcp_port))

    # Get canidates
    message = json.dumps({"TYPE":"REQUEST CANIDATES"})
    client.sendall(message+"\n")
    response = client.recv(1024)
    r = json.loads(response)
    canidates = r["DATA"]

    print("Your canidates for this election are:")
    for i, can in enumerate(canidates):
        print(str(i+1)+") "+can["name"])

    done = False
    choice_val = -1
    while not done:
        choice = raw_input("Enter the number of your chosen canidate")
        try:
            choice_val = int(choice)
            if (choice_val > len(canidates)+1) or (choice_val < 1):
                print("Invalid number, try again")
            else:
                print("You chose canidate "+canidates[choice_val-1]+". Is this correct?")
                accept = raw_input("Enter 'yes' to accept, or 'no' to return to selection")
                if (accept == "yes"):
                    done = True

        except ValueError:
           print("Invalid entry, try again")

    vote = [0 for i in xrange(len(canidates)+1)]
    vote[choice_val] = 1
    authorization_token = "Voter"


if __name__ == "__main__":
main()
