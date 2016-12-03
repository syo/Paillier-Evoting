# Paillier-Evoting

## Roles
Connor: Paillier encryption / decryption & tabulation
Jacob: Client stuff
Kiana: BB and ZKP


## Scheme: 
EB has a known RSA public key & hidden private
EB has a known Paillier public key & hidden private


Voter has private blind signature keys 


1. Voter:
   1. Requests candidates
   2. Generates vote V & encrypts using EB’s public Paillier
   3. Creates authorization token A using known string and hash of encrypted vote
   4. Generates ZKP of correctness & validity of votes
   5. Blinds A & V using private keys
1. Voter submits blinded A to EB
   1. EB verifies registration
   2. EB signs blinded A with private RSA
   3. Returns signed, blinded A to voter 
   4. Voter un-blinds A
1. Voter: 
   1. Submits signed A & V, and ZKP
1. BB:
   1. Decrypts encrypted, signed A & V
   2. Verifies validity of A & signature using EB’s public RSA & checks for string
   3. Verifies validity of V using using EB’s public RSA, hash in A, & ZKP
   4. Saves V
1. Upon election close: 
   1. BB sends all V to CA
   2. CA sums all votes
   3. CA sends sums to EB
   4. EB decrypts using private Paillier & releases results

## Requirements:
1. python2.7
2. Update Pailler Evoting/paillier submodule (https://github.com/kcmcnellis/paillier.git)
3. ```pip install -r requirements.txt```

## To run:
1. ```cd Pailler\ Evoting```
2. ```python evoting_main.py```
3. ```python evoting_client.py```
