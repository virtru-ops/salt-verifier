"""
Client for the salt verifier server
"""
import zmq
import M2Crypto
import hashlib


def is_valid_server_public_key(address, public_key_str):
    context = zmq.Context()
    socket = context.socket(zmq.REQ)

    public_key_bio = M2Crypto.BIO.MemoryBuffer(public_key_str)
    public_key = M2Crypto.RSA.load_pub_key_bio(public_key_bio)

    challenge_message = 'abc'

    encrypted_challenge_message = public_key.public_encrypt(
        challenge_message,
        M2Crypto.RSA.pkcs1_oaep_padding
    )

    socket.connect(address)

    socket.send(encrypted_challenge_message.encode('base64'))

    response = socket.recv()

    response_split = response.split(';')

    if response_split[0] != '200':
        return False

    challenge_signature_base64 = response_split[1]

    challenge_signature = challenge_signature_base64.decode('base64')

    challenge_digest = hashlib.sha256()

    challenge_digest.update(challenge_message)

    verification_result = public_key.verify_rsassa_pss(
        challenge_digest.digest(),
        challenge_signature
    )

    if verification_result != 1:
        return False

    return True
