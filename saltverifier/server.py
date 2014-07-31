"""
A simple challenge response server

Request:

    encrypted-message-of-challenge

Response:

    status-code;body-of-response

Good response:

    200-299;base64 of rsa-sha256 of challenge

Bad response:

    400-599;error-message
"""
import os
import sys
import argparse
import time
import hashlib
import zmq
import M2Crypto
import logging
# Setup the logging to be json
logging.basicConfig(
    format='{"message": "%(message)s", "level": "%(levelname)s", timestamp: "%(asctime)s"}',
    level=logging.INFO,
    stream=sys.stderr
)

DESCRIPTION = 'A simple challenge response server for this salt minions key'

parser = argparse.ArgumentParser(description=DESCRIPTION)
parser.add_argument('--port', type=int, default=4533,
                    help='Port to run the server')
parser.add_argument('--private-key-path', default='/etc/salt/pki/minion/minion.pem',
                    help="The path to the minion's key")


class ChallengeResponseServer():
    def __init__(self, port, private_key):
        self._port = port
        self._private_key = private_key

    def serve(self):
        logging.info('Starting salt-verifier challenge response server')
        try:
            self._server_loop()
        except KeyboardInterrupt:
            logging.info('Shutting down salt-verifier challenge response server')
            pass

    def _server_loop(self):
        context = zmq.Context()
        socket = context.socket(zmq.REP)
        socket.bind('tcp://0.0.0.0:%s' % self._port)

        while True:
            # Wait a little to start a bit... for good measure
            time.sleep(1)

            # Wait for the next request from the client
            encrypted_challenge_message = socket.recv()

            logging.info('received message')
            logging.debug(encrypted_challenge_message)

            # Attempt to decrypt the message
            try:
                challenge_message = self.decrypt(encrypted_challenge_message)
            except M2Crypto.RSA.RSAError, e:
                logging.exception('Exception occured decrypting')
                socket.send('400;Cannot Decrypt message')
                continue
            except Exception, e:
                logging.exception('Internal server error occurred')
                socket.send('500;Internal server error')
                continue

            signed_challenge = self.sign(challenge_message)

            socket.send('200;%s' % signed_challenge.encode('base64'))


    def decrypt(self, base64_cipher_message):
        """Decrypt a message"""
        cipher_message = base64_cipher_message.decode('base64')
        return self._private_key.private_decrypt(
            cipher_message,
            M2Crypto.RSA.pkcs1_oaep_padding
        )

    def sign(self, message):
        """RSASSA-PSS sign the sha256 digest of a message"""
        message_digest = hashlib.sha256()
        message_digest.update(message)

        return self._private_key.sign_rsassa_pss(message_digest.digest())


def run(args=None):
    args = args or sys.argv[1:]
    parsed_args = parser.parse_args(args)
    port = parsed_args.port
    private_key_path = os.path.abspath(parsed_args.private_key_path)

    if not os.path.exists(private_key_path):
        sys.stderr.write('No private key exists at %s\n' % private_key_path)
        return sys.exit(1)

    private_key = M2Crypto.RSA.load_key(private_key_path)

    server = ChallengeResponseServer(port, private_key)
    server.serve()
