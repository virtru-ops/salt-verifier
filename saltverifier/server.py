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
import pwd

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
parser.add_argument('--run-as', help='Username to run process as')
parser.add_argument('--private-key-path', default='/etc/salt/pki/minion/minion.pem',
                    help="The path to the minion's key")
parser.add_argument('--private-key-load-timeout', default=900.0, type=float,
                    help="Time in seconds to wait to load the private key")
parser.add_argument('--private-key-load-interval', default=0.1, type=float,
                    help="Interval in seconds to check for private key during loading")


class PrivateKeyDoesNotExist(Exception):
    pass


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


def load_private_key(private_key_path, timeout, interval):
    current_time = time.time()
    ready = False
    count = 0
    while current_time + timeout > time.time():
        # Report to the logs that we're waiting for the private key... but
        # don't always do it. It'll get too noisy unnecessarily. With the
        # default settings this will run every 2 seconds
        if count % 20 == 0:
            logging.info('Checking for private key @ "%s"' % private_key_path)
        if os.path.exists(private_key_path):
            ready = True
            break
        count += 1
        time.sleep(interval)
    if not ready:
        raise PrivateKeyDoesNotExist(
            'No private key exists @ %s\n' % private_key_path
        )
    logging.info('Private key found @ "%s"' % private_key_path)

    # Load the private key
    private_key = M2Crypto.RSA.load_key(private_key_path)
    return private_key


def run(args=None):
    args = args or sys.argv[1:]
    parsed_args = parser.parse_args(args)
    port = parsed_args.port
    private_key_path = os.path.abspath(parsed_args.private_key_path)

    try:
        private_key = load_private_key(
            private_key_path,
            parsed_args.private_key_load_timeout,
            parsed_args.private_key_load_interval
        )
    except PrivateKeyDoesNotExist, e:
        logging.info(e.message)
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info('Shutting down. Was waiting for private key.')
        sys.exit(1)

    # Downgrade user to the setuid if --run-as is set on command line
    run_as = parsed_args.run_as
    if run_as:
        try:
            passwd = pwd.getpwnam(run_as)
        except KeyError:
            logging.error('No user called %s. Exiting' % run_as)
            return
        os.setuid(passwd.pw_uid)

    server = ChallengeResponseServer(port, private_key)
    server.serve()
