"""
Client for the salt verifier server
"""
import zmq
import M2Crypto
import hashlib
import uuid

DEFAULT_CONNECTION_TIMEOUT = 10000
DEFAULT_REQUEST_TIMEOUT = 10000


class RequestTimeoutError(Exception):
    pass


def make_zmq_request(socket, message, request_timeout=DEFAULT_REQUEST_TIMEOUT,
                     connection_timeout=DEFAULT_CONNECTION_TIMEOUT):
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN | zmq.POLLOUT)

    # check is the socket is ready to send. i.e. are we connected
    poll_results = dict(poller.poll(timeout=connection_timeout))

    if not poll_results.get(socket, None) == zmq.POLLOUT:
        raise RequestTimeoutError('Connection timed out')

    # Make the request
    socket.send(message)

    poll_results = dict(poller.poll(timeout=request_timeout))

    if not poll_results.get(socket, None) == zmq.POLLIN:
        raise RequestTimeoutError('Request timed out')

    return socket.recv()


def is_valid_server_public_key(address, public_key_str,
                               connection_timeout=None,
                               request_timeout=None):
    context = zmq.Context()
    try:
        result = _is_valid_server_public_key(
            context,
            address,
            public_key_str,
            connection_timeout=connection_timeout,
            request_timeout=request_timeout
        )
    finally:
        context.destroy(linger=0)
    return result


def _is_valid_server_public_key(context, address, public_key_str,
                                connection_timeout=None,
                                request_timeout=None):
    socket = context.socket(zmq.REQ)

    public_key_bio = M2Crypto.BIO.MemoryBuffer(public_key_str)
    public_key = M2Crypto.RSA.load_pub_key_bio(public_key_bio)

    # Generate a random uuid as a challenge message
    challenge_message = uuid.uuid4().get_bytes()

    encrypted_challenge_message = public_key.public_encrypt(
        challenge_message,
        M2Crypto.RSA.pkcs1_oaep_padding
    )

    # Make the request to the server
    socket.connect(address)
    encrypted_challenge_message_base64 = encrypted_challenge_message.encode('base64')

    # Wait for a response
    response = make_zmq_request(socket, encrypted_challenge_message_base64,
                                connection_timeout=connection_timeout,
                                request_timeout=request_timeout)

    # All responses are in the form status;message so split on ';'
    response_split = response.split(';')

    if response_split[0] != '200':
        return False

    # Get the signature from the response
    challenge_signature_base64 = response_split[1]
    challenge_signature = challenge_signature_base64.decode('base64')

    # Check the signature
    challenge_digest = hashlib.sha256()
    challenge_digest.update(challenge_message)
    verification_result = public_key.verify_rsassa_pss(
        challenge_digest.digest(),
        challenge_signature
    )

    if verification_result != 1:
        return False
    # If we've arrived here then the signature verified correctly
    return True
