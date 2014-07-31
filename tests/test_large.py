import os
from multiprocessing import Process
from saltverifier.server import run
from saltverifier.client import is_valid_server_public_key

CURRENT_FILE_DIR_PATH = os.path.abspath(os.path.dirname(__file__))


def resolve_fixture_path(filename):
    return os.path.join(CURRENT_FILE_DIR_PATH, 'fixtures', filename)

GOOD_PUBLIC_KEY_STR = open(resolve_fixture_path('test-good-pub.pem')).read()
BAD_PUBLIC_KEY_STR = open(resolve_fixture_path('test-bad-pub.pem')).read()
SERVER_ADDRESS = 'tcp://127.0.0.1:4533'


class TestSaltverifierServerAndClient(object):
    def setup(self):
        private_key_path = resolve_fixture_path('test-priv.pem')
        run_args = ['--private-key-path=%s' % private_key_path]
        self._server_process = Process(
            target=run,
            args=(run_args,)
        )
        self._server_process.start()

    def teardown(self):
        self._server_process.terminate()

    def test_with_a_valid_public_key(self):
        result = is_valid_server_public_key(
            SERVER_ADDRESS,
            GOOD_PUBLIC_KEY_STR
        )
        assert result is True

    def test_with_an_invalid_public_key(self):
        result = is_valid_server_public_key(
            SERVER_ADDRESS,
            BAD_PUBLIC_KEY_STR
        )
        assert result is False
