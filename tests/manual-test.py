from saltverifier.client import is_valid_server_public_key


def main():
    result = is_valid_server_public_key('tcp://127.0.0.1:4533', open('tests/fixtures/test-bad-pub.pem').read())

    if result:
        print "Worked"
    else:
        print "Didn't work"

if __name__ == '__main__':
    main()
