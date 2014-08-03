import sys
import subprocess
import argparse

DESCRIPTION = 'Generates an upstart script for the salt verifier server. This is only tested on ubuntu.'

parser = argparse.ArgumentParser(description=DESCRIPTION)
parser.add_argument('--port', type=int, help='Port to run the server')
parser.add_argument('--private-key-path', help="The path to the minion's key")
parser.add_argument('--run-as', default='nobody',
                    help='Run as a specific user. Requires root')

UPSTART_TEMPLATE = """#
# Auto-generated file. Please do not edit unless you know what you're doing
#

description "Salt verifier server"

start on runlevel [2345]
stop on runlevel [!2345]

respawn

# Try to respawn continuously for 15 minutes
respawn limit 0 900

script
    exec {exec_string}
end script
"""


def generate_upstart_script(args=None):
    args = args or sys.argv[1:]

    parsed_args = parser.parse_args(args)

    port = parsed_args.port
    private_key_path = parsed_args.private_key_path
    run_as = parsed_args.run_as

    process = subprocess.Popen(['which', 'salt-verifier-server'],
                               stdout=subprocess.PIPE)

    server_bin_path, err = process.communicate()

    if process.returncode != 0:
        raise Exception('Cannot find salt-verifier-server binary. Perhaps a virtualenv issue?')

    exec_string = server_bin_path.strip()
    if port:
        exec_string += ' --port=%s' % port
    if private_key_path:
        exec_string += ' --private-key-path=%s' % private_key_path
    if run_as:
        exec_string += ' --run-as=%s' % run_as

    print UPSTART_TEMPLATE.format(exec_string=exec_string)

if __name__ == '__main__':
    generate_upstart_script()
