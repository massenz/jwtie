#!/usr/bin/env python3

import argparse
import json
import jwt
import os
import sys

JWT_SECRET_ENV = "JWT_SECRET"
DEFAULT_SIGNATURE_ALGORITHM = "HS256"
ALLOWED_ALGORITHMS = ["HS256", "HS384", "HS512", "ES256", "ES384", "ES512", "RS256",
                      "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"]


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-a",
        "--algo",
        default=DEFAULT_SIGNATURE_ALGORITHM,
        choices=ALLOWED_ALGORITHMS,
        help=f"The signature algorithm to use. Default: {DEFAULT_SIGNATURE_ALGORITHM}"
    )
    parser.add_argument(
        "-d",
        "--decode",
        action="store_true",
        help="If present, decodes the JWT, without attempting to validate, unless the -v option "
             "is given"
    )
    parser.add_argument(
        "--header",
        action="store_true",
        help="If present, decodes the header too"
    )
    parser.add_argument(
        "--raw",
        action="store_false",
        dest="pretty",
        help="By default, we pretty-print the JSON output; if --raw is specified, we will simply "
             "emit the raw JSON string (usually when piping commands)"
    )
    parser.add_argument(
        "--secret-env",
        default=JWT_SECRET_ENV,
        help="The name of the env var which contains the passphrase for the signature, "
             "or the path to the keypair, as appropriate to the algorithm (see --algo). "
             f"Default: {JWT_SECRET_ENV}"
    )
    parser.add_argument(
        "-v",
        "--validate",
        action="store_true",
        help="If present, validates the JWT, using the given secret, or key, as specified in "
             f"${JWT_SECRET_ENV}\n"
             "TODO: this is not fully implemented yet"
    )
    return parser.parse_args()


def create_jwt(data, secret="", algorithm=DEFAULT_SIGNATURE_ALGORITHM):
    return jwt.encode(data, secret, algorithm=algorithm)


def decode_jwt(token, secret="", validate=False):
    return jwt.decode(token, secret, algorithms=ALLOWED_ALGORITHMS,
                      options={"verify_signature": validate})


def decode_header(token):
    return jwt.get_unverified_header(token)


def emit_json(data, pretty=True):
    if pretty:
        print(json.dumps(data, indent=2))
    else:
        print(data)


if __name__ == '__main__':
    options = parse_args()

    try:
        passphrase = ""
        if options.validate:
            # TODO: currently only supports symmetric encryption, with secret passed in as string.
            passphrase = os.getenv(options.secret_env)
            if not passphrase:
                print(f"ERROR: missing env var ${options.secret_env}", file=sys.stderr)
                exit(1)

        data_in = sys.stdin.read().strip()
        if options.header:
            emit_json(decode_header(data_in), pretty=options.pretty)

        if options.decode:
            emit_json(decode_jwt(data_in, secret=passphrase, validate=options.validate),
                      pretty=options.pretty)
        else:
            print(create_jwt(json.loads(data_in), secret=passphrase, algorithm=options.algo))

    except Exception as error:
        print(f"ERROR: could not process JWT: {error}", file=sys.stderr)
        exit(1)
