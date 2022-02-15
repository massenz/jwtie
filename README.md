# JSON Web Tokens (JWT) utilities

![Version](https://img.shields.io/badge/Version-0.1.0-blue)
![Released](https://img.shields.io/badge/Released-2021.02.06-green)

[![Author](https://img.shields.io/badge/Author-M.%20Massenzio-green)](https://github.com/massenz)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![OS Debian](https://img.shields.io/badge/OS-Linux-green)

_This is a simple utility to generate and decode JSON Web Tokens (JWTs) that can be used to authenticate against web applications._

See [JWT-OPA](https://github.com/massenz/jwt-opa) for an example of how JWTs can be used to authenticate/authorize access to protected online resources/applications.


# Usage

This script requires [the PyJWT module](https://pypi.org/project/PyJWT/):

```shell
$ pip install pyjwt
```

Use `--help` (or `-h`) for a full list of options and their meaning.

To generate a JWT (optionally signed with an empty passphrase), use:

```shell
$ echo '{"sub": "marco", "roles": [ "USER" ]}' | ./jwtie.py

eyJ0eXAiOiJKV .... ktOykD4
```

To decode a JWT that was generated by this or another tool (so long as the JWT is **not** encrypted), use the `-d` flag:

```shell
$ echo "eyJ0eXAiOiJKV1 ... ktOykD4" | ./jwtie.py -d
{
  "sub": "marco",
  "roles": [
    "USER"
  ]
}

```

Optionally, add the `--header` flag to emit the JWT `header` too.


## Validating Signed JWTs

To use a shared secret, set it in the `$JWT_SECRET` env var (if you want to use a different variable name, use `--secret-env SECRET_ENV`):

```shell
$ export JWT_SECRET="mypazzfrase"

# If we use the JWT generated earlier, it won't pass validation
$ echo "eyJ0eXAiOiJKV ... ktOykD4" | ./jwtie.py -d -v         
ERROR: could not process JWT: Signature verification failed

# We must use --validate, -v when generating it:
$ echo '{"sub": "marco", "roles": [ "USER" ]}' | ./jwtie.py -v
eyJ0eXAiO .... mJLKsPkblw  # <<-- note the last part, the signature is different


$ echo "eyJ0eXAiO ... mJLKsPkblw" | ./jwtie.py -d -v --header
{
  "typ": "JWT",
  "alg": "HS256"
}
{
  "sub": "marco",
  "roles": [
    "USER"
  ]
}
```
Note how the `header` carries information about the signature algorithm.

**NOTE** Still `TODO` adding support for asymmetric and key-based signature algorithms

## Raw output

If the output of `jwtie` needs to be fed into other utilities, pretty-printing it may be unnecessary or even undesirable; in such cases use `--raw` to get a simple JSON string:

```shell
$ echo "eyJ0eXAiO ... mJLKsPkblw" | ./jwtie.py -d --raw
{"sub": "marco", "roles": ["USER"]}

# This is pointless, really, but proves a point.
$ echo "eyJ0eXAiO ... mJLKsPkblw" | ./jwtie.py -d --raw \
  | cut -d ',' -f 2 | cut -d '}' -f 1

 "roles": ["USER"]
```

## Install

This will be made available on [PyPi](#) for installation via `pip`:

    $ pip install jwtie

`TODO`: this has not been implemented yet.
