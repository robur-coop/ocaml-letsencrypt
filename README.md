# [let's encrypt](https://letsencrypt.org/) - an ACME implementation in OCaml

This package contains an implementation of the ACME protocol (mostly client
side) purely in OCaml based on draft05. The HTTP and DNS challenges are
implemented (DNS sends signed nsupdate to the authoritative DNS server).

Build with:

    $ opam pin add letsencrypt .

Generate a new account key with:

    $ openssl req -newkey rsa > csr.pem
    $ openssl genrsa > account.pem

with OCaml version ≥ 4.03.0.
Note: acme.ml is not tested, and should be considered yet to be implemented.
