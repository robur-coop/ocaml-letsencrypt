Build with:

    $ opam pin add letsencrypt .

Generate a new account key with:

    $ openssl req -newkey rsa > csr.pem
    $ openssl genrsa > account.pem

with OCaml version ≥ 4.03.0.
Note: acme.ml is not tested, and should be considered yet to be implemented.
