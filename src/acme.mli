(** [Acme]: for when you love authorities.

    Acme is an implementation of the ACME protocol, for automatizing the
    generation of HTTPS certificates.

    Currently, this library has been tested (and is working) only with
    Letsencrypt servers.
 *)
val letsencrypt_url : string
val letsencrypt_staging_url : string



(** ACME Client.

    This module provides client commands.
    Note: right now this module implements only the strict necessary
    in order to register an account, solve http-01 challenges provided by the CA,
    and fetch the certificate.
    This means that you will be able to maintain your server with this, but there
    is no account handling: no implementation for account deletion, no implementation
    for challenges combination, no nothing.
 *)
module Client: sig

    type t

    val get_crt : string -> string -> string -> (string -> string -> unit) ->
                  (string, string) result Lwt.t
    (** [get_crt directory_url rsa_pem csr_pem] asks the CA identified
        by [directory_url] for signing [csr_pem] with account key [account_pem]
        for all domains in [csr_pem].
        The result is either a string result cotaining the pem-encoded signed
        certificate, or an error with a string describing what went wrong. *)

  end
