(** [Letsencrypt]: for when you love authorities.

    Letsencrypt is an implementation of the ACME protocol, for automatizing the
    generation of HTTPS certificates.

    Currently, this library has been tested (and is working) only with
    Letsencrypt servers.
 *)
val letsencrypt_url : Uri.t
val letsencrypt_staging_url : Uri.t

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

  type solver_t
  val default_http_solver : solver_t
  val default_dns_solver : ?proto:Dns.proto -> int -> Ptime.t ->
    (Cstruct.t -> (unit, [ `Msg of string ]) result Lwt.t) ->
    ?recv:(unit -> (Cstruct.t, [ `Msg of string ]) result Lwt.t) ->
    keyname:'a Domain_name.t -> Dns.Dnskey.t -> zone:[ `host ] Domain_name.t -> solver_t

  module Make (Client : Cohttp_lwt.S.Client) : sig
  val initialise : ?ctx:Client.ctx ->
    ?directory:Uri.t -> Nocrypto.Rsa.priv ->
    (t, [ `Msg of string ]) result Lwt.t


  val sign_certificate : ?ctx:Client.ctx ->
    ?solver:solver_t -> t -> (unit -> unit Lwt.t) ->
    X509.Signing_request.t ->
    (X509.Certificate.t, [ `Msg of string ]) result Lwt.t
      (** [get_crt ~directory_url ~solver sleep rsa_pem csr_pem] asks the CA identified at url
          [directory] for signing [csr_pem] with account key [account_pem] for all
          domains in [csr_pem].  This functions accepts an optionl argument
          [solver] specifying how to solve the challenge provided by the CA.  The
          result is either a string result cotaining the pem-encoded signed
          certificate, or an error with a string describing what went wrong. *)
  end

end
