type t

type solver_t

type challenge_t = private {
  url: Uri.t;
  token: string;
}

val default_dns_solver :
  ?proto:Dns.proto -> int -> Ptime.t ->
  (Cstruct.t -> (unit, [ `Msg of string ]) result Lwt.t) ->
  ?recv:(unit -> (Cstruct.t, [ `Msg of string ]) result Lwt.t) ->
  keyname:'a Domain_name.t -> Dns.Dnskey.t -> zone:[ `host ] Domain_name.t -> solver_t
val default_http_solver : solver_t

module Make (Client : Cohttp_lwt.S.Client) : sig
  val initialise : ?ctx:Client.ctx ->
    ?directory:Uri.t -> Nocrypto.Rsa.priv ->
    (t, [ `Msg of string ]) result Lwt.t


  val sign_certificate : ?ctx:Client.ctx ->
    ?solver:solver_t -> t -> (unit -> unit Lwt.t) ->
    X509.Signing_request.t ->
    (X509.Certificate.t, [ `Msg of string ]) result Lwt.t
end
