type t

type solver_t

type challenge_t = private {
  url: Uri.t;
  token: string;
}


val default_dns_solver : Ptime.t -> (Cstruct.t -> (unit, string) result Lwt.t) -> Dns_name.t -> Dns_packet.dnskey -> solver_t
val default_http_solver : solver_t

module Make (Client : Cohttp_lwt.S.Client) : sig
  val initialise : ?ctx:Client.ctx ->
    ?directory:Uri.t -> Nocrypto.Rsa.priv ->
    (t, string) Result.result Lwt.t


  val sign_certificate : ?ctx:Client.ctx ->
    ?solver:solver_t -> t -> (unit -> unit Lwt.t) ->
    X509.CA.signing_request ->
    (X509.t, string) Result.result Lwt.t
end
