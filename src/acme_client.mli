type t
type solver_t

type challenge_t = private {
  url: Uri.t;
  token: string;
}


val get_crt : string ->
              string ->
              ?directory:Uri.t ->
              ?solver:solver_t ->
              (string, string) Result.result Lwt.t


val default_dns_solver : Unix.inet_addr -> Dns_name.t -> Dns_packet.dnskey -> solver_t
val default_http_solver : solver_t
