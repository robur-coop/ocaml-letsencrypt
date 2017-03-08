type t
type solver_t

type challenge_t = private {
  url: Uri.t;
  token: string;
}


val get_crt : string ->
              string ->
              string ->
              ?solver:solver_t ->
              (string, string) Result.result Lwt.t


val default_dns_solver : solver_t
val default_http_solver : solver_t
