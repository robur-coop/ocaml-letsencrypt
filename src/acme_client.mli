type t

type challenge_t = private {
  url: Uri.t;
  token: string;
}

type solver_t = {
    get_challenge : Json.t -> (challenge_t, string) Result.result;
    solve_challenge : t -> challenge_t -> (unit, string) Result.result Lwt.t ;
  }

val get_crt : string ->
              string ->
              string ->
              ?solver:solver_t ->
              (string, string) Result.result Lwt.t


val default_dns_solver : solver_t
val default_http_solver : solver_t
