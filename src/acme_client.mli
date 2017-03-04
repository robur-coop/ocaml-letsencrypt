type t
type challenge_t = private {
  url: Uri.t;
  token: string;
}

val new_cli : string -> string -> string -> (t, string) result Lwt.t
val new_reg : t -> (unit, string) result Lwt.t
val get_http01_challenge : Json.t -> (challenge_t, string) result
val do_http01_challenge : t -> challenge_t -> string -> (unit, 'a) result Lwt.t
val new_authz : t -> string -> (challenge_t, string) result Lwt.t
val challenge_met : t -> challenge_t -> (unit, 'a) result Lwt.t
val poll_challenge_status : 'a -> challenge_t -> (bool, string) result Lwt.t
val poll_until : ?sec:int -> 'a -> challenge_t -> (unit, string) result Lwt.t
val new_cert : t -> (string, string) result Lwt.t
val get_crt : string -> string -> string -> string -> string -> (string, string) Result.result Lwt.t
