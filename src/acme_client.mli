type t
type challenge_t = private {
  url: Uri.t;
  token: string;
}

val get_crt : string ->
              string ->
              string ->
              (string -> string -> unit)  ->
              (string, string) Result.result Lwt.t
