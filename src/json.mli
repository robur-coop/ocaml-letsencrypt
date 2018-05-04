type t = Yojson.Basic.json

val of_string : string -> (t, string) result
val to_string : ?comma:string -> ?colon:string -> t -> string

val string_member : string -> t -> (string, string) result
val list_member : string -> t -> (t list, string) result
val b64_string_member : string -> t -> (string, string) result
val b64_z_member : string -> t -> (Z.t, string) result
val json_member : string -> t -> (t, string) result
