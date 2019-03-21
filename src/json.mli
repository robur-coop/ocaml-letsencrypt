type t = Yojson.Basic.t

val of_string : string -> (t, [ `Msg of string ]) result
val to_string : ?comma:string -> ?colon:string -> t -> string

val string_member : string -> t -> (string, [ `Msg of string ]) result
val list_member : string -> t -> (t list, [ `Msg of string ]) result
val b64_string_member : string -> t -> (string, [ `Msg of string ]) result
val b64_z_member : string -> t -> (Z.t, [ `Msg of string ]) result
val json_member : string -> t -> (t, [ `Msg of string ]) result
