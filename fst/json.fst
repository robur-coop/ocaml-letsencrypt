module Json

assume new type t

assume val of_string : string -> Tot (option t)
assume val to_string : t -> string

assume val string_member : string -> t -> option string
assume val b64_string_member : string -> t -> option string
assume val b64_z_member : string -> t -> option Z.t
assume val json_member : string -> t -> option t
