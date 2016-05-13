module B64u

assume val urlencode : string -> Tot string
assume val urldecode : string -> Tot string

assume val urlencodez : Z.t -> Tot string
assume val urldecodez : string -> Tot Z.t

(* we should give some properties about the formatting in base 64. *)
