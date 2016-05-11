module Primitives

assume new type pub
assume new type priv

type p_inverse_t  (#a:Type) (#b:Type) ($f:(a -> Tot b)) = b -> Tot a

assume val priv_of_pem : string -> priv
assume val pub_of_priv : priv -> pub

assume val pub_of_z : Z.t -> Z.t -> pub
assume val pub_to_z : p_inverse_t pub_of_z
