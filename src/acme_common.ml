type directory_t = {
    directory   : Uri.t;
    new_authz   : Uri.t;
    new_reg     : Uri.t;
    new_cert    : Uri.t;
    revoke_cert : Uri.t;
  }

let domains_of_csr csr =
  let flat_map f xs = List.map f xs |> List.concat in
  let info = X509.CA.info csr in
  let subject_alt_names =
    info.X509.CA.extensions
    |> flat_map (function
        | `Extensions extensions ->
          List.map snd extensions
        | `Name _ | `Password _ -> [])
    |> flat_map (function
        | `Subject_alt_name names -> names
        | _ -> [])
    |> List.map (function
        | `DNS name ->
          name
        | _ -> assert false)
  in
  if subject_alt_names = []
  then
    (* XXX: I'm assuming there is always exactly one CN in a subject. *)
    info.X509.CA.subject
    |> List.find (function
        | `CN name -> true
        | _ -> false)
    |> (function
        | `CN name -> [name]
        | _ -> assert false)
  else  subject_alt_names



let letsencrypt_url =
  "https://acme-v01.api.letsencrypt.org/directory"

let letsencrypt_staging_url =
  "https://acme-staging.api.letsencrypt.org/directory"
