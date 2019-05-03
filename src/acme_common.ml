type directory_t = {
  directory   : Uri.t;
  new_authz   : Uri.t;
  new_reg     : Uri.t;
  new_cert    : Uri.t;
  revoke_cert : Uri.t;
}

let domains_of_csr csr =
  let open X509.Signing_request in
  let info = info csr in
  let subject_alt_names =
    match Ext.(find Extensions info.extensions) with
    | Some exts ->
      begin match X509.Extension.(find Subject_alt_name exts) with
        | None -> Domain_name.Set.empty
        | Some (_, san) -> match X509.General_name.(find DNS san) with
          | None -> Domain_name.Set.empty
          | Some names -> names
      end
    | _ -> Domain_name.Set.empty
  in
  if Domain_name.Set.is_empty subject_alt_names then
    (* XXX: I'm assuming there is always exactly one CN in a subject. *)
    let cn = X509.Distinguished_name.(get CN info.subject) in
    Domain_name.Set.singleton (Domain_name.of_string_exn cn)
  else
    subject_alt_names

let letsencrypt_url = Uri.of_string
    "https://acme-v01.api.letsencrypt.org/directory"

let letsencrypt_staging_url = Uri.of_string
    "https://acme-staging.api.letsencrypt.org/directory"
