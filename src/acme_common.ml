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
        | None -> []
        | Some (_, san) -> match X509.General_name.(find DNS san) with
          | None -> []
          | Some names -> names
      end
    | _ -> []
  in
  match subject_alt_names with
  | [] ->
    begin match X509.Distinguished_name.common_name info.subject with
      | None -> []
      | Some x -> [ x ]
    end
  | _ -> subject_alt_names

let letsencrypt_url = Uri.of_string
    "https://acme-v01.api.letsencrypt.org/directory"

let letsencrypt_staging_url = Uri.of_string
    "https://acme-staging.api.letsencrypt.org/directory"
