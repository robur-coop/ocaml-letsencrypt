{ nix-filter
, buildDunePackage
, asn1-combinators
, base64
, logs
, fmt
, uri
, lwt
, mirage-crypto
, mirage-crypto-ec
, mirage-crypto-pk
, mirage-crypto-rng
, x509
, yojson
, ounit
, ptime
, domain-name
, cstruct
, dns
, dns-tsig
, cmdliner
, cohttp-lwt-unix
, bos
, fpath
, randomconv
}:

rec {
  letsencrypt = buildDunePackage {
    pname = "letsencrypt";

    version = "dev";

    src = nix-filter.lib {
      root = ../.;
      include = [
        "./dune-project"
        "./letsencrypt.opam"
        "src"
        "test"
      ];
    };

    propagatedBuildInputs = [
      asn1-combinators
      base64
      logs
      lwt
      mirage-crypto
      mirage-crypto-ec
      mirage-crypto-pk
      uri
      x509
      yojson
    ];

    buildInputs = [
      fmt
      ounit
      ptime
      domain-name
      cstruct
    ];
  };

  letsencrypt-dns = buildDunePackage {
    pname = "letsencrypt-dns";

    version = "dev";

    src = nix-filter.lib {
      root = ../.;
      include = [
        "./dune-project"
        "./letsencrypt-dns.opam"
        "dns"
      ];
    };

    propagatedBuildInputs = [
      dns
      dns-tsig
      letsencrypt
      logs
      lwt
    ];

    buildInputs = [
      fmt
      domain-name
    ];

    doCheck = false;
  };

  letsencrypt-app = buildDunePackage {
    pname = "letsencrypt-app";

    version = "dev";

    src = nix-filter.lib {
      root = ../.;
      include = [
        "./dune-project"
        "./letsencrypt-app.opam"
        "bin"
      ];
    };

    buildInputs = [
      letsencrypt
      letsencrypt-dns
      cmdliner
      cohttp-lwt-unix
      logs
      fmt
      lwt
      mirage-crypto-rng
      ptime
      bos
      fpath
      randomconv
      cstruct
    ];

    doCheck = false;

    meta.mainProgram = "oacmel";
  };
}
