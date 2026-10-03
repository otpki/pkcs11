## pkcs11-proxy pki init

Create a new CA and issue the initial server/client certificates

```
pkcs11-proxy pki init [flags]
```

### Options

```
      --ca-cn string       CA certificate common name (default "pkcs11-proxy dev CA")
      --ca-days int        CA validity in days (default 3650)
      --ca-only            only create the CA and skip server and client certificates
      --client strings     client certificate names to issue, repeat for more values (default [dev-client])
      --days int           leaf certificate validity in days (default 825)
      --dir string         PKI directory holding ca.pem/ca.key (default "./pki")
      --force              overwrite existing files
  -h, --help               help for init
      --host strings       server SAN (DNS name or IP), repeat for more values (default localhost, 127.0.0.1, ::1)
      --server-cn string   server certificate common name (default "pkcs11-proxy")
```

### SEE ALSO

* [pkcs11-proxy pki](pkcs11-proxy_pki.md)	 - Create a development mTLS tree (CA, server certs, client certs)

