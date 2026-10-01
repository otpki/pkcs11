package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/otpki/pkcs11/internal/pki"
	"github.com/spf13/cobra"
)

// pkiCommonFlags registers the flags shared by pki init and pki issue:
// the tree directory, leaf lifetime, and overwrite policy.
func pkiCommonFlags(cmd *cobra.Command) {
	cmd.Flags().String("dir", "./pki", "PKI directory holding ca.pem/ca.key")
	cmd.Flags().Int("days", pki.DefaultLeafDays, "leaf certificate validity in days")
	cmd.Flags().Bool("force", false, "overwrite existing files")
}

func loadCAFromDir(dir string) (*pki.CA, error) {
	ca, err := pki.LoadCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, fmt.Errorf("load CA from %s (run 'pkcs11-proxy pki init' first): %w", dir, err)
	}
	return ca, nil
}

// newPKICommand groups the development mTLS tooling: init mints a fresh CA
// plus optional server and client leaves; issue adds more leaves under an
// existing tree.
func newPKICommand() *cobra.Command {
	pkiCmd := &cobra.Command{
		Use:   "pki",
		Short: "Create a development mTLS tree (CA, server certs, client certs)",
		Long: `Generate a throwaway Ed25519 CA and leaf certificates for the
broker's tls.* settings and for mTLS client credentials. This is development
tooling — keys land on local disk with 0600 permissions and nothing here
replaces a production CA.`,
	}

	init := &cobra.Command{
		Use:   "init",
		Short: "Create a new CA and issue the initial server/client certificates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, err := toolViper(cmd)
			if err != nil {
				return err
			}
			dir := v.GetString("dir")
			ca, err := pki.GenerateCA(v.GetString("ca-cn"), v.GetInt("ca-days"))
			if err != nil {
				return err
			}
			tree := &pki.Tree{CA: ca}
			if !v.GetBool("ca-only") {
				server, err := ca.IssueServer(v.GetString("server-cn"), v.GetStringSlice("host"), v.GetInt("days"))
				if err != nil {
					return err
				}
				tree.Server = server
			}
			for _, name := range v.GetStringSlice("client") {
				client, err := ca.IssueClient(name, v.GetInt("days"))
				if err != nil {
					return err
				}
				tree.Clients = append(tree.Clients, client)
			}
			written, err := pki.WriteTree(dir, tree, v.GetBool("force"))
			if err != nil {
				return err
			}
			for _, path := range written {
				fmt.Println("wrote", path)
			}
			fmt.Println()
			fmt.Println("broker config:")
			fmt.Printf("  tls:\n    cert_file: %q\n    key_file: %q\n    client_ca_file: %q  # enables mTLS\n",
				filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"), filepath.Join(dir, "ca.pem"))
			return nil
		},
	}
	pkiCommonFlags(init)
	init.Flags().String("ca-cn", "pkcs11-proxy dev CA", "CA certificate common name")
	init.Flags().Int("ca-days", pki.DefaultCADays, "CA validity in days")
	init.Flags().String("server-cn", "pkcs11-proxy", "server certificate common name")
	init.Flags().StringSlice("host", nil, "server SAN (DNS name or IP); repeatable (default localhost, 127.0.0.1, ::1)")
	init.Flags().StringSlice("client", []string{"dev-client"}, "client certificate names to issue; repeatable, empty skips clients")
	init.Flags().Bool("ca-only", false, "only create the CA — skip server and client leaves")

	issue := &cobra.Command{
		Use:   "issue <server|client>",
		Short: "Issue an additional server or client certificate under an existing tree",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := toolViper(cmd)
			if err != nil {
				return err
			}
			dir := v.GetString("dir")
			ca, err := loadCAFromDir(dir)
			if err != nil {
				return err
			}
			name := v.GetString("name")
			if name == "" {
				return errors.New("--name is required")
			}
			var leaf *pki.Issued
			var base string
			slug := pki.SafeFileName(name)
			switch args[0] {
			case "server":
				leaf, err = ca.IssueServer(name, v.GetStringSlice("host"), v.GetInt("days"))
				base = "server-" + slug
			case "client":
				leaf, err = ca.IssueClient(name, v.GetInt("days"))
				base = "clients/" + slug
			default:
				return fmt.Errorf("issue %q: want server or client", args[0])
			}
			if err != nil {
				return err
			}
			written, err := pki.WriteFiles(dir, map[string][]byte{
				base + ".pem": leaf.CertPEM,
				base + ".key": leaf.KeyPEM,
			}, v.GetBool("force"))
			if err != nil {
				return err
			}
			fp, _ := pki.Fingerprint(leaf)
			for _, path := range written {
				fmt.Println("wrote", path)
			}
			fmt.Println("leaf fingerprint", fp)
			return nil
		},
	}
	pkiCommonFlags(issue)
	issue.Flags().String("name", "", "certificate common name (server hostname or client identity)")
	issue.Flags().StringSlice("host", nil, "server SAN (DNS name or IP); repeatable, server issues only")

	pkiCmd.AddCommand(init, issue)
	return pkiCmd
}
