package proxycmd

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/otpki/pkcs11/internal/pki"
	"github.com/spf13/cobra"
)

// pkiCommonFlags adds the options shared by pki init and pki issue.
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

// newPKICommand builds the development mTLS commands.
func newPKICommand() *cobra.Command {
	pkiCmd := &cobra.Command{
		Use:   "pki",
		Short: "Create a development mTLS tree (CA, server certs, client certs)",
		Long: `Generate a local Ed25519 CA and certificates for development mTLS.
Private keys are written to disk with 0600 permissions. Do not use this as a
replacement for a production CA.`,
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
	init.Flags().StringSlice("host", nil, "server SAN (DNS name or IP), repeat for more values (default localhost, 127.0.0.1, ::1)")
	init.Flags().StringSlice("client", []string{"dev-client"}, "client certificate names to issue, repeat for more values")
	init.Flags().Bool("ca-only", false, "only create the CA and skip server and client certificates")

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
	issue.Flags().StringSlice("host", nil, "server SAN (DNS name or IP), repeat for more values")

	pkiCmd.AddCommand(init, issue)
	return pkiCmd
}
