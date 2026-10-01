package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/otpki/pkcs11/internal/auditlog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// toolViper binds one subcommand's flags into the shared viper environment so
// every tool option resolves flag > PKCS11_PROXY_* env > flag default,
// matching how the serve command resolves its configuration.
func toolViper(cmd *cobra.Command) (*viper.Viper, error) {
	v := newConfigViper()
	if err := v.BindPFlags(cmd.Flags()); err != nil {
		return nil, err
	}
	return v, nil
}

// auditKeyFlag registers the shared --key flag for verify and prove.
func auditKeyFlag(cmd *cobra.Command) {
	cmd.Flags().String("key", "", "audit verification public key file (default <log>.key.pub)")
}

// defaultAuditKey derives the verification key path the serve mode writes:
// <log>.key.pub — overridable with --key.
func defaultAuditKey(v *viper.Viper, logPath string) string {
	if key := v.GetString("key"); key != "" {
		return key
	}
	return logPath + ".key.pub"
}

// newAuditCommand groups the offline audit-log tooling. Each subcommand takes
// the log path as its single positional argument.
func newAuditCommand() *cobra.Command {
	audit := &cobra.Command{
		Use:   "audit",
		Short: "Verify and inspect signed audit logs",
	}

	verify := &cobra.Command{
		Use:   "verify <log>",
		Short: "Replay the log, re-derive Merkle roots, and check the checkpoint signature chain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := toolViper(cmd)
			if err != nil {
				return err
			}
			return verifyAuditLog(args[0], defaultAuditKey(v, args[0]))
		},
	}
	auditKeyFlag(verify)

	inspect := &cobra.Command{
		Use:   "inspect <log>",
		Short: "Decode and print audit records (checkpoint lines excluded)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := toolViper(cmd)
			if err != nil {
				return err
			}
			return inspectAuditLog(args[0], v.GetInt("tail"))
		},
	}
	inspect.Flags().Int("tail", 20, "number of records printed (0 = all)")

	prove := &cobra.Command{
		Use:   "prove <log>",
		Short: "Emit a Merkle inclusion proof for one record as JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := toolViper(cmd)
			if err != nil {
				return err
			}
			seq := v.GetUint64("seq")
			if seq == 0 {
				return errors.New("--seq is required")
			}
			return proveAuditRecord(args[0], seq, defaultAuditKey(v, args[0]))
		},
	}
	prove.Flags().Uint64("seq", 0, "record sequence number to prove")
	auditKeyFlag(prove)

	audit.AddCommand(verify, inspect, prove)
	return audit
}

// verifyAuditLog implements "audit verify": replay every leaf and checkpoint,
// re-derive each Merkle root, and check the checkpoint signature chain
// against the public key.
func verifyAuditLog(logPath, keyPath string) error {
	public, err := auditlog.LoadPublicKey(keyPath)
	if err != nil {
		return err
	}
	report, err := auditlog.Verify(logPath, public)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %d records across %d verified checkpoints (key %s)\n",
		logPath, report.Records, report.Checkpoints, report.KeyID)
	if report.Unsealed > 0 || report.PartialTail {
		fmt.Printf("  note: %d records after the last checkpoint are unsealed (pending, truncated, or crash-torn); partial tail: %v\n",
			report.Unsealed, report.PartialTail)
	}
	return nil
}

// inspectAuditLog implements "audit inspect": decode leaf records and print
// the newest tail, checkpoint lines excluded.
func inspectAuditLog(logPath string, tail int) error {
	records, err := auditlog.Inspect(logPath, tail)
	if err != nil {
		return err
	}
	for _, entry := range records {
		fmt.Printf("#%-4d %-30s %-24s %s\n", entry.Seq, entry.Time, entry.Type, auditRecordDetail(entry))
	}
	fmt.Printf("%d records\n", len(records))
	return nil
}

func auditRecordDetail(entry auditlog.Record) string {
	parts := []string{}
	if entry.Target != "" {
		parts = append(parts, "target="+entry.Target)
	}
	if entry.Method != "" {
		parts = append(parts, "method="+entry.Method)
	}
	if entry.ClientID != "" {
		parts = append(parts, "client="+entry.ClientID)
	}
	if entry.Principal != "" {
		parts = append(parts, "principal="+entry.Principal)
	}
	if entry.Code != "" {
		parts = append(parts, "code="+entry.Code)
	}
	if entry.Dropped != 0 {
		parts = append(parts, fmt.Sprintf("dropped=%d", entry.Dropped))
	}
	return strings.Join(parts, " ")
}

// proveAuditRecord implements "audit prove": emit the Merkle inclusion proof
// for one record as JSON and, when a key is given, check it against the
// public key.
func proveAuditRecord(logPath string, seq uint64, keyPath string) error {
	proof, err := auditlog.Prove(logPath, seq)
	if err != nil {
		return err
	}
	if keyPath != "" {
		public, err := auditlog.LoadPublicKey(keyPath)
		if err != nil {
			return err
		}
		if err := auditlog.VerifyProof(proof, public); err != nil {
			return err
		}
	}
	out, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	if keyPath != "" {
		fmt.Printf("proof verified against checkpoint root %s\n", proof.Checkpoint.Root)
	}
	return nil
}
