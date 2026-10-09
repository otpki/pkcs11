package conformance

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestEmbeddedParamsDecode(t *testing.T) {
	dh := ffdhe2048()
	if dh.Prime.BitLen() != 2048 || dh.Base.Cmp(big.NewInt(2)) != 0 || dh.Subprime != nil {
		t.Fatalf("ffdhe2048 wrong: p_bits=%d g=%v q=%v", dh.Prime.BitLen(), dh.Base, dh.Subprime)
	}
	// Cross-check against RFC 7919 first/last bytes
	b := dh.Prime.Bytes()
	if b[0] != 0xff || b[len(b)-1] != 0xff || len(b) != 256 {
		t.Fatalf("ffdhe2048 prime corrupted: %x...%x len=%d", b[:4], b[len(b)-4:], len(b))
	}
	d := dsa2048()
	if d.Prime.BitLen() != 2048 || d.Subprime.BitLen() != 256 || d.Base.Sign() == 0 {
		t.Fatalf("dsa2048 wrong: p=%d q=%d g=%v", d.Prime.BitLen(), d.Subprime.BitLen(), d.Base.Sign())
	}
	// Verify hex decodes equal the byte-array originals (spot: g ends ...fc1a44, q ends ...f8343f)
	if got := hex.EncodeToString(d.Subprime.Bytes()); got != "dc1ca83fc1f7ec5ce1a9cdb23732c15403f7752343cd3b17f653b39816f8343f" {
		t.Fatalf("subprime mismatch: %s", got)
	}
	g := d.Base.Bytes()
	if g[len(g)-2] != 0x1a || g[len(g)-1] != 0x44 {
		t.Fatalf("base tail mismatch: %x", g[len(g)-4:])
	}
}
