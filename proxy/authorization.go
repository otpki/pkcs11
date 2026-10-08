package proxy

import (
	"context"
	"fmt"
)

// AuthorizationOperationActivateTarget is the synthetic operation presented to
// TargetConfig.Authorize immediately before a client-supplied PIN can be used
// for the physical HSM login. It is separate from the ordinary "Login" method
// so policy can allow logical login while restricting who may activate an
// inactive shared target.
const AuthorizationOperationActivateTarget = "proxy.activate-target"

// AuthorizationOperationListRoutes lets a target hide itself from a caller's route catalog.
// Server.RouteCatalog remains unfiltered for operators. A default-deny Authorize must allow this
// operation to keep its target listed.
const AuthorizationOperationListRoutes = "proxy.list-routes"

// AuthorizationRequest contains non-secret request metadata for a target-level
// authorization decision. PINs, request Auth bytes, key material, plaintext,
// ciphertext, and attribute values are never included.
type AuthorizationRequest struct {
	Identity RequestIdentity
	Target   string
	Revision string
	ClientID [16]byte
	// Operation is a raw.Module method name,
	// AuthorizationOperationActivateTarget, or
	// AuthorizationOperationListRoutes.
	Operation string
	// PhysicalActivation is true only for the exact caller selected as leader of
	// an inactive target's activation attempt.
	PhysicalActivation bool
}

// OperationAuthorizer decides whether an authenticated principal may perform a
// target operation. Returning nil allows the request. The zero value preserves
// the original behavior and relies on transport authentication, logical login,
// object isolation, and maintenance policy.
type OperationAuthorizer func(context.Context, AuthorizationRequest) error

func (target *brokerTarget) authorizeOperation(
	ctx context.Context,
	identity RequestIdentity,
	clientID [16]byte,
	operation string,
	physicalActivation bool,
) error {
	if target == nil || target.authorize == nil {
		return nil
	}
	// Authentication material is short-lived and belongs only to the transport
	// authenticator. Target authorization receives the established principal and
	// certificate identity, never the bearer/capability bytes themselves.
	identity.Auth = nil
	err := target.authorize(ctx, AuthorizationRequest{
		Identity:           identity,
		Target:             target.id,
		Revision:           target.revision,
		ClientID:           clientID,
		Operation:          operation,
		PhysicalActivation: physicalActivation,
	})
	if err != nil {
		return &RemoteError{Code: "forbidden", Message: fmt.Sprintf("operation %q is not authorized: %v", operation, err)}
	}
	return nil
}
