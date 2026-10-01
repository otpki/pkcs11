package proxy

import (
	"context"
	"errors"
	"slices"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

type virtualObject struct {
	handle       raw.ObjectHandle
	ownerSession raw.SessionHandle
	native       raw.ObjectHandle
	affine       bool
	recoverable  bool
	token        bool
	private      bool
	class        uint
	keyType      uint
	uniqueID     string
	id           []byte
	label        string
}

func optionalAttribute(module raw.Module, session raw.SessionHandle, object raw.ObjectHandle, typ uint) ([]byte, bool, error) {
	attributes, err := module.GetAttributeValue(session, object, []*raw.Attribute{raw.NewAttribute(typ, nil)})
	if len(attributes) == 1 && attributes[0] != nil && attributes[0].Value != nil {
		return append([]byte(nil), attributes[0].Value...), true, err
	}
	if err != nil && (raw.IsError(err, raw.CKR_ATTRIBUTE_TYPE_INVALID) || raw.IsError(err, raw.CKR_ATTRIBUTE_SENSITIVE)) {
		return nil, false, nil
	}
	return nil, false, err
}

func inspectNativeObject(module raw.Module, session raw.SessionHandle, object raw.ObjectHandle) (*virtualObject, error) {
	result := &virtualObject{native: object}
	if value, ok, err := optionalAttribute(module, session, object, raw.CKA_CLASS); err != nil {
		return nil, err
	} else if ok {
		result.class, _ = raw.ULong(value)
	}
	if value, ok, err := optionalAttribute(module, session, object, raw.CKA_KEY_TYPE); err != nil {
		return nil, err
	} else if ok {
		result.keyType, _ = raw.ULong(value)
	}
	if value, ok, err := optionalAttribute(module, session, object, raw.CKA_TOKEN); err != nil {
		return nil, err
	} else if ok {
		result.token, _ = raw.Bool(value)
	}
	privateKnown := false
	if value, ok, err := optionalAttribute(module, session, object, raw.CKA_PRIVATE); err != nil {
		return nil, err
	} else if ok {
		result.private, _ = raw.Bool(value)
		privateKnown = true
	}
	if !privateKnown && (result.class == raw.CKO_PRIVATE_KEY || result.class == raw.CKO_SECRET_KEY) {
		// Prefer false negatives over accidentally exposing a private object after
		// another logical client caused the physical token to be logged in.
		result.private = true
	}
	if value, ok, err := optionalAttribute(module, session, object, raw.CKA_UNIQUE_ID); err != nil {
		return nil, err
	} else if ok {
		result.uniqueID = string(value)
	}
	if value, ok, err := optionalAttribute(module, session, object, raw.CKA_ID); err != nil {
		return nil, err
	} else if ok {
		result.id = append([]byte(nil), value...)
	}
	if value, ok, err := optionalAttribute(module, session, object, raw.CKA_LABEL); err != nil {
		return nil, err
	} else if ok {
		result.label = string(value)
	}
	return result, nil
}

func (object *virtualObject) hasLocator() bool {
	return object.uniqueID != "" || len(object.id) > 0 || object.label != ""
}

func (object *virtualObject) locator() []*raw.Attribute {
	attributes := make([]*raw.Attribute, 0, 3)
	if object.class != 0 {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_CLASS, object.class))
	}
	if object.keyType != 0 {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_KEY_TYPE, object.keyType))
	}
	switch {
	case object.uniqueID != "":
		attributes = append(attributes, raw.NewAttribute(raw.CKA_UNIQUE_ID, object.uniqueID))
	case len(object.id) > 0:
		attributes = append(attributes, raw.NewAttribute(raw.CKA_ID, object.id))
	case object.label != "":
		attributes = append(attributes, raw.NewAttribute(raw.CKA_LABEL, object.label))
	}
	return attributes
}

func verifyStableLocator(module raw.Module, session raw.SessionHandle, object *virtualObject) bool {
	if object == nil || !object.token || !object.hasLocator() {
		return false
	}
	handles, err := module.FindAllObjects(session, object.locator(), 2)
	return err == nil && len(handles) == 1 && handles[0] == object.native
}

func (client *logicalClient) wrapObject(module raw.Module, nativeSession raw.SessionHandle, target *brokerTarget, lease *pkcs11.RawSessionLease, session *virtualSession, native raw.ObjectHandle) (raw.ObjectHandle, bool, bool, error) {
	if native == 0 {
		return 0, false, false, nil
	}
	// Token-object handles are application-scoped, while session-object handles
	// are tied to the session that created the object's lifetime. Check both maps
	// before querying attributes so repeated discovery returns the same virtual
	// handle when the native module reuses its application-wide handle.
	client.objectsMu.Lock()
	if existing := client.objectsByNative[sessionObjectKey{native: native}]; existing != 0 {
		object := client.objects[existing]
		client.objectsMu.Unlock()
		if object != nil {
			return existing, object.affine, false, nil
		}
	}
	if existing := client.objectsByNative[sessionObjectKey{session: session.handle, native: native}]; existing != 0 {
		object := client.objects[existing]
		client.objectsMu.Unlock()
		if object != nil {
			return existing, object.affine, false, nil
		}
	}
	client.objectsMu.Unlock()

	object, err := inspectNativeObject(module, nativeSession, native)
	if err != nil {
		return 0, false, false, err
	}
	if object.private && !client.authenticated() {
		return 0, false, false, client.authenticationRequiredError()
	}
	object.affine = !object.token
	object.recoverable = object.token && verifyStableLocator(module, nativeSession, object)
	key := sessionObjectKey{native: native}
	if object.affine {
		object.ownerSession = session.handle
		key.session = session.handle
	}

	client.objectsMu.Lock()
	defer client.objectsMu.Unlock()
	if existing := client.objectsByNative[key]; existing != 0 {
		if current := client.objects[existing]; current != nil {
			return existing, current.affine, false, nil
		}
	}
	if len(client.objects) >= client.maxObjects {
		return 0, false, false, raw.Error(raw.CKR_TOKEN_RESOURCE_EXCEEDED)
	}

	// Record the affinity before pinning and publish the virtual handle only
	// after the physical lease is attached. Holding objectsMu prevents another
	// logical session from observing an affine object whose owner has not yet
	// committed its native-session lifetime.
	if object.affine {
		session.affineObjects.Add(1)
		if err := session.pin(target, lease); err != nil {
			if remaining := session.affineObjects.Add(-1); remaining < 0 {
				panic("pkcs11 proxy: affine-object accounting underflow")
			}
			return 0, false, false, err
		}
	}
	handle := raw.ObjectHandle(client.nextObject)
	client.nextObject++
	object.handle = handle
	client.objects[handle] = object
	client.objectsByNative[key] = handle
	return handle, object.affine, true, nil
}

func (client *logicalClient) object(handle raw.ObjectHandle) (*virtualObject, error) {
	client.objectsMu.Lock()
	object := client.objects[handle]
	if object != nil {
		copied := *object
		copied.id = append([]byte(nil), object.id...)
		object = &copied
	}
	client.objectsMu.Unlock()
	if object == nil {
		return nil, raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)
	}
	if object.private && !client.authenticated() {
		return nil, client.authenticationRequiredError()
	}
	return object, nil
}

// objectBorrowSet holds one lifetime read lock per foreign owner session for
// the complete native call. The locks are deduplicated because attempting to
// upgrade one of several read locks during cleanup would self-deadlock.
type objectBorrowSet struct {
	target *brokerTarget
	owners []*virtualSession
	seen   map[*virtualSession]struct{}
}

func newObjectBorrowSet(target *brokerTarget) *objectBorrowSet {
	return &objectBorrowSet{target: target, seen: make(map[*virtualSession]struct{})}
}

func (borrows *objectBorrowSet) borrow(owner *virtualSession) error {
	if owner == nil {
		return raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)
	}
	if _, ok := borrows.seen[owner]; ok {
		return nil
	}
	owner.lifetime.RLock()
	if owner.closed || owner.lease == nil {
		owner.lifetime.RUnlock()
		return raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)
	}
	borrows.seen[owner] = struct{}{}
	borrows.owners = append(borrows.owners, owner)
	return nil
}

func (borrows *objectBorrowSet) close(ctx context.Context) error {
	if borrows == nil {
		return nil
	}
	for _, owner := range slices.Backward(borrows.owners) {
		owner.lifetime.RUnlock()
	}
	var errs []error
	for _, owner := range borrows.owners {
		errs = append(errs, owner.releaseIfIdle(ctx, borrows.target))
	}
	borrows.owners = nil
	borrows.seen = nil
	return errors.Join(errs...)
}

func (client *logicalClient) resolveObjectBorrowed(module raw.Module, nativeSession raw.SessionHandle, session *virtualSession, borrows *objectBorrowSet, handle raw.ObjectHandle) (raw.ObjectHandle, error) {
	if handle == 0 {
		return 0, nil
	}
	object, err := client.object(handle)
	if err != nil {
		return 0, err
	}
	if object.affine {
		owner, err := client.session(object.ownerSession)
		if err != nil {
			return 0, raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)
		}
		if owner == session {
			if !session.hasPinnedLease() {
				return 0, raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)
			}
		} else if err := borrows.borrow(owner); err != nil {
			return 0, err
		}
		return object.native, nil
	}
	if !object.recoverable {
		// Token-object handles are valid across sessions in one Cryptoki
		// application. When the token exposes no unique durable locator, retain the
		// native application handle rather than pinning one physical session for
		// the lifetime of the virtual handle.
		return object.native, nil
	}
	handles, err := module.FindAllObjects(nativeSession, object.locator(), 2)
	if err != nil {
		return 0, err
	}
	if len(handles) != 1 {
		return 0, raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)
	}
	return handles[0], nil
}

func (client *logicalClient) removeObject(session *virtualSession, handle raw.ObjectHandle) *virtualSession {
	client.objectsMu.Lock()
	object := client.objects[handle]
	if object != nil {
		key := sessionObjectKey{native: object.native}
		if object.affine {
			key.session = object.ownerSession
		}
		delete(client.objectsByNative, key)
		delete(client.objects, handle)
	}
	client.objectsMu.Unlock()
	if object == nil || !object.affine {
		return nil
	}
	owner := session
	if object.ownerSession != session.handle {
		var err error
		owner, err = client.session(object.ownerSession)
		if err != nil {
			return nil
		}
	}
	if remaining := owner.affineObjects.Add(-1); remaining < 0 {
		panic("pkcs11 proxy: affine-object accounting underflow")
	}
	return owner
}

func (client *logicalClient) removeAffineObjects(session raw.SessionHandle) {
	client.objectsMu.Lock()
	for handle, object := range client.objects {
		if object.affine && object.ownerSession == session {
			key := sessionObjectKey{native: object.native}
			if object.affine {
				key.session = object.ownerSession
			}
			delete(client.objectsByNative, key)
			delete(client.objects, handle)
		}
	}
	client.objectsMu.Unlock()
}

// takePrivateObjects invalidates every private virtual handle as required by a
// logical C_Logout. Private session objects are returned by owner session so
// the caller can destroy them physically without logging out the shared HSM.
func (client *logicalClient) takePrivateObjects() map[raw.SessionHandle][]raw.ObjectHandle {
	result := make(map[raw.SessionHandle][]raw.ObjectHandle)
	client.objectsMu.Lock()
	for handle, object := range client.objects {
		if object == nil || !object.private {
			continue
		}
		key := sessionObjectKey{native: object.native}
		if object.affine {
			key.session = object.ownerSession
			result[object.ownerSession] = append(result[object.ownerSession], object.native)
		}
		delete(client.objectsByNative, key)
		delete(client.objects, handle)
	}
	client.objectsMu.Unlock()
	return result
}

func (client *logicalClient) refreshObject(module raw.Module, nativeSession raw.SessionHandle, target *brokerTarget, lease *pkcs11.RawSessionLease, session *virtualSession, handle, native raw.ObjectHandle) (becameAffine, becameStable bool, err error) {
	updated, err := inspectNativeObject(module, nativeSession, native)
	if err != nil {
		return false, false, err
	}
	if updated.private && !client.authenticated() {
		return false, false, client.authenticationRequiredError()
	}
	updated.handle = handle
	updated.affine = !updated.token
	updated.recoverable = updated.token && verifyStableLocator(module, nativeSession, updated)
	if updated.affine {
		updated.ownerSession = session.handle
	}

	client.objectsMu.Lock()
	defer client.objectsMu.Unlock()
	old := client.objects[handle]
	if old == nil || (old.affine && old.ownerSession != session.handle) {
		return false, false, raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)
	}

	becameAffine = !old.affine && updated.affine
	becameStable = old.affine && !updated.affine
	if becameAffine {
		session.affineObjects.Add(1)
		if err := session.pin(target, lease); err != nil {
			if remaining := session.affineObjects.Add(-1); remaining < 0 {
				panic("pkcs11 proxy: affine-object accounting underflow")
			}
			return false, false, err
		}
	}

	oldKey := sessionObjectKey{native: old.native}
	if old.affine {
		oldKey.session = old.ownerSession
	}
	delete(client.objectsByNative, oldKey)
	client.objects[handle] = updated
	newKey := sessionObjectKey{native: updated.native}
	if updated.affine {
		newKey.session = updated.ownerSession
	}
	client.objectsByNative[newKey] = handle
	if becameStable {
		if remaining := session.affineObjects.Add(-1); remaining < 0 {
			panic("pkcs11 proxy: affine-object accounting underflow")
		}
	}
	return becameAffine, becameStable, nil
}

func (client *logicalClient) resolveObjectOnLease(ctx context.Context, lease *pkcs11.RawSessionLease, session *virtualSession, borrows *objectBorrowSet, handle raw.ObjectHandle) (raw.ObjectHandle, error) {
	var native raw.ObjectHandle
	err := lease.Call(ctx, "proxy-resolve-object", func(module raw.Module, nativeSession raw.SessionHandle) error {
		var resolveErr error
		native, resolveErr = client.resolveObjectBorrowed(module, nativeSession, session, borrows, handle)
		return resolveErr
	})
	return native, err
}

func (client *logicalClient) rollbackVirtualObjects(session *virtualSession, handles []raw.ObjectHandle) {
	for _, handle := range handles {
		client.removeObject(session, handle)
	}
}
