package proxy

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

var (
	sessionHandleType = reflect.TypeFor[raw.SessionHandle]()
	objectHandleType  = reflect.TypeFor[raw.ObjectHandle]()
	errorType         = reflect.TypeFor[error]()
)

// invoke executes one logical Cryptoki method. Module lifecycle, logical
// sessions, and login are handled here; ordinary session-bound methods are
// translated and dispatched through one managed physical session lease.
//
//nolint:contextcheck // Nil callers intentionally fall back to a detached context.
func (target *brokerTarget) invoke(
	ctx context.Context,
	identity RequestIdentity,
	client *logicalClient,
	method string,
	arguments []any,
) ([]any, []parameterUpdate, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	switch method {
	case "Initialize", "InitializeLegacy":
		return nil, nil, client.initialize()
	case "InitializeWithFlags":
		return nil, nil, client.initialize()
	case "Finalize":
		return nil, nil, client.finalize(ctx, target)
	}

	if !allowsBeforeInitialize(method) && !client.isInitialized() {
		return nil, nil, raw.Error(raw.CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	switch method {
	case "OpenSession":
		if len(arguments) != 2 {
			return nil, nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
		}
		slot, ok := arguments[0].(raw.SlotID)
		if !ok {
			return nil, nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
		}
		flags, ok := arguments[1].(uint)
		if !ok {
			return nil, nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
		}
		if err := target.validateSlot(slot); err != nil {
			return nil, nil, err
		}
		handle, err := client.openSession(target, slot, flags)
		if err != nil {
			return nil, nil, err
		}
		return []any{handle}, nil, nil
	case "CloseSession":
		handle, err := requireSessionArgument(arguments)
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, client.closeSession(ctx, target, handle)
	case "CloseAllSessions":
		if len(arguments) != 1 {
			return nil, nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
		}
		slot, ok := arguments[0].(raw.SlotID)
		if !ok {
			return nil, nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
		}
		if err := target.validateSlot(slot); err != nil {
			return nil, nil, err
		}
		return nil, nil, client.closeAllSessions(ctx, target, slot)
	case "GetSessionInfo":
		handle, err := requireSessionArgument(arguments)
		if err != nil {
			return nil, nil, err
		}
		info, err := target.getLogicalSessionInfo(ctx, client, handle)
		if err != nil {
			return nil, nil, err
		}
		return []any{info}, nil, nil
	case "Login":
		return nil, nil, target.invokeLogin(ctx, identity, client, arguments, false)
	case "LoginUser":
		return nil, nil, target.invokeLogin(ctx, identity, client, arguments, true)
	case "Logout":
		handle, err := requireSessionArgument(arguments)
		if err != nil {
			return nil, nil, err
		}
		if _, err := client.session(handle); err != nil {
			return nil, nil, err
		}
		return nil, nil, client.logicalLogout(ctx, target)
	case "SessionCancel":
		updates, err := target.invokeSessionCancel(ctx, client, arguments)
		return nil, updates, err
	case "AsyncComplete", "AsyncGetID", "AsyncJoin":
		return nil, nil, raw.Error(raw.CKR_SESSION_ASYNC_NOT_SUPPORTED)
	case "SetOutputBufferPolicy":
		// Native output-buffer policy is server-owned because the local module may
		// be shared by several remote clients or target routes. The target's managed
		// vendor adapter has already applied the correct policy; accepting a remote
		// mutation here would let one client change another client's ABI behavior.
		if len(arguments) != 1 {
			return nil, nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
		}
		if _, ok := arguments[0].(raw.OutputBufferPolicy); !ok {
			return nil, nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
		}
		return nil, nil, nil
	case "InitToken":
		return nil, nil, target.invokeInitToken(ctx, identity, client, arguments)
	}

	methodInfo, ok := rawModuleType.MethodByName(method)
	if !ok {
		return nil, nil, &RemoteError{Code: "unknown_method", Message: method}
	}
	if methodInfo.Type.NumIn() > 0 && methodInfo.Type.In(0) == sessionHandleType {
		return target.invokeSessionMethod(ctx, identity, client, methodInfo, method, arguments)
	}

	// Module-level calls that name a slot are restricted to the one token bound
	// to this target. This prevents a caller from escaping the target route and
	// opening a different partition exposed by the same native library.
	if err := target.validateModuleArguments(method, arguments); err != nil {
		return nil, nil, err
	}
	values, err := target.invokeModuleMethod(ctx, client, method, arguments)
	return values, nil, err
}

func requireSessionArgument(arguments []any) (raw.SessionHandle, error) {
	if len(arguments) == 0 {
		return 0, raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	handle, ok := arguments[0].(raw.SessionHandle)
	if !ok || handle == 0 {
		return 0, raw.Error(raw.CKR_SESSION_HANDLE_INVALID)
	}
	return handle, nil
}

func (target *brokerTarget) validateSlot(slot raw.SlotID) error {
	if slot != target.remoteSlot {
		return raw.Error(raw.CKR_SLOT_ID_INVALID)
	}
	return nil
}

func (target *brokerTarget) validateModuleArguments(method string, arguments []any) error {
	switch method {
	case "GetSlotInfo", "GetTokenInfo", "GetMechanismList", "GetMechanismInfo":
		if len(arguments) == 0 {
			return raw.Error(raw.CKR_ARGUMENTS_BAD)
		}
		slot, ok := arguments[0].(raw.SlotID)
		if !ok {
			return raw.Error(raw.CKR_ARGUMENTS_BAD)
		}
		return target.validateSlot(slot)
	}
	return nil
}

func (target *brokerTarget) invokeModuleMethod(ctx context.Context, client *logicalClient, method string, arguments []any) ([]any, error) {
	// A proxy route exposes one stable synthetic slot. The physical slot selected
	// by the managed client may change after hotplug or rediscovery, but remote
	// callers keep using the same route-local identifier.
	if method == "GetSlotList" {
		if len(arguments) != 1 {
			return nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
		}
		tokenPresent, ok := arguments[0].(bool)
		if !ok {
			return nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
		}
		if !tokenPresent {
			return []any{[]raw.SlotID{target.remoteSlot}}, nil
		}
		managed := target.currentClient()
		if managed == nil {
			return nil, raw.ErrClosed
		}
		present := false
		err := managed.WithRawModule(ctx, pkcs11.RawModuleOptions{Operation: "proxy-get-slot-list"}, func(module raw.Module) error {
			slots, err := module.GetSlotList(true)
			if err != nil {
				return err
			}
			if slices.Contains(slots, target.physicalSlot) {
				present = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if !present {
			return []any{[]raw.SlotID{}}, nil
		}
		return []any{[]raw.SlotID{target.remoteSlot}}, nil
	}
	if method == "WaitForSlotEvent" {
		return target.waitForSelectedSlotEvent(ctx, arguments)
	}
	managed := target.currentClient()
	if managed == nil {
		return nil, raw.ErrClosed
	}
	nativeArguments := append([]any(nil), arguments...)
	switch method {
	case "GetSlotInfo", "GetTokenInfo", "GetMechanismList", "GetMechanismInfo":
		nativeArguments[0] = target.physicalSlot
	}
	var values []any
	err := managed.WithRawModule(ctx, pkcs11.RawModuleOptions{Operation: "proxy-" + strings.ToLower(method)}, func(module raw.Module) error {
		var err error
		values, err = callRawMethod(module, method, nativeArguments)
		return err
	})
	if err != nil {
		return values, err
	}
	if method == "GetTokenInfo" && len(values) == 1 {
		if info, ok := values[0].(raw.TokenInfo); ok {
			info.MaxSessionCount = uint(target.budget.MaxVirtualSessionsPerClient)
			info.SessionCount = uint(client.sessionCount())
			info.MaxRwSessionCount = uint(target.budget.MaxVirtualSessionsPerClient)
			info.RwSessionCount = uint(client.readWriteSessionCount())
			// The local raw binding retains the complete PKCS #11 3.2 async API,
			// but the network proxy cannot safely retain arbitrary provider pointers
			// after CKR_PENDING. Never advertise an unsafe capability remotely.
			info.Flags &^= raw.CKF_ASYNC_SESSION_SUPPORTED
			values[0] = info
		}
	}
	return values, nil
}

func (target *brokerTarget) waitForSelectedSlotEvent(ctx context.Context, arguments []any) ([]any, error) {
	if len(arguments) != 1 {
		return nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	flags, ok := arguments[0].(uint)
	if !ok {
		return nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
	}

	// A native blocking C_WaitForSlotEvent cannot be interrupted reliably when a
	// request-scoped TCP connection disappears. Poll the module in nonblocking
	// mode instead, preserving CKF_DONT_BLOCK semantics while allowing the proxy
	// context to cancel promptly and without leaking a native call goroutine.
	nonblocking := flags&raw.CKF_DONT_BLOCK != 0
	callFlags := flags | raw.CKF_DONT_BLOCK
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		var slot raw.SlotID
		managed := target.currentClient()
		if managed == nil {
			return nil, raw.ErrClosed
		}
		err := managed.WithRawModule(ctx, pkcs11.RawModuleOptions{Operation: "proxy-wait-for-slot-event"}, func(module raw.Module) error {
			var callErr error
			slot, callErr = module.WaitForSlotEvent(callFlags)
			return callErr
		})
		switch {
		case err == nil && slot == target.physicalSlot:
			return []any{target.remoteSlot}, nil
		case err == nil:
			// Ignore events for slots that are not exposed by this target and drain
			// any immediately queued events before waiting.
			continue
		case raw.IsError(err, raw.CKR_NO_EVENT) && nonblocking:
			return nil, err
		case raw.IsError(err, raw.CKR_NO_EVENT):
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ticker.C:
				continue
			}
		default:
			return nil, err
		}
	}
}

func callRawMethod(module raw.Module, method string, arguments []any) (values []any, err error) {
	if module == nil {
		return nil, raw.ErrClosed
	}
	call := reflect.ValueOf(module).MethodByName(method)
	if !call.IsValid() {
		return nil, &RemoteError{Code: "unknown_method", Message: method}
	}
	if len(arguments) != call.Type().NumIn() {
		return nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	inputs := make([]reflect.Value, len(arguments))
	for index, argument := range arguments {
		expected := call.Type().In(index)
		if argument == nil {
			inputs[index] = reflect.Zero(expected)
			continue
		}
		value := reflect.ValueOf(argument)
		if value.Type().AssignableTo(expected) {
			inputs[index] = value
			continue
		}
		if value.Type().ConvertibleTo(expected) {
			inputs[index] = value.Convert(expected)
			continue
		}
		return nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			values = nil
			err = fmt.Errorf("pkcs11 proxy: invoke %s: %v", method, recovered)
		}
	}()
	outputs := call.Call(inputs)
	if len(outputs) != 0 && outputs[len(outputs)-1].Type().Implements(errorType) {
		last := outputs[len(outputs)-1]
		outputs = outputs[:len(outputs)-1]
		if !last.IsNil() {
			if resultErr, ok := reflect.TypeAssert[error](last); ok {
				err = resultErr
			}
		}
	}
	values = make([]any, len(outputs))
	for index, output := range outputs {
		values[index] = output.Interface()
	}
	return values, err
}

func (target *brokerTarget) getLogicalSessionInfo(ctx context.Context, client *logicalClient, handle raw.SessionHandle) (raw.SessionInfo, error) {
	session, err := client.session(handle)
	if err != nil {
		return raw.SessionInfo{}, err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	session.touch()
	_ = ctx
	return raw.SessionInfo{
		SlotID: session.slot,
		Flags:  session.flags,
		State:  raw.State(logicalSessionState(client, session.readWrite)),
	}, nil
}

func logicalSessionState(client *logicalClient, readWrite bool) uint {
	userType, loggedIn := client.loginIdentity()
	if !loggedIn {
		if readWrite {
			return raw.CKS_RW_PUBLIC_SESSION
		}
		return raw.CKS_RO_PUBLIC_SESSION
	}
	if userType == raw.CKU_SO {
		return raw.CKS_RW_SO_FUNCTIONS
	}
	if readWrite {
		return raw.CKS_RW_USER_FUNCTIONS
	}
	return raw.CKS_RO_USER_FUNCTIONS
}

func (target *brokerTarget) invokeLogin(ctx context.Context, identity RequestIdentity, client *logicalClient, arguments []any, withUsername bool) error {
	minimum := 3
	if withUsername {
		minimum = 4
	}
	if len(arguments) != minimum {
		return raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	handle, ok := arguments[0].(raw.SessionHandle)
	if !ok {
		return raw.Error(raw.CKR_SESSION_HANDLE_INVALID)
	}
	session, err := client.session(handle)
	if err != nil {
		return err
	}
	userType, ok := arguments[1].(uint)
	if !ok {
		return raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	pin, ok := arguments[2].([]byte)
	if !ok {
		return raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	username := ""
	if withUsername {
		username, ok = arguments[3].(string)
		if !ok {
			return raw.Error(raw.CKR_ARGUMENTS_BAD)
		}
	}
	defer wipe(pin)
	if userType == raw.CKU_CONTEXT_SPECIFIC {
		session.mu.Lock()
		defer session.mu.Unlock()
		session.touch()
		if len(session.operations) == 0 {
			return raw.Error(raw.CKR_OPERATION_NOT_INITIALIZED)
		}
		lease, finish, ok := session.beginPinnedUse(ctx, target)
		if !ok {
			return raw.Error(raw.CKR_OPERATION_NOT_INITIALIZED)
		}
		loginErr := target.contextLogin(ctx, identity, client, lease, userType, username, pin)
		return errors.Join(loginErr, finish())
	}
	if userType == raw.CKU_SO {
		if !target.maintenance.Enabled {
			return raw.Error(raw.CKR_USER_TYPE_INVALID)
		}
		if !session.readWrite {
			return raw.Error(raw.CKR_SESSION_READ_ONLY)
		}
		if target.hasReadOnlySession() {
			return raw.Error(raw.CKR_SESSION_READ_ONLY_EXISTS)
		}
	}
	return client.logicalLogin(ctx, target, identity, userType, pin, username)
}

func (target *brokerTarget) invokeSessionCancel(ctx context.Context, client *logicalClient, arguments []any) (updates []parameterUpdate, err error) {
	if len(arguments) != 2 {
		return nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	handle, ok := arguments[0].(raw.SessionHandle)
	if !ok {
		return nil, raw.Error(raw.CKR_SESSION_HANDLE_INVALID)
	}
	flags, ok := arguments[1].(uint)
	if !ok {
		return nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	if flags&^supportedCancelFlags() != 0 {
		return nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	session, err := client.session(handle)
	if err != nil {
		return nil, err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	session.touch()
	if flags == 0 {
		return nil, nil
	}
	names := operationsForCancelFlags(flags)
	if session.operations["restored-operation"] {
		names = append(names, "restored-operation")
	}
	active := names[:0]
	for _, name := range names {
		if session.operations[name] {
			active = append(active, name)
		}
	}
	names = active
	if len(names) == 0 && !session.hasPinnedLease() {
		return nil, nil
	}
	lease, temporary, finishUse, err := session.ensureLease(ctx, target, "proxy-session-cancel")
	if err != nil {
		return nil, err
	}
	if finishUse != nil {
		defer func() { err = errors.Join(err, finishUse()) }()
	}
	closeTemporary := temporary
	defer func() {
		if closeTemporary {
			err = errors.Join(err, lease.Close(ctx))
		}
	}()
	err = lease.Call(ctx, "proxy-session-cancel", func(module raw.Module, native raw.SessionHandle) error {
		return module.SessionCancel(native, flags)
	})
	if err != nil {
		if raw.IsError(err, raw.CKR_PENDING) {
			if temporary {
				if pinErr := session.pin(target, lease); pinErr != nil {
					lease.MarkBroken()
					return nil, pinErr
				}
				closeTemporary = false
			}
			return nil, err
		}
		return nil, err
	}
	// Remove only the operation classes requested by the caller. Session objects
	// and unrelated halves of a dual-function operation remain pinned.
	updates, releaseErr := session.cancelOperations(ctx, target, names)
	return updates, releaseErr
}

func (target *brokerTarget) invokeSessionMethod(
	ctx context.Context,
	identity RequestIdentity,
	client *logicalClient,
	methodInfo reflect.Method,
	method string,
	arguments []any,
) (result []any, updates []parameterUpdate, err error) {
	handle, err := requireSessionArgument(arguments)
	if err != nil {
		return nil, nil, err
	}
	session, err := client.session(handle)
	if err != nil {
		return nil, nil, err
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil, nil, raw.Error(raw.CKR_SESSION_CLOSED)
	}
	session.touch()

	if method == "InitPIN" || method == "SetPIN" {
		if err := target.authorizeMaintenance(ctx, identity, method); err != nil {
			return nil, nil, err
		}
	}

	descriptor := operationForMethod(method)
	if method == "GetOperationState" {
		// Native operation state belongs to the exact physical session carrying the
		// active multipart operation. Checking out an unrelated pooled session would
		// return meaningless state or leak another caller's operation.
		if !session.hasPinnedLease() || len(session.operations) == 0 {
			return nil, nil, raw.Error(raw.CKR_OPERATION_NOT_INITIALIZED)
		}
	}
	if method == "SetOperationState" && len(session.operations) != 0 {
		return nil, nil, raw.Error(raw.CKR_OPERATION_ACTIVE)
	}
	if err := session.requireOperations(descriptor.Required); err != nil {
		return nil, nil, err
	}
	if descriptor.Transition == operationStart && descriptor.Name != "" && session.operations[descriptor.Name] {
		return nil, nil, raw.Error(raw.CKR_OPERATION_ACTIVE)
	}

	lease, temporary, finishUse, err := session.ensureLease(ctx, target, "proxy-"+strings.ToLower(method))
	if err != nil {
		return nil, nil, err
	}
	if finishUse != nil {
		defer func() { err = errors.Join(err, finishUse()) }()
	}
	closeTemporary := temporary
	if err := target.ensureLeaseAuthenticated(ctx, client, lease); err != nil {
		if temporary {
			lease.MarkBroken()
			_ = lease.Close(ctx)
			closeTemporary = false
		}
		return nil, nil, err
	}
	defer func() {
		if closeTemporary {
			err = errors.Join(err, lease.Close(ctx))
		}
	}()

	borrows := newObjectBorrowSet(target)
	defer func() { err = errors.Join(err, borrows.close(ctx)) }()

	nativeArguments := make([]any, len(arguments))
	copy(nativeArguments, arguments)
	nativeArguments[0] = lease.Handle()
	for index := 1; index < len(nativeArguments); index++ {
		translated, translateErr := client.translateObjectHandles(nativeArguments[index], func(object raw.ObjectHandle) (raw.ObjectHandle, error) {
			return client.resolveObjectOnLease(ctx, lease, session, borrows, object)
		})
		if translateErr != nil {
			return nil, nil, translateErr
		}
		nativeArguments[index] = translated
	}
	if method == "FindObjectsInit" || method == "FindAllObjects" {
		if err := client.restrictFindTemplate(nativeArguments); err != nil {
			return nil, nil, err
		}
	}
	if err := client.authorizeTemplates(method, nativeArguments); err != nil {
		return nil, nil, err
	}

	var nativeValues []any
	callNative := func() error {
		return lease.Call(ctx, "proxy-"+strings.ToLower(method), func(module raw.Module, native raw.SessionHandle) error {
			nativeArguments[0] = native
			var err error
			nativeValues, err = callRawMethod(module, method, nativeArguments)
			return err
		})
	}
	callErr := callNative()
	if raw.IsError(callErr, raw.CKR_USER_NOT_LOGGED_IN) && client.authenticated() {
		// CKR_USER_NOT_LOGGED_IN is reported before the requested operation is
		// performed. Server-managed and protected-path targets may safely perform
		// one coordinated reauthentication attempt. A client-activated target has
		// intentionally retained no PIN, so it invalidates the activation generation
		// and fails closed until another audited C_Login supplies one.
		lease.InvalidateAuthentication()
		target.invalidatePhysicalLogin()
		if target.login.Mode == PhysicalLoginClientActivated {
			callErr = errors.Join(callErr, activationRequiredError())
		} else if authErr := target.ensureLeaseAuthenticated(ctx, client, lease); authErr == nil {
			nativeValues = nil
			callErr = callNative()
		} else {
			callErr = errors.Join(callErr, authErr)
		}
	}
	createdNative := createdNativeObjectHandles(method, nativeValues)
	cleanupAfterSuccess := func(cause error) error {
		if callErr != nil || len(createdNative) == 0 {
			return cause
		}
		cleanupErr := cleanupNativeObjects(ctx, lease, createdNative)
		if cleanupErr != nil {
			lease.MarkBroken()
		}
		return errors.Join(cause, cleanupErr)
	}

	// Preserve partial outputs allowed by Cryptoki (most notably attribute reads)
	// while ensuring that no native object handle crosses the network boundary.
	values, affine, virtualHandles, virtualizeErr := client.virtualizeResults(ctx, target, lease, session, methodInfo, nativeValues)
	if virtualizeErr != nil {
		client.rollbackVirtualObjects(session, virtualHandles)
		resultErr := cleanupAfterSuccess(virtualizeErr)
		if descriptor.Transition != operationStateless || session.pinnedLeaseIs(lease) {
			session.cancelLeaseLocked(ctx, target)
			client.removeAffineObjects(session.handle)
			closeTemporary = false
		}
		return nil, nil, resultErr
	}

	argumentAffine, argumentHandles, syncErr := client.syncMutableArguments(ctx, target, lease, session, arguments, nativeArguments)
	virtualHandles = append(virtualHandles, argumentHandles...)
	if syncErr != nil {
		client.rollbackVirtualObjects(session, virtualHandles)
		resultErr := cleanupAfterSuccess(syncErr)
		if descriptor.Transition != operationStateless || session.pinnedLeaseIs(lease) {
			session.cancelLeaseLocked(ctx, target)
			client.removeAffineObjects(session.handle)
			closeTemporary = false
		}
		return nil, nil, resultErr
	}
	affine = affine || argumentAffine

	if callErr != nil {
		if operationErrorKeepsState(callErr) {
			// Async sessions are deliberately disabled unless a target explicitly
			// opts in after validating native input-buffer retention. A synchronous
			// provider returning CKR_PENDING is therefore treated as unusable rather
			// than releasing memory that it may still reference.
			if raw.IsError(callErr, raw.CKR_PENDING) {
				lease.MarkBroken()
				if session.pinnedLeaseIs(lease) {
					session.cancelLeaseLocked(ctx, target)
					client.removeAffineObjects(session.handle)
					closeTemporary = false
				}
				return values, nil, raw.Error(raw.CKR_SESSION_ASYNC_NOT_SUPPORTED)
			}
			if descriptor.Transition == operationStart && descriptor.Name != "" {
				if err := session.startOperation(target, descriptor.Name, lease, firstMechanisms(nativeArguments)); err != nil {
					lease.MarkBroken()
					return nil, nil, err
				}
				closeTemporary = false
			}
			return values, nil, callErr
		}

		// A failed stateful call commonly terminates provider operation state. The
		// exact residual state is vendor-dependent, so discard the pinned session
		// rather than returning it to another logical client.
		if descriptor.Transition != operationStateless || len(descriptor.Required) != 0 {
			if session.pinnedLeaseIs(lease) {
				session.cancelLeaseLocked(ctx, target)
				client.removeAffineObjects(session.handle)
				closeTemporary = false
			} else {
				lease.MarkBroken()
			}
		}
		return values, nil, callErr
	}

	if descriptor.Transition == operationStart {
		if err := session.startOperation(target, descriptor.Name, lease, firstMechanisms(nativeArguments)); err != nil {
			client.rollbackVirtualObjects(session, virtualHandles)
			lease.MarkBroken()
			_ = lease.Close(ctx)
			closeTemporary = false
			return nil, nil, cleanupAfterSuccess(err)
		}
		closeTemporary = false
	}

	if affine {
		if !session.hasPinnedLease() {
			if err := session.pin(target, lease); err != nil {
				client.rollbackVirtualObjects(session, virtualHandles)
				lease.MarkBroken()
				_ = lease.Close(ctx)
				closeTemporary = false
				return nil, nil, cleanupAfterSuccess(err)
			}
		}
		if session.pinnedLeaseIs(lease) {
			closeTemporary = false
		}
	}

	if descriptor.Transition == operationFinish {
		updates, err = session.finishOperation(ctx, target, descriptor.Name)
		if err != nil {
			return nil, nil, err
		}
		if !session.hasPinnedLease() {
			closeTemporary = temporary
		}
	}

	pinnedByMutation, err := client.applyPostCallObjectState(ctx, target, lease, session, method, arguments, nativeArguments, values)
	if err != nil {
		client.rollbackVirtualObjects(session, virtualHandles)
		return nil, nil, cleanupAfterSuccess(err)
	}
	if pinnedByMutation {
		closeTemporary = false
	}
	if temporary && !session.hasPinnedLease() {
		closeTemporary = true
	}
	return values, updates, nil
}

func createdNativeObjectHandles(method string, values []any) []raw.ObjectHandle {
	appendHandle := func(result []raw.ObjectHandle, index int) []raw.ObjectHandle {
		if index >= len(values) {
			return result
		}
		handle, ok := values[index].(raw.ObjectHandle)
		if ok && handle != 0 {
			return append(result, handle)
		}
		return result
	}
	var result []raw.ObjectHandle
	switch method {
	case "CreateObject", "CopyObject", "GenerateKey", "UnwrapKey", "DeriveKey", "DecapsulateKey", "UnwrapKeyAuthenticated":
		result = appendHandle(result, 0)
	case "GenerateKeyPair":
		result = appendHandle(result, 0)
		result = appendHandle(result, 1)
	case "EncapsulateKey":
		result = appendHandle(result, 1)
	}
	return result
}

func cleanupNativeObjects(ctx context.Context, lease *pkcs11.RawSessionLease, handles []raw.ObjectHandle) error {
	var errs []error
	for _, handle := range handles {
		if handle == 0 {
			continue
		}
		err := lease.Call(ctx, "proxy-cleanup-unreturned-object", func(module raw.Module, session raw.SessionHandle) error {
			return module.DestroyObject(session, handle)
		})
		if err != nil && !raw.IsError(err, raw.CKR_OBJECT_HANDLE_INVALID) {
			errs = append(errs, fmt.Errorf("destroy unreturned object 0x%x: %w", uint(handle), err))
		}
	}
	return errors.Join(errs...)
}

func firstMechanisms(arguments []any) []*raw.Mechanism {
	for _, argument := range arguments {
		if mechanisms, ok := argument.([]*raw.Mechanism); ok {
			return mechanisms
		}
	}
	return nil
}

func (target *brokerTarget) authorizeMaintenance(ctx context.Context, identity RequestIdentity, operation string) error {
	if !target.maintenance.Enabled {
		target.obs.emitAudit(ctx, AuditEvent{Type: "maintenance", Target: target.id, Method: operation, ClientID: hexID(identity.ClientID), Principal: identity.Principal, Code: "maintenance_disabled"})
		return raw.Error(raw.CKR_FUNCTION_NOT_SUPPORTED)
	}
	if target.maintenance.Authorize != nil {
		if err := target.maintenance.Authorize(ctx, identity, operation); err != nil {
			target.obs.emitAudit(ctx, AuditEvent{Type: "maintenance", Target: target.id, Method: operation, ClientID: hexID(identity.ClientID), Principal: identity.Principal, Code: "maintenance_unauthorized"})
			return &RemoteError{Code: "maintenance_unauthorized", Message: err.Error()}
		}
	}
	target.obs.emitAudit(ctx, AuditEvent{Type: "maintenance", Target: target.id, Method: operation, ClientID: hexID(identity.ClientID), Principal: identity.Principal})
	return nil
}

func (target *brokerTarget) invokeInitToken(ctx context.Context, identity RequestIdentity, client *logicalClient, arguments []any) error {
	if err := target.authorizeMaintenance(ctx, identity, "InitToken"); err != nil {
		return err
	}
	if len(arguments) != 3 {
		return raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	slot, ok := arguments[0].(raw.SlotID)
	if !ok {
		return raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	if err := target.validateSlot(slot); err != nil {
		return err
	}
	pin, ok := arguments[1].([]byte)
	if !ok {
		return raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	defer wipe(pin)
	label, ok := arguments[2].(string)
	if !ok {
		return raw.Error(raw.CKR_ARGUMENTS_BAD)
	}

	// C_InitToken is destructive and requires no open logical sessions. execute
	// holds the exclusive maintenance lock, so this count cannot change until the
	// local module has been reopened and a new target epoch has been published.
	if client.sessionCount() != 0 || target.logicalSessionCount() != 0 {
		return raw.Error(raw.CKR_SESSION_EXISTS)
	}

	target.controlMu.Lock()
	defer target.controlMu.Unlock()
	if target.control != nil {
		_ = target.control.Close(ctx)
		target.control = nil
	}
	target.invalidatePhysicalLogin()

	oldClient := target.currentClient()
	if oldClient == nil {
		return raw.ErrClosed
	}
	if err := oldClient.Deactivate(ctx); err != nil {
		// Deactivation is the coordinated, single physical logout boundary. Do not
		// proceed with destructive initialization while a session may still be live.
		return err
	}
	initErr := oldClient.WithRawModule(ctx, pkcs11.RawModuleOptions{Operation: "proxy-init-token"}, func(module raw.Module) error {
		return module.InitToken(target.physicalSlot, pin, label)
	})
	if initErr != nil {
		// The token was not changed. Restore the existing managed client and control
		// session so a failed maintenance request does not disable the route.
		refreshErr := oldClient.Refresh(ctx)
		if refreshErr == nil {
			target.physicalSlot = oldClient.Device().Fingerprint.SlotID
		}
		control, controlErr := oldClient.AcquireRawSession(ctx, pkcs11.RawSessionOptions{ReadWrite: true, Operation: "proxy-control-session-after-failed-init-token"})
		if controlErr == nil {
			target.control = control
		}
		return errors.Join(initErr, refreshErr, controlErr)
	}

	// The token label, serial metadata, mechanism inventory, and login state may
	// all have changed. Close and reopen the managed client by slot rather than
	// refreshing through the old selector, which may contain the previous label.
	closeErr := oldClient.Close(ctx)
	selectorSlot := target.physicalSlot
	config := target.clientConfig
	config.Token = pkcs11.TokenSelector{SlotID: &selectorSlot}
	newClient, openErr := pkcs11.Open(ctx, config)
	if openErr != nil {
		target.closed.Store(true)
		return errors.Join(closeErr, fmt.Errorf("reopen initialized token: %w", openErr))
	}
	control, controlErr := newClient.AcquireRawSession(ctx, pkcs11.RawSessionOptions{ReadWrite: true, Operation: "proxy-control-session-after-init-token"})
	if controlErr != nil {
		_ = newClient.Close(ctx)
		target.closed.Store(true)
		return errors.Join(closeErr, fmt.Errorf("open control session after token initialization: %w", controlErr))
	}

	target.swapClient(newClient)
	target.clientMu.Lock()
	target.clientConfig = config
	target.clientMu.Unlock()
	target.control = control
	target.physicalSlot = newClient.Device().Fingerprint.SlotID
	target.loginScope = newClient.LoginScope()

	if err := target.rotateEpoch(); err != nil {
		target.closed.Store(true)
		return errors.Join(closeErr, err)
	}
	target.resetLogicalClientsAfterTokenInitialization(ctx, client.id)
	target.ledger.reset(target.currentEpoch())
	return closeErr
}

func (target *brokerTarget) resetLogicalClientsAfterTokenInitialization(ctx context.Context, currentID [16]byte) {
	target.clientsMu.Lock()
	current := target.clients[currentID]
	var retired []*logicalClient
	for id, candidate := range target.clients {
		if id == currentID {
			continue
		}
		delete(target.clients, id)
		retired = append(retired, candidate)
	}
	target.clientsMu.Unlock()
	if current != nil {
		current.resetAfterTokenInitialization()
	}
	for _, candidate := range retired {
		_ = candidate.close(ctx, target)
	}
}

func (client *logicalClient) translateObjectHandles(value any, translate func(raw.ObjectHandle) (raw.ObjectHandle, error)) (any, error) {
	if value == nil {
		return nil, nil
	}
	translated, err := translateObjectValue(reflect.ValueOf(value), translate)
	if err != nil {
		return nil, err
	}
	return translated.Interface(), nil
}

func translateObjectValue(value reflect.Value, translate func(raw.ObjectHandle) (raw.ObjectHandle, error)) (reflect.Value, error) {
	if !value.IsValid() {
		return value, nil
	}
	if value.Type() == objectHandleType {
		rawHandle, ok := reflect.TypeAssert[raw.ObjectHandle](value)
		if !ok {
			return reflect.Value{}, fmt.Errorf("proxy: value typed %v is not an object handle", value.Type())
		}
		handle, err := translate(rawHandle)
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(handle), nil
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type()), nil
		}
		translated, err := translateObjectValue(value.Elem(), translate)
		if err != nil {
			return reflect.Value{}, err
		}
		result := reflect.New(value.Type()).Elem()
		result.Set(translated)
		return result, nil
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type()), nil
		}
		translated, err := translateObjectValue(value.Elem(), translate)
		if err != nil {
			return reflect.Value{}, err
		}
		result := reflect.New(value.Type().Elem())
		result.Elem().Set(translated)
		return result, nil
	case reflect.Struct:
		result := reflect.New(value.Type()).Elem()
		result.Set(value)
		for index := 0; index < value.NumField(); index++ {
			field := result.Field(index)
			if !field.CanSet() || !value.Type().Field(index).IsExported() {
				continue
			}
			translated, err := translateObjectValue(value.Field(index), translate)
			if err != nil {
				return reflect.Value{}, err
			}
			field.Set(translated)
		}
		return result, nil
	case reflect.Slice:
		if value.IsNil() || value.Type().Elem().Kind() == reflect.Uint8 {
			return value, nil
		}
		result := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for index := 0; index < value.Len(); index++ {
			translated, err := translateObjectValue(value.Index(index), translate)
			if err != nil {
				return reflect.Value{}, err
			}
			result.Index(index).Set(translated)
		}
		return result, nil
	case reflect.Array:
		result := reflect.New(value.Type()).Elem()
		for index := 0; index < value.Len(); index++ {
			translated, err := translateObjectValue(value.Index(index), translate)
			if err != nil {
				return reflect.Value{}, err
			}
			result.Index(index).Set(translated)
		}
		return result, nil
	case reflect.Map:
		if value.IsNil() {
			return value, nil
		}
		result := reflect.MakeMapWithSize(value.Type(), value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			key, err := translateObjectValue(iterator.Key(), translate)
			if err != nil {
				return reflect.Value{}, err
			}
			item, err := translateObjectValue(iterator.Value(), translate)
			if err != nil {
				return reflect.Value{}, err
			}
			result.SetMapIndex(key, item)
		}
		return result, nil
	default:
		return value, nil
	}
}

func (client *logicalClient) restrictFindTemplate(arguments []any) error {
	if client.authenticated() {
		return nil
	}
	for index, argument := range arguments {
		attributes, ok := argument.([]*raw.Attribute)
		if !ok {
			continue
		}
		for _, attribute := range attributes {
			if attribute == nil || attribute.Type != raw.CKA_PRIVATE {
				continue
			}
			private, valid := raw.Bool(attribute.Value)
			if valid && private {
				return client.authenticationRequiredError()
			}
			return nil
		}
		arguments[index] = append(attributes, raw.NewAttribute(raw.CKA_PRIVATE, false))
		return nil
	}
	return nil
}

func (client *logicalClient) authorizeTemplates(method string, arguments []any) error {
	if client.authenticated() {
		return nil
	}
	switch method {
	case "CreateObject", "CopyObject", "GenerateKey", "GenerateKeyPair", "UnwrapKey", "DeriveKey", "DecapsulateKey", "UnwrapKeyAuthenticated":
		for _, argument := range arguments {
			attributes, ok := argument.([]*raw.Attribute)
			if !ok {
				continue
			}
			if templatePrivate(attributes) {
				return client.authenticationRequiredError()
			}
		}
	}
	return nil
}

func templatePrivate(attributes []*raw.Attribute) bool {
	class := uint(0)
	for _, attribute := range attributes {
		if attribute == nil {
			continue
		}
		switch attribute.Type {
		case raw.CKA_PRIVATE:
			if private, ok := raw.Bool(attribute.Value); ok && private {
				return true
			}
		case raw.CKA_CLASS:
			class, _ = raw.ULong(attribute.Value)
		}
	}
	return class == raw.CKO_PRIVATE_KEY || class == raw.CKO_SECRET_KEY
}

func (client *logicalClient) virtualizeResults(
	ctx context.Context,
	target *brokerTarget,
	lease *pkcs11.RawSessionLease,
	session *virtualSession,
	method reflect.Method,
	values []any,
) ([]any, bool, []raw.ObjectHandle, error) {
	result := make([]any, len(values))
	var affine bool
	var created []raw.ObjectHandle
	for index, value := range values {
		translated, translatedAffine, handles, err := client.virtualizeValue(ctx, target, lease, session, reflect.ValueOf(value))
		if err != nil {
			return nil, false, created, err
		}
		if index >= method.Type.NumOut() {
			return nil, false, created, fmt.Errorf("pkcs11 proxy: %s returned too many values", method.Name)
		}
		result[index] = translated.Interface()
		affine = affine || translatedAffine
		created = append(created, handles...)
	}
	return result, affine, created, nil
}

func (client *logicalClient) virtualizeValue(ctx context.Context, target *brokerTarget, lease *pkcs11.RawSessionLease, session *virtualSession, value reflect.Value) (reflect.Value, bool, []raw.ObjectHandle, error) {
	if !value.IsValid() {
		return value, false, nil, nil
	}
	if value.Type() == objectHandleType {
		native, ok := reflect.TypeAssert[raw.ObjectHandle](value)
		if !ok {
			return value, false, nil, fmt.Errorf("pkcs11 proxy: value typed %v is not an object handle", value.Type())
		}
		if native == 0 {
			return value, false, nil, nil
		}
		var virtual raw.ObjectHandle
		var affine, created bool
		err := lease.Call(ctx, "proxy-wrap-object", func(module raw.Module, nativeSession raw.SessionHandle) error {
			var wrapErr error
			virtual, affine, created, wrapErr = client.wrapObject(module, nativeSession, target, lease, session, native)
			return wrapErr
		})
		if err != nil {
			return reflect.Value{}, false, nil, err
		}
		if created {
			return reflect.ValueOf(virtual), affine, []raw.ObjectHandle{virtual}, nil
		}
		return reflect.ValueOf(virtual), affine, nil, nil
	}
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return value, false, nil, nil
		}
		translated, affine, handles, err := client.virtualizeValue(ctx, target, lease, session, value.Elem())
		if err != nil {
			return reflect.Value{}, false, handles, err
		}
		result := reflect.New(value.Type().Elem())
		result.Elem().Set(translated)
		return result, affine, handles, nil
	case reflect.Interface:
		if value.IsNil() {
			return value, false, nil, nil
		}
		translated, affine, handles, err := client.virtualizeValue(ctx, target, lease, session, value.Elem())
		if err != nil {
			return reflect.Value{}, false, handles, err
		}
		result := reflect.New(value.Type()).Elem()
		result.Set(translated)
		return result, affine, handles, nil
	case reflect.Struct:
		result := reflect.New(value.Type()).Elem()
		result.Set(value)
		var affine bool
		var handles []raw.ObjectHandle
		for index := 0; index < value.NumField(); index++ {
			fieldInfo := value.Type().Field(index)
			if !fieldInfo.IsExported() || !result.Field(index).CanSet() {
				continue
			}
			translated, fieldAffine, fieldHandles, err := client.virtualizeValue(ctx, target, lease, session, value.Field(index))
			if err != nil {
				return reflect.Value{}, false, append(handles, fieldHandles...), err
			}
			result.Field(index).Set(translated)
			affine = affine || fieldAffine
			handles = append(handles, fieldHandles...)
		}
		return result, affine, handles, nil
	case reflect.Slice:
		if value.IsNil() || value.Type().Elem().Kind() == reflect.Uint8 {
			return value, false, nil, nil
		}
		result := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		var affine bool
		var handles []raw.ObjectHandle
		for index := 0; index < value.Len(); index++ {
			translated, itemAffine, itemHandles, err := client.virtualizeValue(ctx, target, lease, session, value.Index(index))
			if err != nil {
				return reflect.Value{}, false, append(handles, itemHandles...), err
			}
			result.Index(index).Set(translated)
			affine = affine || itemAffine
			handles = append(handles, itemHandles...)
		}
		return result, affine, handles, nil
	case reflect.Array:
		result := reflect.New(value.Type()).Elem()
		var affine bool
		var handles []raw.ObjectHandle
		for index := 0; index < value.Len(); index++ {
			translated, itemAffine, itemHandles, err := client.virtualizeValue(ctx, target, lease, session, value.Index(index))
			if err != nil {
				return reflect.Value{}, false, append(handles, itemHandles...), err
			}
			result.Index(index).Set(translated)
			affine = affine || itemAffine
			handles = append(handles, itemHandles...)
		}
		return result, affine, handles, nil
	default:
		return value, false, nil, nil
	}
}

func (client *logicalClient) syncMutableArguments(
	ctx context.Context,
	target *brokerTarget,
	lease *pkcs11.RawSessionLease,
	session *virtualSession,
	original, native []any,
) (bool, []raw.ObjectHandle, error) {
	var affine bool
	var handles []raw.ObjectHandle
	for index := range original {
		if index >= len(native) {
			break
		}
		switch destination := original[index].(type) {
		case []*raw.Mechanism:
			source, ok := native[index].([]*raw.Mechanism)
			if !ok {
				continue
			}
			for i := range destination {
				if i < len(source) && destination[i] != nil && source[i] != nil {
					copyParameterUpdate(destination[i].Parameter, source[i].Parameter)
				}
			}
		case *raw.AsyncData:
			source, ok := native[index].(*raw.AsyncData)
			if !ok || destination == nil || source == nil {
				continue
			}
			copied := *source
			copied.Value = append([]byte(nil), source.Value...)
			for _, pair := range []struct {
				native raw.ObjectHandle
				assign func(raw.ObjectHandle)
			}{
				{source.Object, func(value raw.ObjectHandle) { copied.Object = value }},
				{source.AdditionalObject, func(value raw.ObjectHandle) { copied.AdditionalObject = value }},
			} {
				if pair.native == 0 {
					continue
				}
				var virtual raw.ObjectHandle
				var itemAffine, created bool
				err := lease.Call(ctx, "proxy-wrap-async-object", func(module raw.Module, nativeSession raw.SessionHandle) error {
					var wrapErr error
					virtual, itemAffine, created, wrapErr = client.wrapObject(module, nativeSession, target, lease, session, pair.native)
					return wrapErr
				})
				if err != nil {
					return false, handles, err
				}
				pair.assign(virtual)
				if created {
					handles = append(handles, virtual)
				}
				affine = affine || itemAffine
			}
			*destination = copied
		default:
			// Message APIs pass typed parameter pointers through an `any` argument.
			// Copy provider-written fields such as generated GCM IVs back into the
			// caller-owned parameter without replacing unrelated pointer inputs.
			copyParameterUpdate(destination, native[index])
		}
	}
	_ = target
	return affine, handles, nil
}

func (client *logicalClient) applyPostCallObjectState(ctx context.Context, target *brokerTarget, lease *pkcs11.RawSessionLease, session *virtualSession, method string, original, native []any, values []any) (bool, error) {
	switch method {
	case "DestroyObject":
		if len(original) > 1 {
			if handle, ok := original[1].(raw.ObjectHandle); ok {
				owner := client.removeObject(session, handle)
				if owner == nil || owner == session {
					return false, session.releaseIfIdle(ctx, target)
				}
				// A foreign owner's lifetime read lock is held by objectBorrowSet
				// until this call returns; its close path performs the release.
				return false, nil
			}
		}
	case "SetAttributeValue":
		if len(original) > 1 {
			handle, ok := original[1].(raw.ObjectHandle)
			if !ok {
				return false, nil
			}
			nativeHandle, ok := native[1].(raw.ObjectHandle)
			if !ok {
				return false, nil
			}
			var becameAffine, becameStable bool
			err := lease.Call(ctx, "proxy-refresh-object", func(module raw.Module, nativeSession raw.SessionHandle) error {
				var refreshErr error
				becameAffine, becameStable, refreshErr = client.refreshObject(module, nativeSession, target, lease, session, handle, nativeHandle)
				return refreshErr
			})
			if err != nil {
				return false, err
			}
			if becameAffine {
				return true, nil
			}
			if becameStable {
				return false, session.releaseIfIdle(ctx, target)
			}
		}
	}
	_ = values
	return false, nil
}

var _ = errors.Is
