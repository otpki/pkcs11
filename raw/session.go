package raw

import "sync"

// sessionHandleStore records the slot associated with handles opened through
// this Ctx. Cryptoki does not expose a reverse handle-to-slot enumeration, so
// this bookkeeping lets CloseAllSessions release retained mechanism state only
// for sessions that belong to the closed slot.
type sessionHandleStore struct {
	mu    sync.Mutex
	slots map[SessionHandle]SlotID
}

func (s *sessionHandleStore) add(handle SessionHandle, slot SlotID) {
	if handle == 0 {
		return
	}
	s.mu.Lock()
	if s.slots == nil {
		s.slots = make(map[SessionHandle]SlotID)
	}
	s.slots[handle] = slot
	s.mu.Unlock()
}

func (s *sessionHandleStore) remove(handle SessionHandle) {
	s.mu.Lock()
	delete(s.slots, handle)
	s.mu.Unlock()
}

func (s *sessionHandleStore) removeSlot(slot SlotID) []SessionHandle {
	s.mu.Lock()
	var handles []SessionHandle
	for handle, candidate := range s.slots {
		if candidate == slot {
			handles = append(handles, handle)
			delete(s.slots, handle)
		}
	}
	s.mu.Unlock()
	return handles
}

func (s *sessionHandleStore) clear() {
	s.mu.Lock()
	s.slots = nil
	s.mu.Unlock()
}

func (c *Ctx) InitPIN(session SessionHandle, pin []byte) error {
	arena := &nativeArena{}
	defer arena.close()
	pointer, err := nativeCopySecret(arena, pin)
	if err != nil {
		return err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionInitPIN, c.abi.ulongArgument(uint(session)), pointer, c.abi.ulongArgument(uint(len(pin)))))
}

func (c *Ctx) SetPIN(session SessionHandle, oldPIN, newPIN []byte) error {
	arena := &nativeArena{}
	defer arena.close()
	oldPointer, err := nativeCopySecret(arena, oldPIN)
	if err != nil {
		return err
	}
	newPointer, err := nativeCopySecret(arena, newPIN)
	if err != nil {
		return err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionSetPIN,
		c.abi.ulongArgument(uint(session)),
		oldPointer, c.abi.ulongArgument(uint(len(oldPIN))),
		newPointer, c.abi.ulongArgument(uint(len(newPIN)))))
}

// OpenSession opens a session without application data or a notification
// callback. Passing nil for both avoids native-to-Go callback lifetime issues.
func (c *Ctx) OpenSession(slot SlotID, flags uint) (SessionHandle, error) {
	_, unlock, err := c.locked()
	if err != nil {
		return 0, err
	}
	defer unlock()
	arena := &nativeArena{}
	defer arena.close()
	pointer, value, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return 0, err
	}
	if err := rv(c.call(functionOpenSession,
		c.abi.ulongArgument(uint(slot)), c.abi.ulongArgument(flags), 0, 0, pointer)); err != nil {
		return 0, err
	}
	handle := SessionHandle(c.abi.getULong(value, 0))
	c.sessions.add(handle, slot)
	return handle, nil
}

func (c *Ctx) CloseSession(session SessionHandle) error {
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	callErr := rv(c.call(functionCloseSession, c.abi.ulongArgument(uint(session))))
	unlock()
	if callErr == nil || IsError(callErr, CKR_SESSION_HANDLE_INVALID) || IsError(callErr, CKR_SESSION_CLOSED) {
		c.releaseSessionMechanisms(session)
		c.sessions.remove(session)
	}
	return callErr
}

func (c *Ctx) CloseAllSessions(slot SlotID) error {
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	callErr := rv(c.call(functionCloseAllSessions, c.abi.ulongArgument(uint(slot))))
	unlock()
	if callErr == nil {
		for _, session := range c.sessions.removeSlot(slot) {
			c.releaseSessionMechanisms(session)
		}
	}
	return callErr
}

type sessionInfoLayout struct{ slot, state, flags, deviceError, size int }

func nativeSessionInfoLayout(abi NativeABI) sessionInfoLayout {
	builder := newNativeLayoutBuilder(abi)
	layout := sessionInfoLayout{
		slot:        builder.addULong(),
		state:       builder.addULong(),
		flags:       builder.addULong(),
		deviceError: builder.addULong(),
	}
	layout.size = builder.size()
	return layout
}

func (c *Ctx) GetSessionInfo(session SessionHandle) (SessionInfo, error) {
	_, unlock, err := c.locked()
	if err != nil {
		return SessionInfo{}, err
	}
	defer unlock()
	layout := nativeSessionInfoLayout(c.abi)
	arena := &nativeArena{}
	defer arena.close()
	pointer, value, err := arena.alloc(layout.size)
	if err != nil {
		return SessionInfo{}, err
	}
	if err := rv(c.call(functionGetSessionInfo, c.abi.ulongArgument(uint(session)), pointer)); err != nil {
		return SessionInfo{}, err
	}
	return SessionInfo{
		SlotID:      SlotID(c.abi.getULong(value, layout.slot)),
		State:       State(c.abi.getULong(value, layout.state)),
		Flags:       c.abi.getULong(value, layout.flags),
		DeviceError: c.abi.getULong(value, layout.deviceError),
	}, nil
}

func (c *Ctx) GetOperationState(session SessionHandle) ([]byte, error) {
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.callOutput(func(output, length uintptr) uint {
		return c.call(functionGetOperationState, c.abi.ulongArgument(uint(session)), output, length)
	})
}

func (c *Ctx) SetOperationState(session SessionHandle, state []byte, encryptionKey, authenticationKey ObjectHandle) error {
	arena := &nativeArena{}
	defer arena.close()
	pointer, err := nativeCopy(arena, state)
	if err != nil {
		return err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	callErr := rv(c.call(functionSetOperationState,
		c.abi.ulongArgument(uint(session)), pointer, c.abi.ulongArgument(uint(len(state))),
		c.abi.ulongArgument(uint(encryptionKey)), c.abi.ulongArgument(uint(authenticationKey))))
	unlock()
	if callErr == nil {
		// The restored native operation state is self-contained. Any retained
		// mechanism images from the previous state no longer belong to it.
		c.releaseSessionMechanisms(session)
	}
	return callErr
}

func (c *Ctx) Login(session SessionHandle, userType uint, pin []byte) error {
	arena := &nativeArena{}
	defer arena.close()
	pointer, err := nativeCopySecret(arena, pin)
	if err != nil {
		return err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionLogin,
		c.abi.ulongArgument(uint(session)), c.abi.ulongArgument(userType), pointer, c.abi.ulongArgument(uint(len(pin)))))
}

func (c *Ctx) LoginUser(session SessionHandle, userType uint, pin []byte, username string) error {
	arena := &nativeArena{}
	defer arena.close()
	pinPointer, err := nativeCopySecret(arena, pin)
	if err != nil {
		return err
	}
	usernamePointer, err := nativeCopy(arena, []byte(username))
	if err != nil {
		return err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionLoginUser,
		c.abi.ulongArgument(uint(session)), c.abi.ulongArgument(userType),
		pinPointer, c.abi.ulongArgument(uint(len(pin))),
		usernamePointer, c.abi.ulongArgument(uint(len(username)))))
}

func (c *Ctx) Logout(session SessionHandle) error {
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionLogout, c.abi.ulongArgument(uint(session))))
}

func (c *Ctx) SessionCancel(session SessionHandle, flags uint) error {
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	callErr := rv(c.call(functionSessionCancel, c.abi.ulongArgument(uint(session)), c.abi.ulongArgument(flags)))
	unlock()
	if callErr == nil {
		// C_SessionCancel can cancel a subset of the independently active
		// operation classes. Preserve retained parameter graphs for every class
		// that the caller did not select.
		c.releaseSessionMechanismsByFlags(session, flags)
	}
	return callErr
}

func (c *Ctx) GetFunctionStatus(session SessionHandle) error {
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionGetFunctionStatus, c.abi.ulongArgument(uint(session))))
}

func (c *Ctx) CancelFunction(session SessionHandle) error {
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	callErr := rv(c.call(functionCancelFunction, c.abi.ulongArgument(uint(session))))
	unlock()
	if callErr == nil {
		c.releaseSessionMechanisms(session)
	}
	return callErr
}

func (c *Ctx) WaitForSlotEvent(flags uint) (SlotID, error) {
	_, unlock, err := c.locked()
	if err != nil {
		return 0, err
	}
	defer unlock()
	arena := &nativeArena{}
	defer arena.close()
	pointer, value, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return 0, err
	}
	if err := rv(c.call(functionWaitForSlotEvent, c.abi.ulongArgument(flags), pointer, 0)); err != nil {
		return 0, err
	}
	return SlotID(c.abi.getULong(value, 0)), nil
}
