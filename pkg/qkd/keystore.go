package qkd

import "sync"

// KeyStatus 是密钥材料的生命周期状态。
type KeyStatus string

const (
	// KeyAvailable 可被申请/消费。
	KeyAvailable KeyStatus = "available"
	// KeyConsumed 已被唯一一次消费取走，不得再次发放。
	KeyConsumed KeyStatus = "consumed"
	// KeyRevoked 已被管理方主动作废，不得发放。
	KeyRevoked KeyStatus = "revoked"
	// KeyAborted 标记中止会话；中止会话不持有任何密钥材料。
	KeyAborted KeyStatus = "aborted"
)

// 消费/查询被拒绝时的可区分原因。
const (
	ErrKeyNotFound     = "key_not_found"
	ErrAlreadyConsumed = "already_consumed"
	ErrKeyRevoked      = "key_revoked"
	ErrSessionAborted  = "session_aborted"
	ErrSessionExists   = "session_exists"
)

// StoreError 携带机器可读的拒绝原因 Code 与人类可读说明 Msg。
type StoreError struct {
	Code string
	Msg  string
}

func (e *StoreError) Error() string { return "qkd: " + e.Msg }

// KeyMaterial 是一份带生命周期状态的共享密钥。
type KeyMaterial struct {
	ID        string
	SessionID string
	BitLen    int
	Key       []byte
	Status    KeyStatus
}

// KeyStore 是进程内、并发安全的会话与密钥注册表。
type KeyStore struct {
	mu       sync.Mutex
	keys     map[string]*KeyMaterial
	sessions map[string]*Session
}

// NewKeyStore 创建空密钥库。
func NewKeyStore() *KeyStore {
	return &KeyStore{keys: map[string]*KeyMaterial{}, sessions: map[string]*Session{}}
}

// register 在锁内登记一次成功协商的会话与密钥。
func (s *KeyStore) register(sess *Session, km *KeyMaterial) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[sess.ID]; ok {
		return &StoreError{Code: ErrSessionExists, Msg: "会话标识已存在：" + sess.ID}
	}
	if _, ok := s.keys[km.ID]; ok {
		return &StoreError{Code: ErrSessionExists, Msg: "密钥标识冲突：" + km.ID}
	}
	s.sessions[sess.ID] = sess
	s.keys[km.ID] = km
	return nil
}

// markAborted 在锁内登记中止会话，不创建任何密钥材料。
func (s *KeyStore) markAborted(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
}

// Consume 原子地申请并取走一份密钥：
// available -> consumed 且返回密钥字节；对已消费/已作废/不存在/中止会话
// 的申请分别返回可区分原因。并发调用同一份密钥时恰好一个请求成功。
func (s *KeyStore) Consume(keyID string) ([]byte, *KeyMaterial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	km, ok := s.keys[keyID]
	if !ok {
		// 可能是调用方误用了中止会话的标识。
		return nil, nil, &StoreError{Code: ErrKeyNotFound, Msg: "密钥不存在：" + keyID}
	}
	switch km.Status {
	case KeyConsumed:
		return nil, km, &StoreError{Code: ErrAlreadyConsumed, Msg: "密钥已被消费，不得重复发放：" + keyID}
	case KeyRevoked:
		return nil, km, &StoreError{Code: ErrKeyRevoked, Msg: "密钥已作废：" + keyID}
	case KeyAvailable:
		km.Status = KeyConsumed
		out := append([]byte(nil), km.Key...)
		mat := *km
		return out, &mat, nil
	default:
		return nil, km, &StoreError{Code: ErrSessionAborted, Msg: "密钥所在会话已中止：" + keyID}
	}
}

// Revoke 将一份可用密钥作废（available/revoked 幂等）；
// 已消费密钥不可作废，返回 ErrAlreadyConsumed。
func (s *KeyStore) Revoke(keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	km, ok := s.keys[keyID]
	if !ok {
		return &StoreError{Code: ErrKeyNotFound, Msg: "密钥不存在：" + keyID}
	}
	switch km.Status {
	case KeyConsumed:
		return &StoreError{Code: ErrAlreadyConsumed, Msg: "密钥已被消费，不能作废：" + keyID}
	case KeyAvailable:
		km.Status = KeyRevoked
	}
	return nil
}

// Lookup 返回密钥元数据的拷贝（不含密钥字节），用于状态追踪。
func (s *KeyStore) Lookup(keyID string) (*KeyMaterial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	km, ok := s.keys[keyID]
	if !ok {
		return nil, &StoreError{Code: ErrKeyNotFound, Msg: "密钥不存在：" + keyID}
	}
	cp := *km
	cp.Key = nil
	return &cp, nil
}

// Session 返回会话记录拷贝。
func (s *KeyStore) Session(sessionID string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, &StoreError{Code: ErrKeyNotFound, Msg: "会话不存在：" + sessionID}
	}
	cp := *sess
	return &cp, nil
}

// Sessions 返回全部会话记录的快照（乱序/重复调用均不影响内部状态）。
func (s *KeyStore) Sessions() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, *sess)
	}
	return out
}
