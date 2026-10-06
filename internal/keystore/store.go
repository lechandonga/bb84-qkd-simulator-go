// Package keystore 管理 BB84 协商产出密钥的生命周期与消费语义。
package keystore

import (
	"errors"
	"fmt"
	"sync"

	"github.com/lechandonga/bb84-qkd-simulator-go/internal/qkd"
)

// State 为密钥的可追踪状态。
type State string

const (
	// StateAvailable 可用：协商成功，等待被申请消费。
	StateAvailable State = "available"
	// StateConsumed 已消费：已被唯一一次成功申请取走，不可重复发放。
	StateConsumed State = "consumed"
	// StateRevoked 已作废：被管理方主动作废（例如会话审计失败）。
	StateRevoked State = "revoked"
	// StateAborted 中止：对应会话被安全判定中止，不含任何可用密钥材料。
	StateAborted State = "aborted"
)

// 申请/管理密钥时可能返回的可区分错误。
var (
	ErrKeyNotFound    = errors.New("keystore: key id not found")
	ErrKeyAlreadyUsed = errors.New("keystore: key already consumed")
	ErrKeyRevoked     = errors.New("keystore: key has been revoked")
	ErrKeyAborted     = errors.New("keystore: session aborted, no key material available")
	ErrKeyDuplicate   = errors.New("keystore: key id already registered")
)

// Entry 是仓库内一条密钥记录。
type Entry struct {
	ID        string
	SessionID string
	Length    int
	State     State
	bits      []byte
}

// Store 是线程安全的本地密钥仓库；Alice 与 Bob 可各持一个，
// 由于 KeyMaterial 的 ID/长度/内容由协商结果确定，两端记录天然一致。
type Store struct {
	mu      sync.Mutex
	entries map[string]*Entry
	order   []string
}

// New 创建空仓库。
func New() *Store {
	return &Store{entries: make(map[string]*Entry)}
}

// Put 把一次成功协商的密钥材料登记为“可用”。
// 重复登记同一 ID 返回 ErrKeyDuplicate，避免覆盖造成错配。
func (s *Store) Put(k *qkd.KeyMaterial) error {
	if k == nil {
		return fmt.Errorf("keystore: nil key material")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[k.ID]; ok {
		return ErrKeyDuplicate
	}
	bits := make([]byte, len(k.Bits))
	copy(bits, k.Bits)
	s.entries[k.ID] = &Entry{
		ID:        k.ID,
		SessionID: k.SessionID,
		Length:    k.Length,
		State:     StateAvailable,
		bits:      bits,
	}
	s.order = append(s.order, k.ID)
	return nil
}

// PutAborted 登记一个被中止的会话；其记录永久为“中止”状态，
// 任何申请都返回 ErrKeyAborted，确保中止会话不产出可用材料。
func (s *Store) PutAborted(sessionID string, reason qkd.AbortReason) error {
	id := "aborted:" + sessionID
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[id]; ok {
		return ErrKeyDuplicate
	}
	s.entries[id] = &Entry{
		ID:        id,
		SessionID: sessionID,
		State:     StateAborted,
	}
	s.order = append(s.order, id)
	return nil
}

// ConsumeResult 是一次成功申请返回的内容。
type ConsumeResult struct {
	ID     string
	Length int
	Bits   []byte
}

// Consume 申请并消费一份密钥。
// 该操作是原子的：并发申请同一 ID 时恰好一个请求成功，
// 其余请求根据当前状态得到 ErrKeyAlreadyUsed / ErrKeyRevoked / ErrKeyAborted。
// 重复或乱序申请不会改变或错配任何密钥内容。
func (s *Store) Consume(id string) (*ConsumeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	switch e.State {
	case StateConsumed:
		return nil, ErrKeyAlreadyUsed
	case StateRevoked:
		return nil, ErrKeyRevoked
	case StateAborted:
		return nil, ErrKeyAborted
	}
	e.State = StateConsumed
	bits := make([]byte, len(e.bits))
	copy(bits, e.bits)
	return &ConsumeResult{ID: e.ID, Length: e.Length, Bits: bits}, nil
}

// Revoke 将一份可用密钥作废；已消费/已作废/中止的记录状态保持不变。
func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return ErrKeyNotFound
	}
	if e.State == StateAvailable {
		e.State = StateRevoked
	}
	return nil
}

// Status 查询密钥状态；未知 ID 返回 ErrKeyNotFound。
func (s *Store) Status(id string) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return "", ErrKeyNotFound
	}
	return e.State, nil
}

// Entry 返回某条记录的快照（不含密钥比特）。
func (s *Store) Entry(id string) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	cp := *e
	cp.bits = nil
	return &cp, nil
}

// List 按登记顺序返回全部记录快照。
func (s *Store) List() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, 0, len(s.order))
	for _, id := range s.order {
		e := s.entries[id]
		cp := *e
		cp.bits = nil
		out = append(out, cp)
	}
	return out
}
