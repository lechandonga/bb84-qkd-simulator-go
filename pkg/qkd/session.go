// Package qkd 在 BB84 协议引擎之上提供会话安全判定与密钥生命周期管理。
//
// 一个 Session 对应一次完整协商：成功时向密钥库登记一份带状态的共享密钥；
// 中止时记录可区分的中止原因，且不登记任何密钥材料。
// KeyStore 以互斥保护保证“同一份密钥只能被成功消费一次”，对并发申请成立。
package qkd

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/lechandonga/bb84-qkd-simulator-go/pkg/bb84"
)

// Status 是会话的最终状态。
type Status string

const (
	// StatusSuccess 表示协商成功并产出共享密钥。
	StatusSuccess Status = "success"
	// StatusAborted 表示协商在某一安全检查处被中止。
	StatusAborted Status = "aborted"
)

// Session 记录一次 QKD 协商的结果快照（密钥本身保存在密钥库中）。
type Session struct {
	ID          string
	Status      Status
	AbortReason bb84.AbortReason
	AbortError  string
	KeyID       string
	KeyBitLen   int
	Stats       bb84.Stats
}

// Manager 编排“执行协商 -> 登记/中止”的过程，并持有密钥库。
type Manager struct {
	store *KeyStore
}

// NewManager 创建会话管理器。
func NewManager(store *KeyStore) *Manager {
	if store == nil {
		store = NewKeyStore()
	}
	return &Manager{store: store}
}

// Store 返回管理器绑定的密钥库。
func (m *Manager) Store() *KeyStore { return m.store }

// Run 执行一次协商。协商成功时密钥以“可用”状态登记入库；
// 中止时登记一条中止会话记录，且密钥库中不存在任何关联密钥材料。
// sessionID 用于业务侧追踪；同一 sessionID 重复登记会返回错误。
func (m *Manager) Run(sessionID string, cfg bb84.Config) (*Session, error) {
	if _, ok := m.store.sessions[sessionID]; ok {
		return nil, &StoreError{Code: ErrSessionExists, Msg: "会话标识已存在：" + sessionID}
	}

	engine, err := bb84.NewEngine(cfg)
	if err != nil {
		return nil, err
	}
	res, err := engine.Run()

	sess := &Session{ID: sessionID, Stats: res.Stats}
	if err != nil || !res.Success {
		sess.Status = StatusAborted
		if res.Abort != nil {
			sess.AbortReason = res.Abort.Reason
			sess.AbortError = res.Abort.Error()
		}
		m.store.markAborted(sess)
		return sess, err
	}

	keyID := deriveKeyID(sessionID, res.KeyIDSeed, res.Stats.FinalKeyBits)
	material := &KeyMaterial{
		ID:        keyID,
		SessionID: sessionID,
		BitLen:    res.Stats.FinalKeyBits,
		Key:       append([]byte(nil), res.Key...),
		Status:    KeyAvailable,
	}
	if err := m.store.register(sess, material); err != nil {
		return nil, err
	}
	sess.Status = StatusSuccess
	sess.KeyID = keyID
	sess.KeyBitLen = material.BitLen
	return sess, nil
}

// deriveKeyID 由确定量（会话标识、协商种子、最终密钥比特长度）派生密钥标识。
// 它不依赖任何随机或环境状态，因此两端各自执行同一协商会得到同一密钥标识
// 与同一密钥长度，重复或乱序申请也不会造成标识错配。
func deriveKeyID(sessionID string, seed uint64, bitLen int) string {
	h := sha256.New()
	h.Write([]byte("bb84-key-id-v1"))
	h.Write([]byte(sessionID))
	var buf [8]byte
	for i := 0; i < 8; i++ {
		buf[i] = byte(seed >> (8 * i))
	}
	h.Write(buf[:])
	var l [8]byte
	for i := 0; i < 8; i++ {
		l[i] = byte(bitLen >> (8 * i))
	}
	h.Write(l[:])
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}
