package qkd

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Stats 记录一次协商各阶段的可观测数据。
type Stats struct {
	Sent             int     `json:"sent"`
	Lost             int     `json:"lost"`
	Received         int     `json:"received"`
	BasisMatched     int     `json:"basis_matched"`
	SiftedBits       int     `json:"sifted_bits"`
	SampleBits       int     `json:"sample_bits"`
	SampleErrors     int     `json:"sample_errors"`
	EstimatedQBER    float64 `json:"estimated_qber"`
	CorrectedBits    int     `json:"corrected_bits"`
	CorrectionRounds int     `json:"correction_rounds"`
	ReconciledBits   int     `json:"reconciled_bits"`
	FinalKeyBits     int     `json:"final_key_bits"`
}

// KeyMaterial 是一次成功协商产出的共享密钥。
// Alice 与 Bob 两端得到的 ID、长度、内容完全一致。
type KeyMaterial struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Bits      []byte `json:"-"`
	Length    int    `json:"length"`
}

// Result 是一次协商的结果。AbortErr == nil 表示成功成钥。
type Result struct {
	SessionID   string       `json:"session_id"`
	Config      Config       `json:"config"`
	Stats       Stats        `json:"stats"`
	Key         *KeyMaterial `json:"key,omitempty"`
	AbortReason AbortReason  `json:"abort_reason,omitempty"`
	AbortErr    error        `json:"-"`
}

// Succeeded 报告会话是否成功产出密钥。
func (r *Result) Succeeded() bool { return r.AbortErr == nil }

// deriveKeyID 完全由密钥内容与种子决定，因此两端独立计算也必然相同，
// 且对重复/乱序申请保持稳定。
func deriveKeyID(seed int64, bits []byte, length int) string {
	h := sha256.New()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(seed))
	h.Write(buf[:])
	h.Write(bits)
	binary.LittleEndian.PutUint64(buf[:], uint64(length))
	h.Write(buf[:])
	return fmt.Sprintf("key-%s", hex.EncodeToString(h.Sum(nil))[:16])
}
