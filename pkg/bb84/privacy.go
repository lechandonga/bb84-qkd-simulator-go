package bb84

import (
	"crypto/sha256"
	"encoding/binary"
)

// privacyAmplify 执行保密放大，把纠错后的 n 比特密钥压缩为 finalBits 比特。
//
// 采用通用哈希族（线性通用哈希）：每个输出比特是输入比特在一个随机掩码
// 下的奇偶内积，掩码流由 (域分隔标签, paSeed) 的 SHA-256 哈希扩展生成。
// paSeed 模拟双方在经典信道上公开约定的哈希族参数，因此两端输入相同时
// 输出必然相同；任何掌握部分输入信息的窃听者都无法预测压缩后的比特。
func privacyAmplify(corrected []byte, finalBits int, paSeed uint64) []byte {
	n := len(corrected)
	var label [8]byte
	binary.LittleEndian.PutUint64(label[:], paSeed)

	stream := newMaskStream(label[:])
	out := make([]byte, (finalBits+7)/8)
	for j := 0; j < finalBits; j++ {
		var bit byte
		for i := 0; i < n; i++ {
			if stream.bit() == 1 {
				bit ^= corrected[i]
			}
		}
		out[j/8] |= bit << (j % 8)
	}
	return out
}

// maskStream 由 SHA-256 计数器模式扩展出任意长的确定性掩码流。
type maskStream struct {
	seed  []byte
	buf   []byte
	pos   int
	count uint64
}

func newMaskStream(seed []byte) *maskStream {
	return &maskStream{seed: seed}
}

func (m *maskStream) refill() {
	var ctr [8]byte
	binary.LittleEndian.PutUint64(ctr[:], m.count)
	h := sha256.New()
	h.Write([]byte("bb84-pa-mask-v1"))
	h.Write(m.seed)
	h.Write(ctr[:])
	m.buf = h.Sum(nil)
	m.count++
	m.pos = 0
}

func (m *maskStream) bit() byte {
	if m.pos >= len(m.buf)*8 {
		m.refill()
	}
	b := (m.buf[m.pos/8] >> (m.pos % 8)) & 1
	m.pos++
	return b
}
