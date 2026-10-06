package qkd

import "math"

// binaryEntropy 返回二元熵函数 H2(p) = -p log2 p - (1-p) log2(1-p)。
func binaryEntropy(p float64) float64 {
	if p <= 0 || p >= 1 {
		return 0
	}
	return -p*math.Log2(p) - (1-p)*math.Log2(1-p)
}

// toeplitzMultiply 使用 Toeplitz 矩阵把 in 压缩为 outLen 比特。
// Toeplitz 矩阵由 (outLen + inLen - 1) 个确定性系数完全描述，
// 系数由 seed 生成；输出的每一比特是输入比特与矩阵某一行的 GF(2) 内积。
// 该实现既是通用剩余类提取器（隐私放大），也保证相同输入可复现。
func toeplitzMultiply(in []byte, outLen, inLen int, seed int64) []byte {
	coef := newRNG(seed ^ 0x517cc1b727220a95)
	words := (inLen + 63) / 64
	cols := make([]uint64, words)
	for i := 0; i < inLen; i++ {
		if in[i] == 1 {
			cols[i>>6] |= 1 << uint(i&63)
		}
	}

	diag := outLen + inLen - 1
	stream := make([]uint64, (diag+63)/64)
	for i := range stream {
		stream[i] = coef.next()
	}
	coefBit := func(k int) byte { return byte((stream[k>>6] >> uint(k&63)) & 1) }

	out := make([]byte, outLen)
	rowWords := words
	row := make([]uint64, rowWords)
	for i := 0; i < outLen; i++ {
		for w := 0; w < rowWords; w++ {
			row[w] = 0
		}
		base := outLen - 1 - i
		for j := 0; j < inLen; j++ {
			if coefBit(base+j) == 1 {
				row[j>>6] |= 1 << uint(j&63)
			}
		}
		var parity uint64
		for w := 0; w < rowWords; w++ {
			x := row[w] & cols[w]
			parity ^= x
		}
		parity ^= parity >> 32
		parity ^= parity >> 16
		parity ^= parity >> 8
		parity ^= parity >> 4
		parity ^= parity >> 2
		parity ^= parity >> 1
		out[i] = byte(parity & 1)
	}
	return out
}
