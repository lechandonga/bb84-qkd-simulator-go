// Package randutil 提供可复现的进程内确定性随机源。
//
// 模拟过程中所有“随机”行为（态制备、测量、抽样、置换等）都从该随机源
// 取数。随机源只由配置中的随机种子决定，不包含任何时间、协程 ID 等
// 环境因素，因此同一配置重复运行（即使存在并发）必然得到完全一致的结果。
package randutil

import (
	"math/rand/v2"
)

// RNG 是基于 PCG 的确定性随机数生成器。
type RNG struct {
	r *rand.Rand
}

// New 使用给定种子构造随机源。两个种子字都由同一个 seed 派生，
// 保证 seed -> 随机序列是一一确定的映射。
func New(seed uint64) *RNG {
	return &RNG{r: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
}

// Intn 返回 [0,n) 的伪随机整数。
func (g *RNG) Intn(n int) int {
	if n <= 0 {
		panic("randutil: Intn argument must be positive")
	}
	return int(g.r.Uint64() % uint64(n))
}

// Bit 返回一个伪随机比特 0/1。
func (g *RNG) Bit() byte {
	return byte(g.r.Uint64() & 1)
}

// Float64 返回 [0,1) 的伪随机浮点数，用于与概率阈值比较。
func (g *RNG) Float64() float64 {
	return g.r.Float64()
}

// Perm 返回 [0,n) 的一个确定性伪随机置换。
func (g *RNG) Perm(n int) []int {
	return g.r.Perm(n)
}

// Shuffle 原地打乱切片，打乱顺序由随机源决定。
func (g *RNG) Shuffle(n int, swap func(i, j int)) {
	g.r.Shuffle(n, swap)
}

// Uint64 返回一个伪随机 64 位无符号整数。
func (g *RNG) Uint64() uint64 {
	return g.r.Uint64()
}
