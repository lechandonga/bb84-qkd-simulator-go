package qkd

// rng 是一个带种子的确定性随机源。
// 整个模拟过程严格串行地使用同一个 rng（信道顺序即光子发送顺序），
// 因此同一 Seed + 配置重复运行必然产生逐位一致的结果，
// 不受 goroutine 调度等执行顺序因素影响。
type rng struct {
	state uint64
}

func newRNG(seed int64) *rng {
	s := uint64(seed)
	if s == 0 {
		s = 0x9e3779b97f4a7c15
	}
	return &rng{state: s}
}

// next 返回 [0, 2^64) 内的伪随机数（SplitMix64）。
func (r *rng) next() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// chance 在概率 p（0..1）成立时返回 true。
func (r *rng) chance(p float64) bool {
	if p <= 0 {
		return false
	}
	if p >= 1 {
		return true
	}
	return float64(r.next()>>11)/float64(uint64(1)<<53) < p
}

// bit 返回一个均匀随机比特。
func (r *rng) bit() byte {
	return byte(r.next() & 1)
}
