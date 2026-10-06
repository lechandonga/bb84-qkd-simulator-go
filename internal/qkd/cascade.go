package qkd

import "math"

// cascade 运行 CASCADE 风格信息和解。
// 双方在模拟的经典公共信道上只交换块奇偶；发现奇偶不一致时，
// 通过二分法定位并翻转 Bob 端的错误比特，再向历史轮次级联回溯。
// 返回：纠错后的两端比特、执行轮数、纠正比特数、泄露的奇偶比特数、
// 以及在限定轮数后仍不收敛时的中止错误。
func cascade(alice, bob []byte, cfg Config, qber float64, rnd *rng) (
	[]byte, []byte, int, int, int, error) {

	n := len(alice)
	if n == 0 {
		return alice, bob, 0, 0, 0, nil
	}

	leak := 0
	fixed := 0

	// 每轮一个排列视图：perm 为“排列位置 -> 原始下标”，
	// pos 为其逆映射；bound 为排列位置空间上的块边界。
	type view struct {
		perm  []int
		pos   []int
		bound []int
	}
	views := make([]view, 0, cfg.CascadePasses)

	// askParity 模拟经典信道上的一次“区间奇偶询问”，泄露 1 比特。
	askParity := func(pass, lo, hi int) (byte, byte) {
		v := views[pass]
		var pa, pb byte
		for t := lo; t < hi; t++ {
			idx := v.perm[t]
			pa ^= alice[idx]
			pb ^= bob[idx]
		}
		leak++
		return pa, pb
	}

	// findAndFix 在指定轮次的某个排列区间 [lo,hi) 内定位一个错误并翻转，
	// 定位采用奇偶二分，每步泄露 1 比特；随后向历史轮次级联回溯。
	var findAndFix func(pass, lo, hi int) bool
	findAndFix = func(pass, lo, hi int) bool {
		if hi-lo <= 0 {
			return false
		}
		pa, pb := askParity(pass, lo, hi)
		if pa == pb {
			return false
		}
		for hi-lo > 1 {
			mid := lo + (hi-lo)/2
			pa, pb = askParity(pass, lo, mid)
			if pa != pb {
				hi = mid
			} else {
				lo = mid
			}
		}
		idx := views[pass].perm[lo]
		bob[idx] ^= 1
		fixed++

		// 级联回溯：该比特翻转后，它在历史轮次所在块的奇偶必然改变，
		// 若历史块现在奇偶不一致，则其中还藏有另一个错误。
		for old := pass - 1; old >= 0; old-- {
			ov := views[old]
			p := ov.pos[idx]
			b := len(ov.bound) - 2
			for x := 0; x < len(ov.bound)-1; x++ {
				if ov.bound[x] <= p && p < ov.bound[x+1] {
					b = x
					break
				}
			}
			pa, pb := askParity(old, ov.bound[b], ov.bound[b+1])
			if pa != pb {
				findAndFix(old, ov.bound[b], ov.bound[b+1])
			}
		}
		return true
	}

	k := int(math.Ceil(0.73 / qber))
	if k < 2 {
		k = 2
	}
	if k > n {
		k = n
	}
	// CASCADE 经典调度：首轮块大小 k1≈0.73/q，后续轮次配合随机排列
	// 使用更大的块（2k1, 4k1, 8k1...），使奇偶询问总数保持在合理量级。
	k1 := k

	rounds := 0
	for pass := 0; pass < cfg.CascadePasses; pass++ {
		rounds = pass + 1

		// 确定性排列：首轮保持原序；后续轮次由种子洗牌。
		perm := make([]int, n)
		for i := range perm {
			perm[i] = i
		}
		if pass > 0 {
			for i := n - 1; i > 0; i-- {
				j := int(rnd.next() % uint64(i+1))
				perm[i], perm[j] = perm[j], perm[i]
			}
		}
		pos := make([]int, n)
		for location, idx := range perm {
			pos[idx] = location
		}

		bound := []int{0}
		for start := 0; start < n; start += k {
			end := start + k
			if end > n {
				end = n
			}
			bound = append(bound, end)
		}
		views = append(views, view{perm: perm, pos: pos, bound: bound})

		for b := 0; b < len(bound)-1; b++ {
			findAndFix(pass, bound[b], bound[b+1])
		}

		k = k1 * (1 << (pass + 1))
		if k > n {
			k = n
		}
	}

	// 终检：模拟经典信道上每 64 位一次的奇偶确认，仍有差异即判定纠错失败。
	var diffs int
	for i := range alice {
		if alice[i] != bob[i] {
			diffs++
		}
	}
	leak += (n + 63) / 64
	if diffs > 0 {
		return alice, bob, rounds, fixed, leak, ErrAbortedCorrectionFailed
	}
	return alice, bob, rounds, fixed, leak, nil
}
