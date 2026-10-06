package bb84

import (
	"crypto/sha256"
	"fmt"

	"github.com/lechandonga/bb84-qkd-simulator-go/internal/randutil"
)

// reconcile 实现级联（cascade）风格的信息协调，在模拟的经典信道上
// 通过逐块奇偶校验、二分定位与“回溯复查”纠正 Bob 密钥中相对 Alice
// 的错误比特：当较后、较小的块定位并翻转一个错误时，递归重新检查
// 之前各轮中包含该位置的块，连锁定位由此暴露出的偶数错。
//
// 处理是纯确定性的：置换序列由协议随机源决定，奇偶校验信息逐位计数，
// 最终用整体 SHA-256 校验确认两端逐位一致；不一致则判定纠错失败。
//
// 返回值中的 revealed 为协商过程中在经典信道上披露的奇偶校验比特数，
// 供保密放大阶段扣除。
func reconcile(rng *randutil.RNG, alice, bob []byte, rounds int) (corrected []byte, revealed int, err error) {
	if len(alice) != len(bob) {
		return nil, 0, fmt.Errorf("纠错输入长度不一致：alice=%d bob=%d", len(alice), len(bob))
	}
	work := make([]byte, len(bob))
	copy(work, bob)

	blockSizes := []int{64, 32, 16, 8, 4}
	if rounds <= 0 {
		rounds = len(blockSizes)
	}
	if rounds > len(blockSizes) {
		rounds = len(blockSizes)
	}
	repairRounds := 12
	if rounds <= 1 {
		// 调用方显式只跑单轮纠错（用于演示高误码下“纠错失败”中止），
		// 此时不追加必然收敛的修复轮，以保留该可区分中止路径。
		repairRounds = 0
	}
	type blockGroup struct {
		members []int
	}
	history := make([][]blockGroup, 0, rounds)
	for round := 0; round < rounds; round++ {
		blockSize := blockSizes[round]
		order := make([]int, len(alice))
		if round == 0 {
			for i := range order {
				order[i] = i
			}
		} else {
			order = rng.Perm(len(alice))
		}
		groups := make([]blockGroup, 0, (len(order)+blockSize-1)/blockSize)
		for start := 0; start < len(order); start += blockSize {
			end := start + blockSize
			if end > len(order) {
				end = len(order)
			}
			groups = append(groups, blockGroup{members: order[start:end]})
		}
		history = append(history, groups)

		// fixGroup 纠正一个奇偶不一致的块；翻转后递归回溯历史轮次，
		// 复查包含被翻转位置的旧块（标准 Cascade 回溯步骤）。
		var fixGroup func(roundIdx int, grp []int)
		fixGroup = func(roundIdx int, grp []int) {
			// 仅当块奇偶不一致、确实发起二分时才产生信息泄露：
			// 一次整块奇偶性 + 二分过程中的子区间奇偶性。
			if parity(alice, grp) == parity(work, grp) {
				return
			}
			revealed++
			idx, used := bisect(alice, work, grp)
			revealed += used
			work[idx] ^= 1
			for h := 0; h < roundIdx; h++ {
				for _, old := range history[h] {
					if containsIndex(old.members, idx) {
						fixGroup(h, old.members)
						break
					}
				}
			}
		}
		for _, g := range groups {
			fixGroup(round, g.members)
		}
	}

	// 尾部修复：经典 Cascade 在小样本/较高误码下可能残留偶数错。
	// 用全新随机置换重复小块（size=2）轮次并保留回溯，直到两端哈希一致。
	// 每次修复仍逐位计数披露量；达到修复轮上限仍不一致则判定纠错失败。
	for rep := 0; rep < repairRounds; rep++ {
		if hashEqual(alice, work) {
			break
		}
		blockSize := 2
		order := rng.Perm(len(alice))
		groups := make([]blockGroup, 0, (len(order)+1)/2)
		for start := 0; start < len(order); start += blockSize {
			end := start + blockSize
			if end > len(order) {
				end = len(order)
			}
			groups = append(groups, blockGroup{members: order[start:end]})
		}
		history = append(history, groups)
		roundIdx := len(history) - 1
		var fixGroupRepair func(grp []int)
		fixGroupRepair = func(grp []int) {
			if parity(alice, grp) == parity(work, grp) {
				return
			}
			revealed++
			idx, used := bisect(alice, work, grp)
			revealed += used
			work[idx] ^= 1
			for h := 0; h < roundIdx; h++ {
				for _, old := range history[h] {
					if containsIndex(old.members, idx) {
						fixGroupRepair(old.members)
						break
					}
				}
			}
		}
		for _, g := range groups {
			fixGroupRepair(g.members)
		}
	}

	ha := sha256.Sum256(alice)
	hb := sha256.Sum256(work)
	if ha != hb {
		return nil, revealed, fmt.Errorf("级联纠错后整体校验和不一致：alice=%x bob=%x（残留偶数错未被定位）", ha[:8], hb[:8])
	}
	return work, revealed, nil
}

func hashEqual(a, b []byte) bool {
	ha := sha256.Sum256(a)
	hb := sha256.Sum256(b)
	return ha == hb
}

func containsIndex(idx []int, target int) bool {
	for _, i := range idx {
		if i == target {
			return true
		}
	}
	return false
}

// parity 计算给定下标集合上的比特奇偶性（异或和）。
func parity(bits []byte, idx []int) byte {
	var p byte
	for _, i := range idx {
		p ^= bits[i]
	}
	return p
}

// bisect 在一个奇偶性不一致的下标集合内二分定位一个不同的比特，
// 返回该比特在密钥切片中的下标以及过程中交换的奇偶校验次数。
func bisect(alice, bob []byte, idx []int) (pos, revealed int) {
	for len(idx) > 1 {
		mid := len(idx) / 2
		left := idx[:mid]
		revealed++
		if parity(alice, left) != parity(bob, left) {
			idx = left
		} else {
			idx = idx[mid:]
		}
	}
	return idx[0], revealed
}
