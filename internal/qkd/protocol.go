package qkd

import (
	"fmt"
	"math"
)

type measured struct {
	aliceBit byte
	basis    byte
	bobBasis byte
	bobBit   byte
}

// Run 执行一次完整的进程内 BB84 模拟。
// 全程串行推进（态制备→信道→测量→基矢比对→筛选→抽样→纠错→保密放大），
// 随机性只来自 Config.Seed，因此结果确定且可复现。
func Run(cfg Config) (*Result, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	res := &Result{
		SessionID: fmt.Sprintf("sess-%d-%08x", cfg.Seed, cfg.PhotonCount),
		Config:    cfg,
	}
	st := &res.Stats
	rnd := newRNG(cfg.Seed)

	// —— 阶段 1/2：Alice 制备量子态，光子依次经过信道，Bob 测量 ——
	var records []measured
	st.Sent = cfg.PhotonCount

	for i := 0; i < cfg.PhotonCount; i++ {
		bit := rnd.bit()
		basis := rnd.bit()

		// Bob 在光子到达前独立选择测量基。
		bobBasis := rnd.bit()

		// 信道：丢包最先判定，丢失的光子不会产生任何记录。
		if rnd.chance(cfg.LossRate) {
			st.Lost++
			continue
		}

		// 信道：Eve 拦截-测量-重发。Eve 选错基时，
		// 重发态在 Bob 基正确的情况下仍有 50% 概率出错。
		arrivingBit := bit
		if cfg.Eavesdrop {
			eveBasis := rnd.bit()
			if eveBasis != basis && rnd.chance(0.5) {
				arrivingBit ^= 1
			}
		}

		// 信道：自然噪声比特翻转。
		if rnd.chance(cfg.NoiseRate) {
			arrivingBit ^= 1
		}

		// Bob 测量：基一致得到到达比特；基不一致结果随机。
		bobBit := byte(0)
		if bobBasis == basis {
			bobBit = arrivingBit
		} else {
			bobBit = rnd.bit()
		}

		records = append(records, measured{
			aliceBit: bit,
			basis:    basis,
			bobBasis: bobBasis,
			bobBit:   bobBit,
		})
	}
	st.Received = len(records)

	// —— 阶段 3：基矢比对（进程内模拟经典公共信道）并筛选 ——
	var aliceSifted, bobSifted []byte
	for _, rc := range records {
		if rc.basis == rc.bobBasis {
			aliceSifted = append(aliceSifted, rc.aliceBit)
			bobSifted = append(bobSifted, rc.bobBit)
		}
	}
	st.BasisMatched = len(aliceSifted)

	// —— 阶段 4：抽样估计误码率并做安全判定 ——
	sampleN := int(math.Floor(float64(len(aliceSifted)) * cfg.SampleFraction))
	st.SampleBits = sampleN
	if sampleN < cfg.MinSampleSize {
		abort(res, ErrAbortedInsufficientSample)
		return res, nil
	}

	// 抽样位置由种子确定性选取（部分 Fisher–Yates 洗牌取前 sampleN 个）。
	order := make([]int, len(aliceSifted))
	for i := range order {
		order[i] = i
	}
	for i := 0; i < sampleN; i++ {
		j := i + int(rnd.next()%uint64(len(order)-i))
		order[i], order[j] = order[j], order[i]
	}
	sampleSet := make(map[int]struct{}, sampleN)
	for i := 0; i < sampleN; i++ {
		sampleSet[order[i]] = struct{}{}
	}

	errs := 0
	for idx := range sampleSet {
		if aliceSifted[idx] != bobSifted[idx] {
			errs++
		}
	}
	st.SampleErrors = errs
	qber := float64(errs) / float64(sampleN)
	st.EstimatedQBER = qber

	if qber > cfg.QBERThreshold {
		if cfg.Eavesdrop {
			abort(res, ErrAbortedEavesdrop)
		} else {
			abort(res, ErrAbortedQBERExceeded)
		}
		return res, nil
	}

	// 抽样比特已被公开，必须剔除；剩余比特进入纠错。
	var aliceRest, bobRest []byte
	for i := range aliceSifted {
		if _, used := sampleSet[i]; !used {
			aliceRest = append(aliceRest, aliceSifted[i])
			bobRest = append(bobRest, bobSifted[i])
		}
	}
	st.SiftedBits = len(aliceRest)

	// —— 阶段 5：CASCADE 纠错（进程内经典信道上的奇偶校验交互）——
	aliceKey, _, rounds, corrected, leakedParity, cerr := cascade(aliceRest, bobRest, cfg, qber, rnd)
	st.CorrectionRounds = rounds
	st.CorrectedBits = corrected
	if cerr != nil {
		abort(res, cerr)
		return res, nil
	}

	st.ReconciledBits = len(aliceKey)

	// —— 阶段 6：保密放大 ——
	// 按 BB84 成钥率公式收缩：L = n(1-H2(q)) - 泄露比特；
	// 这里 n 已是剔除抽样后的长度，故泄露量只计纠错奇偶交互的实际比特数。
	leaked := leakedParity
	finalLen := int(math.Floor(float64(len(aliceKey))*(1-binaryEntropy(qber)) - float64(leaked)))
	if finalLen <= 0 {
		abort(res, ErrAbortedNoKey)
		return res, nil
	}

	finalBits := toeplitzMultiply(aliceKey, finalLen, len(aliceKey), cfg.Seed^int64(len(aliceKey)))
	st.FinalKeyBits = finalLen

	res.Key = &KeyMaterial{
		ID:        deriveKeyID(cfg.Seed, finalBits, finalLen),
		SessionID: res.SessionID,
		Bits:      finalBits,
		Length:    finalLen,
	}
	return res, nil
}

func abort(res *Result, err error) {
	res.AbortReason = reasonOf(err)
	res.AbortErr = err
}
