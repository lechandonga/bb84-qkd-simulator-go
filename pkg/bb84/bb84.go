// Package bb84 在进程内模拟完整的 BB84 量子密钥协商流程。
//
// 流程覆盖：Alice 态制备 -> 模拟光量子信道传输（噪声/丢包/窃听）->
// Bob 测量 -> 基矢比对与筛选（sifting）-> 抽样估计误码率（QBER）->
// 信息协调（纠错）-> 保密放大（privacy amplification）。
//
// 所有随机性都来自由种子确定的随机源：协商不访问时间、网络或协程
// 调度状态，因此同一配置（含同一随机种子）重复运行的结果逐位一致。
package bb84

import (
	"fmt"
	"math"

	"github.com/lechandonga/bb84-qkd-simulator-go/internal/randutil"
	"github.com/lechandonga/bb84-qkd-simulator-go/pkg/channel"
)

// AbortReason 是协商中止原因，取值见本包常量。
type AbortReason string

const (
	// AbortQBERExceeded 表示抽样估计的误码率超过安全阈值，疑似窃听。
	AbortQBERExceeded AbortReason = "qber_exceeded"
	// AbortInsufficientSample 表示筛选后的有效比特/抽样样本不足，无法可靠估计误码率。
	AbortInsufficientSample AbortReason = "insufficient_sample"
	// AbortErrorCorrectionFailed 表示纠错后双方校验和仍不一致，纠错失败。
	AbortErrorCorrectionFailed AbortReason = "error_correction_failed"
)

// NegotiationError 在协商必须中止时返回，Reason 可用于区分中止原因。
type NegotiationError struct {
	Reason AbortReason
	msg    string
}

func (e *NegotiationError) Error() string {
	return fmt.Sprintf("bb84: 协商中止（%s）：%s", e.Reason, e.msg)
}

// Config 是一次 BB84 协商的全部配置。
type Config struct {
	// Pulses 为 Alice 发送的光子脉冲总数。
	Pulses int
	// MinSiftedBits 为筛选后至少需要的有效比特数，不足则中止。
	MinSiftedBits int
	// SampleFraction 为从筛选密钥中抽取出用于估计 QBER 的比例，取值 (0,1)。
	SampleFraction float64
	// MinSampleBits 为抽样比对的最少样本数，不足则按有效样本不足中止。
	MinSampleBits int
	// QBERThreshold 为误码率安全阈值，抽样 QBER 严格大于该值即中止（疑似窃听）。
	QBERThreshold float64
	// SafetyBits 为保密放大时额外扣除的安全余量（比特）。
	SafetyBits int
	// ReconciliationRounds 设置纠错轮数，<=0 时使用默认 3 轮（块长 8/4/2）。
	// 该参数主要用于在高误码场景下演示“纠错失败”这一可区分中止原因。
	ReconciliationRounds int
	// Channel 为模拟信道参数（丢包、噪声、窃听）。
	Channel channel.Config
	// Seed 为本次协商的随机种子，决定全部随机事件。
	Seed uint64
}

// Stats 记录协商各阶段的可观测统计量，便于日志与测试断言。
type Stats struct {
	PulsesSent       int
	Detected         int
	SiftedBits       int
	SampledBits      int
	SampleMismatches int
	EstimatedQBER    float64
	RawKeyBits       int
	RevealedParity   int
	EveLeakageBits   float64
	PrivacyInputBits int
	FinalKeyBits     int
	Eavesdropping    bool
	NoiseRate        float64
	LossRate         float64
}

// Result 是一次协商的结果。
type Result struct {
	// Success 为 true 表示协商成功，Key 为双方一致的最终密钥。
	Success bool
	// Abort 为协商中止的原因错误；成功时为 nil。
	Abort *NegotiationError
	// Key 为经保密放大后的最终共享密钥（字节形式），中止时为 nil。
	Key []byte
	// KeyIDSeed 是由本次协商确定量派生密钥标识所需的种子（见会话层）。
	KeyIDSeed uint64
	Stats     Stats
}

// Engine 执行一次完整 BB84 协商。Engine 不保留跨次协商状态，
// 每次调用 Run 都从配置与种子重新开始，可安全并发运行多个实例。
type Engine struct {
	cfg Config
	// protocolRng 驱动协议侧随机性：制备、测量、抽样、纠错置换与 PA 种子。
	protocolRng *randutil.RNG
}

// NewEngine 创建协议引擎，并校验配置。
func NewEngine(cfg Config) (*Engine, error) {
	if cfg.Pulses <= 0 {
		return nil, fmt.Errorf("bb84: Pulses 必须为正数")
	}
	if cfg.MinSiftedBits <= 0 {
		return nil, fmt.Errorf("bb84: MinSiftedBits 必须为正数")
	}
	if cfg.SampleFraction <= 0 || cfg.SampleFraction >= 1 {
		return nil, fmt.Errorf("bb84: SampleFraction 必须落在 (0,1)")
	}
	if cfg.MinSampleBits <= 0 {
		return nil, fmt.Errorf("bb84: MinSampleBits 必须为正数")
	}
	if cfg.QBERThreshold <= 0 || cfg.QBERThreshold >= 1 {
		return nil, fmt.Errorf("bb84: QBERThreshold 必须落在 (0,1)")
	}
	if cfg.SafetyBits < 0 {
		return nil, fmt.Errorf("bb84: SafetyBits 不能为负")
	}
	return &Engine{cfg: cfg, protocolRng: randutil.New(cfg.Seed ^ 0xa5a5f0f001010101)}, nil
}

// Run 执行完整协商。返回的 Result 一定非 nil；中止原因同时体现在
// Result.Abort 和返回的 error 中（二者为同一个 *NegotiationError）。
func (e *Engine) Run() (*Result, error) {
	cfg := e.cfg
	rng := e.protocolRng

	stats := &Stats{
		PulsesSent:    cfg.Pulses,
		Eavesdropping: cfg.Channel.Eavesdropping,
		NoiseRate:     cfg.Channel.NoiseRate,
		LossRate:      cfg.Channel.LossRate,
	}
	fail := func(reason AbortReason, msg string) (*Result, error) {
		e := &NegotiationError{Reason: reason, msg: msg}
		return &Result{Success: false, Abort: e, Key: nil, Stats: *stats}, e
	}

	// 1. Alice 制备：随机比特 + 随机基。
	photons := make([]channel.Photon, cfg.Pulses)
	aliceBases := make([]byte, cfg.Pulses)
	for i := 0; i < cfg.Pulses; i++ {
		bit := rng.Bit()
		basis := rng.Bit()
		photons[i] = channel.Photon{Bit: bit, Basis: basis, Seq: i}
		aliceBases[i] = basis
	}

	// 2. 光量子信道传输（信道使用独立派生的随机流）。
	ch, err := channel.New(cfg.Channel, cfg.Seed^0x51514444aaaa5555)
	if err != nil {
		return nil, err
	}
	detections := ch.Transmit(photons)

	// 3. Bob 选择测量基并测量。
	bobBases := make([]byte, cfg.Pulses)
	bobBits := make([]byte, cfg.Pulses)
	detected := make([]bool, cfg.Pulses)
	for i := 0; i < cfg.Pulses; i++ {
		bobBases[i] = rng.Bit()
		if detections[i].Detected {
			stats.Detected++
			detected[i] = true
			if bobBases[i] == detections[i].Photon.Basis {
				bobBits[i] = detections[i].Photon.Bit
			} else {
				// 基不匹配时测量结果随机塌缩，随后会在筛选阶段丢弃。
				bobBits[i] = rng.Bit()
			}
		}
	}

	// 4. 基矢比对与筛选：保留“成功探测且双方基一致”的位置，两端严格对齐。
	var aliceSifted, bobSifted []byte
	for i := 0; i < cfg.Pulses; i++ {
		if detected[i] && aliceBases[i] == bobBases[i] {
			aliceSifted = append(aliceSifted, photons[i].Bit)
			bobSifted = append(bobSifted, bobBits[i])
		}
	}
	stats.SiftedBits = len(aliceSifted)

	if len(aliceSifted) < cfg.MinSiftedBits {
		return fail(AbortInsufficientSample,
			fmt.Sprintf("筛选后有效比特仅 %d，少于要求的 %d（丢包率 %.2f）",
				len(aliceSifted), cfg.MinSiftedBits, cfg.Channel.LossRate))
	}

	// 5. 抽样估计 QBER：双方公开比对随机抽取的位置。
	sampleCount := int(float64(len(aliceSifted)) * cfg.SampleFraction)
	if sampleCount < cfg.MinSampleBits {
		return fail(AbortInsufficientSample,
			fmt.Sprintf("抽样样本仅 %d，少于要求的 %d，无法可靠估计误码率",
				sampleCount, cfg.MinSampleBits))
	}
	order := rng.Perm(len(aliceSifted))
	sampleSet := make(map[int]struct{}, sampleCount)
	for _, idx := range order[:sampleCount] {
		sampleSet[idx] = struct{}{}
	}
	mismatches := 0
	var aliceRaw, bobRaw []byte
	for idx := 0; idx < len(aliceSifted); idx++ {
		if _, ok := sampleSet[idx]; ok {
			if aliceSifted[idx] != bobSifted[idx] {
				mismatches++
			}
			continue // 抽样位被公开，必须从密钥中剔除
		}
		aliceRaw = append(aliceRaw, aliceSifted[idx])
		bobRaw = append(bobRaw, bobSifted[idx])
	}
	stats.SampledBits = sampleCount
	stats.SampleMismatches = mismatches
	stats.EstimatedQBER = float64(mismatches) / float64(sampleCount)
	stats.RawKeyBits = len(aliceRaw)

	if stats.EstimatedQBER > cfg.QBERThreshold {
		return fail(AbortQBERExceeded,
			fmt.Sprintf("抽样误码率 %.4f 超过安全阈值 %.4f（抽样 %d 位，不一致 %d 位），疑似存在窃听",
				stats.EstimatedQBER, cfg.QBERThreshold, sampleCount, mismatches))
	}

	// 6. 信息协调（级联纠错），使两端原始密钥逐位一致。
	corrected, revealed, err := reconcile(rng, aliceRaw, bobRaw, cfg.ReconciliationRounds)
	stats.RevealedParity = revealed
	if err != nil {
		return fail(AbortErrorCorrectionFailed, err.Error())
	}

	// 7. 保密放大：扣除 Eve 的潜在信息与纠错泄露，再做全域哈希压缩。
	// Eve 信息量（单比特 Shannon 熵亏）：h = -log2(1 - 4q/3)，
	// 4q/3 源于拦截-重发攻击下 Eve 与筛选比特的互信息 I_E = 1 - h(...)。
	q := stats.EstimatedQBER
	eveLeakage := 0.0
	if x := 1.0 - 4.0*q/3.0; x > 0 {
		eveLeakage = -log2(x) * float64(len(corrected))
	} else {
		eveLeakage = float64(len(corrected))
	}
	// 纠错在经典信道上披露的奇偶校验信息与最终确认哈希（256 比特）同样要扣除。
	stats.EveLeakageBits = eveLeakage
	stats.PrivacyInputBits = len(corrected)
	finalBits := len(corrected) - int(eveLeakage+0.999999) - revealed - 256 - cfg.SafetyBits
	if finalBits <= 0 {
		return fail(AbortQBERExceeded,
			fmt.Sprintf("保密放大后密钥长度为 %d（误码率 %.4f 已使可提取密钥量耗尽）", finalBits, q))
	}

	paSeed := rng.Uint64()
	finalKey := privacyAmplify(corrected, finalBits, paSeed)

	stats.FinalKeyBits = finalBits
	res := &Result{Stats: *stats}
	res.Success = true
	res.Key = finalKey
	// 密钥标识种子只取确定量，保证两端/重复运行派生的标识一致。
	res.KeyIDSeed = cfg.Seed
	return res, nil
}
func log2(x float64) float64 {
	return math.Log2(x)
}
