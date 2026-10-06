package bb84

import (
	"errors"
	"testing"

	"github.com/lechandonga/bb84-qkd-simulator-go/pkg/channel"
)

func testCfg(seed uint64) Config {
	return Config{
		Pulses:               8192,
		MinSiftedBits:        256,
		SampleFraction:       0.2,
		MinSampleBits:        64,
		QBERThreshold:        0.15,
		SafetyBits:           16,
		ReconciliationRounds: 3,
		Seed:                 seed,
	}
}

func runOne(t *testing.T, cfg Config) (*Result, *NegotiationError) {
	t.Helper()
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	res, err := eng.Run()
	var ne *NegotiationError
	if errors.As(err, &ne) {
		return res, ne
	}
	return res, nil
}

// 业务：理想信道协商成功，最终密钥非空且长度统计一致。
func TestBB84_IdealChannelSucceeds(t *testing.T) {
	res, ne := runOne(t, testCfg(101))
	if ne != nil {
		t.Fatalf("理想信道不应中止：%v", ne)
	}
	if !res.Success || len(res.Key) == 0 {
		t.Fatal("理想信道必须产出非空共享密钥")
	}
	if res.Stats.EstimatedQBER != 0 {
		t.Fatalf("理想信道 QBER 应为 0，实测 %.4f", res.Stats.EstimatedQBER)
	}
	if res.Stats.FinalKeyBits > 8*(len(res.Key)) || res.Stats.FinalKeyBits <= 8*(len(res.Key)-1) {
		t.Fatalf("最终密钥比特数 %d 与字节长度 %d 不一致", res.Stats.FinalKeyBits, len(res.Key))
	}
	t.Logf("业务[正常协商]: 筛选=%d 抽样=%d QBER=0 最终密钥=%d bit",
		res.Stats.SiftedBits, res.Stats.SampledBits, res.Stats.FinalKeyBits)
}

// 业务：噪声与丢包下仍协商成功，正常噪声不被误判为窃听，且密钥随误码率收缩。
func TestBB84_NoiseAndLossSucceedAndShrinks(t *testing.T) {
	ideal, ne1 := runOne(t, testCfg(102))
	if ne1 != nil {
		t.Fatalf("基线协商失败：%v", ne1)
	}
	noisy := testCfg(102)
	noisy.Channel = channel.Config{LossRate: 0.3, NoiseRate: 0.04}
	res, ne := runOne(t, noisy)
	if ne != nil {
		t.Fatalf("正常噪声+丢包不应中止：%v", ne)
	}
	if res.Stats.EstimatedQBER > noisy.QBERThreshold {
		t.Fatalf("正常噪声 %.4f 被误判为窃听", res.Stats.EstimatedQBER)
	}
	if res.Stats.FinalKeyBits >= ideal.Stats.FinalKeyBits {
		t.Fatalf("误码率上升后密钥应收缩：理想=%d 噪声场景=%d",
			ideal.Stats.FinalKeyBits, res.Stats.FinalKeyBits)
	}
	if res.Stats.Detected >= res.Stats.PulsesSent {
		t.Fatal("30%% 丢包下探测数应明显少于发送数")
	}
	t.Logf("业务[噪声丢包]: QBER=%.4f 探测=%d/%d 最终密钥 %d->%d bit（收缩）",
		res.Stats.EstimatedQBER, res.Stats.Detected, res.Stats.PulsesSent,
		ideal.Stats.FinalKeyBits, res.Stats.FinalKeyBits)
}

// 业务：窃听把 QBER 抬升到 ~25%，超过阈值，必须以 qber_exceeded 中止且无密钥。
func TestBB84_EavesdroppingAborts(t *testing.T) {
	cfg := testCfg(103)
	cfg.Channel = channel.Config{Eavesdropping: true, NoiseRate: 0.01}
	res, ne := runOne(t, cfg)
	if ne == nil || ne.Reason != AbortQBERExceeded {
		t.Fatalf("窃听场景应因 %s 中止，实际：%v", AbortQBERExceeded, ne)
	}
	if res.Success || res.Key != nil {
		t.Fatal("疑似窃听的会话不得产出任何密钥材料")
	}
	if res.Stats.EstimatedQBER < 0.18 {
		t.Fatalf("拦截-重发应使 QBER 接近 0.25，实测 %.4f", res.Stats.EstimatedQBER)
	}
	t.Logf("业务[窃听判定]: QBER=%.4f > 阈值 %.2f，以 %s 中止，无密钥产出",
		res.Stats.EstimatedQBER, cfg.QBERThreshold, ne.Reason)
}

// 业务：高丢包导致筛选有效比特不足，以 insufficient_sample 中止。
func TestBB84_InsufficientSiftedBits(t *testing.T) {
	cfg := testCfg(104)
	cfg.Channel = channel.Config{LossRate: 0.97}
	res, ne := runOne(t, cfg)
	if ne == nil || ne.Reason != AbortInsufficientSample {
		t.Fatalf("应因 %s 中止，实际：%v", AbortInsufficientSample, ne)
	}
	if res.Key != nil {
		t.Fatal("中止会话不得产出密钥")
	}
	t.Logf("业务[样本不足-筛选]: 丢包率 0.97，筛选比特=%d，以 %s 中止",
		res.Stats.SiftedBits, ne.Reason)
}

// 业务：抽样比例过低导致抽样样本不足，同样以 insufficient_sample 中止。
func TestBB84_InsufficientSampledBits(t *testing.T) {
	cfg := testCfg(105)
	cfg.SampleFraction = 0.002
	cfg.MinSampleBits = 64
	_, ne := runOne(t, cfg)
	if ne == nil || ne.Reason != AbortInsufficientSample {
		t.Fatalf("抽样不足应因 %s 中止，实际：%v", AbortInsufficientSample, ne)
	}
	t.Logf("业务[样本不足-抽样]: 抽样比例 %.3f，以 %s 中止", cfg.SampleFraction, ne.Reason)
}

// 业务：高误码 + 受限的单轮纠错无法纠净，以 error_correction_failed 中止，
// 且该原因与“疑似窃听/样本不足”可区分。
func TestBB84_ErrorCorrectionFailureDistinct(t *testing.T) {
	found := false
	var last *Result
	for seed := uint64(200); seed < 260; seed++ {
		cfg := testCfg(seed)
		cfg.Channel = channel.Config{NoiseRate: 0.13}
		cfg.ReconciliationRounds = 1
		res, ne := runOne(t, cfg)
		if ne != nil && ne.Reason == AbortQBERExceeded {
			continue // 该种子抽样 QBER 已先超限，跳过
		}
		if ne != nil && ne.Reason == AbortErrorCorrectionFailed {
			found = true
			last = res
			break
		}
	}
	if !found {
		t.Fatal("在 60 个种子中未观察到纠错失败中止，请检查该中止路径")
	}
	if last.Key != nil {
		t.Fatal("纠错失败不得产出密钥")
	}
	t.Logf("业务[纠错失败]: 高误码单轮纠错，QBER=%.4f 通过阈值但校验不一致，以 %s 中止",
		last.Stats.EstimatedQBER, AbortErrorCorrectionFailed)
}

// 业务：同配置重复运行（含并发）必须得到完全一致的 QBER、长度与密钥。
func TestBB84_DeterministicAcrossRuns(t *testing.T) {
	cfg := testCfg(303)
	cfg.Channel = channel.Config{LossRate: 0.2, NoiseRate: 0.03}
	first, ne := runOne(t, cfg)
	if ne != nil {
		t.Fatalf("基线协商失败：%v", ne)
	}

	results := make(chan *Result, 8)
	for i := 0; i < 8; i++ {
		go func() {
			r, _ := runOne(t, cfg)
			results <- r
		}()
	}
	for i := 0; i < 8; i++ {
		r := <-results
		if r.Stats.EstimatedQBER != first.Stats.EstimatedQBER ||
			r.Stats.FinalKeyBits != first.Stats.FinalKeyBits ||
			!equalBytes(r.Key, first.Key) {
			t.Fatal("并发重复运行结果偏离串行基线，确定性被破坏")
		}
	}
	t.Logf("业务[确定性]: 8 个并发重复协商的 QBER=%.4f、长度=%d、密钥逐位一致",
		first.Stats.EstimatedQBER, first.Stats.FinalKeyBits)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
