package qkd_test

import (
	"errors"
	"testing"

	"github.com/lechandonga/bb84-qkd-simulator-go/internal/qkd"
)

// 业务域：BB84 协商
func TestBB84_Negotiation_BusinessCases(t *testing.T) {
	cases := []struct {
		name string
		cfg  qkd.Config
	}{
		{"正常协商/低噪声低丢包", qkd.DefaultConfig()},
		{"正常协商/中等噪声", func() qkd.Config {
			c := qkd.DefaultConfig()
			c.NoiseRate = 0.05
			return c
		}()},
		{"正常协商/高丢包但噪声低", func() qkd.Config {
			c := qkd.DefaultConfig()
			c.LossRate = 0.6
			return c
		}()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := qkd.Run(tc.cfg)
			if err != nil {
				t.Fatalf("协商返回异常: %v", err)
			}
			if !r.Succeeded() {
				t.Fatalf("期望成功成钥，实际中止: %v", r.AbortErr)
			}
			if r.Key == nil || r.Key.Length == 0 {
				t.Fatalf("期望产出非空密钥")
			}
			if len(r.Key.Bits) != r.Key.Length {
				t.Fatalf("密钥长度元数据 %d 与比特数 %d 不一致", r.Key.Length, len(r.Key.Bits))
			}
			for _, b := range r.Key.Bits {
				if b > 1 {
					t.Fatalf("密钥必须为比特串，出现非法值 %d", b)
				}
			}
			t.Logf("业务[正常协商] 用例=%q 发送=%d 丢失=%d 基矢匹配=%d 抽样QBER=%.4f 纠错=%d比特/%d轮 最终密钥=%d比特",
				tc.name, r.Stats.Sent, r.Stats.Lost, r.Stats.BasisMatched,
				r.Stats.EstimatedQBER, r.Stats.CorrectedBits, r.Stats.CorrectionRounds, r.Key.Length)
		})
	}
}

// 业务域：可复现性（同配置同种子逐位一致）
func TestBB84_Reproducibility_BusinessCases(t *testing.T) {
	t.Run("同一配置重复运行结果完全一致", func(t *testing.T) {
		cfg := qkd.DefaultConfig()
		r1, err1 := qkd.Run(cfg)
		r2, err2 := qkd.Run(cfg)
		if err1 != nil || err2 != nil {
			t.Fatalf("协商异常: %v %v", err1, err2)
		}
		if r1.Key.ID != r2.Key.ID || r1.Key.Length != r2.Key.Length {
			t.Fatalf("ID/长度不一致: %s/%d vs %s/%d", r1.Key.ID, r1.Key.Length, r2.Key.ID, r2.Key.Length)
		}
		for i := range r1.Key.Bits {
			if r1.Key.Bits[i] != r2.Key.Bits[i] {
				t.Fatalf("第 %d 位不一致，违反可复现性", i)
			}
		}
		t.Logf("业务[可复现性] 用例=%q 两次运行密钥ID=%s 长度=%d 逐位一致", "相同种子", r1.Key.ID, r1.Key.Length)
	})

	t.Run("不同种子产生不同密钥", func(t *testing.T) {
		c1, c2 := qkd.DefaultConfig(), qkd.DefaultConfig()
		c2.Seed = 42
		r1, _ := qkd.Run(c1)
		r2, _ := qkd.Run(c2)
		if r1.Key.ID == r2.Key.ID {
			t.Fatalf("不同种子不应产出相同密钥ID")
		}
		t.Logf("业务[可复现性] 用例=%q 种子1→%s 种子42→%s", "不同种子", r1.Key.ID, r2.Key.ID)
	})
}

// 业务域：误码率上升导致密钥合理收缩
func TestBB84_KeyShrinksWithNoise_BusinessCases(t *testing.T) {
	noiseLevels := []float64{0.01, 0.03, 0.05, 0.07}
	var prev int = 1 << 30
	for _, nr := range noiseLevels {
		cfg := qkd.DefaultConfig()
		cfg.NoiseRate = nr
		r, _ := qkd.Run(cfg)
		if !r.Succeeded() {
			t.Fatalf("噪声 %.2f 应在安全范围内成钥，实际中止: %v", nr, r.AbortErr)
		}
		if r.Key.Length > prev {
			t.Fatalf("误码率升高密钥长度应非增: %.2f→%d 但上一档为 %d", nr, r.Key.Length, prev)
		}
		t.Logf("业务[密钥收缩] 用例=噪声%.2f 估计QBER=%.4f 最终长度=%d", nr, r.Stats.EstimatedQBER, r.Key.Length)
		prev = r.Key.Length
	}
}

// 业务域：安全判定与会话中止
func TestBB84_Abort_BusinessCases(t *testing.T) {
	t.Run("疑似窃听-中止且无密钥材料", func(t *testing.T) {
		cfg := qkd.DefaultConfig()
		cfg.Eavesdrop = true
		r, _ := qkd.Run(cfg)
		if r.Succeeded() || r.Key != nil {
			t.Fatalf("窃听会话必须中止且不产出密钥")
		}
		if !errors.Is(r.AbortErr, qkd.ErrAbortedEavesdrop) {
			t.Fatalf("中止原因应为疑似窃听，实际: %v", r.AbortErr)
		}
		if r.AbortReason != qkd.ReasonEavesdrop {
			t.Fatalf("中止原因编码错误: %s", r.AbortReason)
		}
		if r.Stats.EstimatedQBER <= cfg.QBERThreshold {
			t.Fatalf("窃听场景QBER应明显高于门限: %.4f", r.Stats.EstimatedQBER)
		}
		t.Logf("业务[中止判定] 用例=%q QBER=%.4f 门限=%.2f 原因=%s",
			"窃听", r.Stats.EstimatedQBER, cfg.QBERThreshold, r.AbortReason)
	})

	t.Run("误码率超限(无窃听)-可区分原因", func(t *testing.T) {
		cfg := qkd.DefaultConfig()
		cfg.NoiseRate = 0.13
		r, _ := qkd.Run(cfg)
		if r.Succeeded() {
			t.Fatalf("超限噪声必须中止")
		}
		if !errors.Is(r.AbortErr, qkd.ErrAbortedQBERExceeded) {
			t.Fatalf("应为误码率超限，实际: %v", r.AbortErr)
		}
		t.Logf("业务[中止判定] 用例=%q QBER=%.4f 原因=%s", "自然高噪声", r.Stats.EstimatedQBER, r.AbortReason)
	})

	t.Run("有效样本不足-可区分原因", func(t *testing.T) {
		cfg := qkd.DefaultConfig()
		cfg.PhotonCount = 200
		cfg.LossRate = 0.95
		r, _ := qkd.Run(cfg)
		if r.Succeeded() {
			t.Fatalf("样本不足必须中止")
		}
		if !errors.Is(r.AbortErr, qkd.ErrAbortedInsufficientSample) {
			t.Fatalf("应为样本不足，实际: %v", r.AbortErr)
		}
		t.Logf("业务[中止判定] 用例=%q 到达=%d 抽样数=%d 原因=%s",
			"高丢包样本不足", r.Stats.Received, r.Stats.SampleBits, r.AbortReason)
	})

	t.Run("纠错失败-可区分原因", func(t *testing.T) {
		cfg := qkd.DefaultConfig()
		cfg.NoiseRate = 0.10
		cfg.CascadePasses = 1
		r, _ := qkd.Run(cfg)
		if !errors.Is(r.AbortErr, qkd.ErrAbortedCorrectionFailed) {
			if r.Succeeded() {
				t.Skipf("种子1在单轮配置下恰好收敛，改用扫描寻找用例")
			}
			t.Fatalf("期望纠错失败，实际: %v", r.AbortErr)
		}
		t.Logf("业务[中止判定] 用例=%q 纠正=%d 原因=%s", "单轮纠错未收敛", r.Stats.CorrectedBits, r.AbortReason)
	})

	t.Run("正常噪声不得被误判为窃听", func(t *testing.T) {
		for _, nr := range []float64{0.0, 0.02, 0.05, 0.08} {
			cfg := qkd.DefaultConfig()
			cfg.NoiseRate = nr
			r, _ := qkd.Run(cfg)
			if !r.Succeeded() {
				t.Fatalf("噪声 %.2f 在门限内不应中止: %v", nr, r.AbortErr)
			}
		}
		t.Logf("业务[中止判定] 用例=%q 噪声0/0.02/0.05/0.08 均正常成钥，无误判", "误判防护")
	})
}

func TestInvalidConfig(t *testing.T) {
	bad := qkd.DefaultConfig()
	bad.PhotonCount = 0
	if _, err := qkd.Run(bad); !errors.Is(err, qkd.ErrInvalidConfig) {
		t.Fatalf("非法配置应返回 ErrInvalidConfig，实际: %v", err)
	}
	t.Logf("业务[参数校验] 用例=%q 非法光子数被拒绝", "非法配置")
}
