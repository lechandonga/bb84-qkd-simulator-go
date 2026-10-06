// Command qkd-demo 在进程内演示四种本地信道条件下的 BB84 协商：
// 理想信道、噪声+丢包、高噪声收缩、Eve 窃听中止。完全离线、可复现。
package main

import (
	"fmt"

	"github.com/lechandonga/bb84-qkd-simulator-go/pkg/bb84"
	"github.com/lechandonga/bb84-qkd-simulator-go/pkg/channel"
	"github.com/lechandonga/bb84-qkd-simulator-go/pkg/qkd"
)

func main() {
	mgr := qkd.NewManager(nil)

	scenarios := []struct {
		name string
		cfg  bb84.Config
	}{
		{"理想信道（无噪声/无丢包）", base(1)},
		{"噪声 4% + 丢包 30%", withChannel(base(2), channel.Config{LossRate: 0.30, NoiseRate: 0.04})},
		{"噪声 6% + 丢包 10%（密钥进一步收缩）", withChannel(withPulses(base(3), 4096), channel.Config{LossRate: 0.10, NoiseRate: 0.06})},
		{"高噪声 13% + 单轮纠错（纠错失败中止）", withRounds(withChannel(base(5), channel.Config{NoiseRate: 0.13}), 1)},
		{"Eve 拦截-重发（应中止）", withChannel(base(4), channel.Config{Eavesdropping: true, NoiseRate: 0.01})},
	}

	for _, sc := range scenarios {
		sess, err := mgr.Run(sc.name, sc.cfg)
		fmt.Printf("=== %s ===\n", sc.name)
		s := sess.Stats
		fmt.Printf("发送脉冲=%d 探测=%d 筛选=%d 抽样=%d 抽样不一致=%d 估计QBER=%.4f\n",
			s.PulsesSent, s.Detected, s.SiftedBits, s.SampledBits, s.SampleMismatches, s.EstimatedQBER)
		if err != nil || sess.Status == qkd.StatusAborted {
			fmt.Printf("结果: 中止，原因=%s\n说明: %s\n\n", sess.AbortReason, sess.AbortError)
			continue
		}
		fmt.Printf("纠错披露=%d Eve泄露=%.1fbit 最终密钥=%d bit (%.1f 字节)\n",
			s.RevealedParity, s.EveLeakageBits, s.FinalKeyBits, float64(s.FinalKeyBits)/8)
		fmt.Printf("结果: 成功，密钥标识=%s\n\n", sess.KeyID)
	}
}

func base(seed uint64) bb84.Config {
	return bb84.Config{
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

func withChannel(cfg bb84.Config, ch channel.Config) bb84.Config {
	cfg.Channel = ch
	return cfg
}

func withRounds(cfg bb84.Config, rounds int) bb84.Config {
	cfg.ReconciliationRounds = rounds
	return cfg
}

func withPulses(cfg bb84.Config, pulses int) bb84.Config {
	cfg.Pulses = pulses
	return cfg
}
