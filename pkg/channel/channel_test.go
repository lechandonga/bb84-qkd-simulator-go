package channel

import (
	"sync"
	"testing"
)

// 业务：信道确定性。同一配置+种子重复传输（含并发）必须逐光子一致。
func TestChannel_DeterministicAndConcurrencySafe(t *testing.T) {
	cfg := Config{LossRate: 0.2, NoiseRate: 0.05, Eavesdropping: true}
	photons := make([]Photon, 512)
	for i := range photons {
		photons[i] = Photon{Bit: byte(i % 2), Basis: byte((i / 2) % 2), Seq: i}
	}

	run := func() []Detection {
		ch, err := New(cfg, 42)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return ch.Transmit(photons)
	}
	first := run()
	second := run()
	if len(first) != len(second) {
		t.Fatalf("探测结果长度不一致 %d != %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Detected != second[i].Detected {
			t.Fatalf("位置 %d 探测结果不确定：%v != %v", i, first[i].Detected, second[i].Detected)
		}
		if first[i].Detected {
			a, b := first[i].Photon, second[i].Photon
			if a.Bit != b.Bit || a.Basis != b.Basis {
				t.Fatalf("位置 %d 光子内容不确定", i)
			}
		}
	}

	// 并发使用各自独立的信道实例，结果仍必须与串行一致。
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := run()
			for i := range got {
				if got[i].Detected != first[i].Detected {
					t.Errorf("并发传输结果偏离串行基线，位置 %d", i)
					return
				}
			}
		}()
	}
	wg.Wait()
	t.Log("业务[信道确定性]: 同配置重复与并发传输的丢包/翻转/窃听结果逐位一致")
}

// 业务：丢包率被如实体现在探测数量上。
func TestChannel_LossRate(t *testing.T) {
	const n = 20000
	photons := make([]Photon, n)
	ch, _ := New(Config{LossRate: 0.3}, 1)
	out := ch.Transmit(photons)
	detected := 0
	for _, d := range out {
		if d.Detected {
			detected++
		}
	}
	rate := 1 - float64(detected)/n
	if rate < 0.28 || rate > 0.32 {
		t.Fatalf("实际丢包率 %.3f 偏离配置 0.30 过多", rate)
	}
	t.Logf("业务[丢包]: 配置丢包率 0.30，实测 %.3f", rate)
}

// 业务：噪声在“无窃听、基矢一致”时按比例翻转编码比特。
func TestChannel_NoiseFlipsBits(t *testing.T) {
	const n = 20000
	photons := make([]Photon, n)
	ch, _ := New(Config{NoiseRate: 0.08}, 2)
	out := ch.Transmit(photons)
	flips := 0
	for i, d := range out {
		if d.Detected && d.Photon.Bit != photons[i].Bit {
			flips++
		}
	}
	rate := float64(flips) / n
	if rate < 0.07 || rate > 0.09 {
		t.Fatalf("实测翻转率 %.3f 偏离配置 0.08 过多", rate)
	}
	t.Logf("业务[噪声]: 配置噪声 0.08，实测翻转率 %.3f", rate)
}

// 业务：非法概率配置必须被拒绝。
func TestChannel_InvalidConfig(t *testing.T) {
	for _, bad := range []Config{{LossRate: 1}, {NoiseRate: -0.1}} {
		if _, err := New(bad, 1); err == nil {
			t.Fatalf("非法配置 %+v 未被拒绝", bad)
		}
	}
	t.Log("业务[配置校验]: 越界的丢包率/噪声率被拒绝")
}
