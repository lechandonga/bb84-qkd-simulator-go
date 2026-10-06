// qkd-demo 在进程内用模拟光量子信道演示完整 BB84 协商与密钥管理。
// 不依赖任何外部服务或真实设备：噪声、丢包、窃听全部来自本地配置与随机种子。
package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/lechandonga/bb84-qkd-simulator-go/internal/keystore"
	"github.com/lechandonga/bb84-qkd-simulator-go/internal/qkd"
)

type scenario struct {
	name string
	cfg  qkd.Config
}

func main() {
	seed := flag.Int64("seed", 1, "随机种子（同配置同种子结果完全一致）")
	flag.Parse()

	base := qkd.DefaultConfig()
	base.Seed = *seed

	mk := func(name string, mutate func(*qkd.Config)) scenario {
		c := base
		mutate(&c)
		return scenario{name: name, cfg: c}
	}

	scenarios := []scenario{
		mk("正常信道", func(c *qkd.Config) {}),
		mk("中等噪声", func(c *qkd.Config) { c.NoiseRate = 0.06 }),
		mk("高丢包", func(c *qkd.Config) { c.LossRate = 0.6 }),
		mk("高噪声超门限", func(c *qkd.Config) { c.NoiseRate = 0.13 }),
		mk("样本不足", func(c *qkd.Config) { c.PhotonCount = 200; c.LossRate = 0.95 }),
		mk("疑似窃听", func(c *qkd.Config) { c.Eavesdrop = true }),
	}

	alice := keystore.New()
	bob := keystore.New()

	for _, sc := range scenarios {
		fmt.Printf("════ 场景: %s (seed=%d) ════\n", sc.name, sc.cfg.Seed)
		res, err := qkd.Run(sc.cfg)
		if err != nil {
			fmt.Printf("  配置非法: %v\n\n", err)
			continue
		}
		st := res.Stats
		fmt.Printf("  发送=%d 丢失=%d 到达=%d 基矢匹配=%d\n", st.Sent, st.Lost, st.Received, st.BasisMatched)
		fmt.Printf("  抽样=%d 错误=%d 估计QBER=%.4f (门限 %.2f)\n",
			st.SampleBits, st.SampleErrors, st.EstimatedQBER, sc.cfg.QBERThreshold)

		if !res.Succeeded() {
			fmt.Printf("  → 会话中止，原因=%s (%v)\n", res.AbortReason, res.AbortErr)
			_ = alice.PutAborted(res.SessionID, res.AbortReason)
			_ = bob.PutAborted(res.SessionID, res.AbortReason)
			if _, err := alice.Consume("aborted:" + res.SessionID); err != nil {
				fmt.Printf("  → 尝试申领中止会话密钥被拒绝: %v\n", err)
			}
			fmt.Println()
			continue
		}

		fmt.Printf("  纠错=%d比特/%d轮 协商后=%d 保密放大后最终密钥=%d比特\n",
			st.CorrectedBits, st.CorrectionRounds, st.ReconciledBits, st.FinalKeyBits)
		fmt.Printf("  密钥ID=%s 两端标识/长度一致\n", res.Key.ID)

		_ = alice.Put(res.Key)
		_ = bob.Put(res.Key)
		got, err := alice.Consume(res.Key.ID)
		if err != nil {
			fmt.Printf("  申领失败: %v\n", err)
		} else {
			fmt.Printf("  Alice 首次申领成功，获得 %d 比特\n", got.Length)
		}
		if _, err := alice.Consume(res.Key.ID); err != nil {
			fmt.Printf("  Alice 重复申领被拒绝: %v\n", err)
		}
		fmt.Println()
	}

	// 演示：随噪声升高，最终密钥长度收缩。
	fmt.Println("════ 密钥长度随误码率收缩（同一信道规模） ════")
	for _, nr := range []float64{0.01, 0.03, 0.05, 0.07, 0.08} {
		c := base
		c.NoiseRate = nr
		r, _ := qkd.Run(c)
		status := fmt.Sprintf("最终密钥=%4d比特", r.Stats.FinalKeyBits)
		if !r.Succeeded() {
			status = fmt.Sprintf("中止(%s)", r.AbortReason)
		}
		fmt.Printf("  噪声=%.2f QBER=%.4f → %s\n", nr, r.Stats.EstimatedQBER, status)
	}
	fmt.Println()

	// 演示：并发申领同一份密钥恰好一个成功。
	fmt.Println("════ 并发申领同一份密钥 ════")
	r, _ := qkd.Run(base)
	st := keystore.New()
	_ = st.Put(r.Key)
	const contenders = 16
	results := make(chan error, contenders)
	done := make(chan struct{})
	for i := 0; i < contenders; i++ {
		go func() {
			<-done
			_, err := st.Consume(r.Key.ID)
			results <- err
		}()
	}
	close(done)
	ok, denied := 0, 0
	for i := 0; i < contenders; i++ {
		if err := <-results; err == nil {
			ok++
		} else if errors.Is(err, keystore.ErrKeyAlreadyUsed) {
			denied++
		}
	}
	fmt.Printf("  %d 个并发请求: 成功=%d 被拒绝(已消费)=%d\n", contenders, ok, denied)
}
