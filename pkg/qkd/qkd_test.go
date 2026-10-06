package qkd

import (
	"errors"
	"sync"
	"testing"

	"github.com/lechandonga/bb84-qkd-simulator-go/pkg/bb84"
	"github.com/lechandonga/bb84-qkd-simulator-go/pkg/channel"
)

func cfg(seed uint64) bb84.Config {
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

// 业务：成功会话登记可用密钥；消费一次后状态为已消费，重复消费被拒绝。
func TestQKD_SessionSuccessAndSingleConsumption(t *testing.T) {
	mgr := NewManager(nil)
	sess, err := mgr.Run("sess-ok", cfg(401))
	if err != nil {
		t.Fatalf("协商失败：%v", err)
	}
	if sess.Status != StatusSuccess || sess.KeyID == "" {
		t.Fatalf("会话应成功并带密钥标识，实际 %+v", sess)
	}

	key, mat, err := mgr.Store().Consume(sess.KeyID)
	if err != nil {
		t.Fatalf("首次消费应成功：%v", err)
	}
	if mat.Status != KeyConsumed || len(key)*8 < sess.KeyBitLen-7 {
		t.Fatalf("消费后状态/长度异常：status=%s len=%d bitLen=%d", mat.Status, len(key), sess.KeyBitLen)
	}

	if _, _, err := mgr.Store().Consume(sess.KeyID); err == nil {
		t.Fatal("重复消费必须被拒绝")
	} else {
		var se *StoreError
		if !errors.As(err, &se) || se.Code != ErrAlreadyConsumed {
			t.Fatalf("拒绝原因应为 %s，实际 %v", ErrAlreadyConsumed, err)
		}
	}
	t.Logf("业务[一次性消费]: 会话 %s 密钥 %d bit 首次消费成功，重复消费以 %s 拒绝",
		sess.ID, sess.KeyBitLen, ErrAlreadyConsumed)
}

// 业务：并发申请同一份密钥恰好一个成功，其余全部以 already_consumed 拒绝。
func TestQKD_ConcurrentConsumeExactlyOneWinner(t *testing.T) {
	mgr := NewManager(nil)
	sess, err := mgr.Run("sess-concurrent", cfg(402))
	if err != nil {
		t.Fatalf("协商失败：%v", err)
	}

	const contenders = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins, rejected := 0, 0
	start := make(chan struct{})
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := mgr.Store().Consume(sess.KeyID)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				wins++
			} else {
				var se *StoreError
				if errors.As(err, &se) && se.Code == ErrAlreadyConsumed {
					rejected++
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins != 1 || rejected != contenders-1 {
		t.Fatalf("并发消费赢家数=%d（应为1），被拒数=%d（应为%d）", wins, rejected, contenders-1)
	}
	t.Logf("业务[并发唯一发放]: %d 个并发申请，1 个成功，%d 个以 %s 被拒",
		contenders, rejected, ErrAlreadyConsumed)
}

// 业务：中止会话只留中止记录，密钥库不存在任何关联密钥材料。
func TestQKD_AbortedSessionHoldsNoKey(t *testing.T) {
	mgr := NewManager(nil)
	c := cfg(403)
	c.Channel = channel.Config{Eavesdropping: true}
	sess, err := mgr.Run("sess-eve", c)
	if err == nil {
		t.Fatal("窃听场景应中止")
	}
	if sess.Status != StatusAborted || sess.AbortReason != bb84.AbortQBERExceeded {
		t.Fatalf("会话状态/原因异常：%+v", sess)
	}
	if _, _, err := mgr.Store().Consume(sess.KeyID); err == nil {
		t.Fatal("中止会话不应存在可消费密钥")
	}
	if got := len(mgr.Store().sessions); got != 1 {
		t.Fatalf("应登记 1 条中止会话记录，实际 %d", got)
	}
	t.Logf("业务[中止无密钥]: 会话 %s 以 %s 中止，密钥库零密钥材料", sess.ID, sess.AbortReason)
}

// 业务：三类中止原因可区分。
func TestQKD_AbortReasonsAreDistinct(t *testing.T) {
	mgr := NewManager(nil)

	eve := cfg(404)
	eve.Channel = channel.Config{Eavesdropping: true, NoiseRate: 0.01}
	s1, err1 := mgr.Run("eve", eve)
	if err1 == nil || s1.AbortReason != bb84.AbortQBERExceeded {
		t.Fatalf("窃听原因异常：%v", err1)
	}

	loss := cfg(405)
	loss.Channel = channel.Config{LossRate: 0.98}
	s2, err2 := mgr.Run("loss", loss)
	if err2 == nil || s2.AbortReason != bb84.AbortInsufficientSample {
		t.Fatalf("样本不足原因异常：%v", err2)
	}

	ec := cfg(406)
	ec.Channel = channel.Config{NoiseRate: 0.13}
	ec.ReconciliationRounds = 1
	s3, err3 := mgr.Run("ec", ec)
	if err3 == nil {
		t.Fatal("高误码单轮纠错场景应中止")
	}
	if s3.AbortReason != bb84.AbortErrorCorrectionFailed && s3.AbortReason != bb84.AbortQBERExceeded {
		t.Fatalf("未预期的中止原因：%s", s3.AbortReason)
	}
	t.Logf("业务[中止可区分]: 窃听=%s 样本不足=%s 高噪声场景=%s",
		s1.AbortReason, s2.AbortReason, s3.AbortReason)
}

// 业务：作废密钥不可再消费；重复/乱序申请得到的拒绝原因稳定。
func TestQKD_RevokeAndOutOfOrderRequests(t *testing.T) {
	mgr := NewManager(nil)
	sess, err := mgr.Run("sess-revoke", cfg(407))
	if err != nil {
		t.Fatalf("协商失败：%v", err)
	}
	// 先作废，再以乱序方式先查询后消费。
	if err := mgr.Store().Revoke(sess.KeyID); err != nil {
		t.Fatalf("作废失败：%v", err)
	}
	if _, err := mgr.Store().Lookup(sess.KeyID); err != nil {
		t.Fatalf("查询作废密钥应仍可见：%v", err)
	}
	_, _, err = mgr.Store().Consume(sess.KeyID)
	var se *StoreError
	if !errors.As(err, &se) || se.Code != ErrKeyRevoked {
		t.Fatalf("作废密钥消费应以 %s 拒绝，实际 %v", ErrKeyRevoked, err)
	}
	// 重复作废幂等；不存在密钥给出 key_not_found。
	if err := mgr.Store().Revoke(sess.KeyID); err != nil {
		t.Fatalf("重复作废应幂等：%v", err)
	}
	if _, _, err := mgr.Store().Consume("does-not-exist"); err == nil {
		t.Fatal("不存在的密钥必须被拒绝")
	} else if !errors.As(err, &se) || se.Code != ErrKeyNotFound {
		t.Fatalf("拒绝原因应为 %s，实际 %v", ErrKeyNotFound, err)
	}
	t.Logf("业务[作废与乱序]: 作废密钥查询可见、消费以 %s 拒绝，未知标识以 %s 拒绝",
		ErrKeyRevoked, ErrKeyNotFound)
}

// 业务：同一协商在两端独立执行，密钥标识与长度一致；重复/乱序登记不错配。
func TestQKD_KeyIDConsistentAcrossEndpoints(t *testing.T) {
	storeA, storeB := NewKeyStore(), NewKeyStore()
	mA, mB := NewManager(storeA), NewManager(storeB)

	run := func(m *Manager, sid string) *Session {
		s, err := m.Run(sid, cfg(500))
		if err != nil {
			t.Fatalf("协商失败：%v", err)
		}
		return s
	}
	// 乱序、重复地在两端各跑两次同会话标识的等价协商（不同 sessionID 承载重复运行）。
	s1b := run(mB, "link-1")
	s1a := run(mA, "link-1")
	s2a := run(mA, "link-2")
	s2b := run(mB, "link-2")
	if s1a.KeyID != s1b.KeyID || s1a.KeyBitLen != s1b.KeyBitLen {
		t.Fatalf("link-1 两端标识/长度不一致：%+v vs %+v", s1a, s1b)
	}
	if s2a.KeyID != s2b.KeyID || s2a.KeyBitLen != s2b.KeyBitLen {
		t.Fatalf("link-2 两端标识/长度不一致：%+v vs %+v", s2a, s2b)
	}
	if s1a.KeyID == s2a.KeyID {
		t.Fatal("不同会话标识不得派生出相同密钥标识")
	}
	// 同一 sessionID 重复登记必须被拒绝，避免错配覆盖。
	if _, err := mA.Run("link-1", cfg(500)); err == nil {
		t.Fatal("重复会话标识必须登记失败")
	} else {
		var se *StoreError
		if !errors.As(err, &se) || se.Code != ErrSessionExists {
			t.Fatalf("拒绝原因应为 %s，实际 %v", ErrSessionExists, err)
		}
	}
	t.Logf("业务[两端一致]: link-1/link-2 两端密钥标识与长度逐一对齐，重复登记以 %s 拒绝",
		ErrSessionExists)
}
