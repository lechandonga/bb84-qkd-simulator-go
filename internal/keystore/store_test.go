package keystore_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/lechandonga/bb84-qkd-simulator-go/internal/keystore"
	"github.com/lechandonga/bb84-qkd-simulator-go/internal/qkd"
)

func negotiateKey(t *testing.T, cfg qkd.Config) *qkd.KeyMaterial {
	t.Helper()
	r, err := qkd.Run(cfg)
	if err != nil {
		t.Fatalf("协商失败: %v", err)
	}
	if !r.Succeeded() {
		t.Fatalf("用例需要成功成钥，实际中止: %v", r.AbortErr)
	}
	return r.Key
}

// 业务域：密钥生命周期状态
func TestKeyStore_Lifecycle_BusinessCases(t *testing.T) {
	t.Run("可用→已消费，不可重复发放", func(t *testing.T) {
		st := keystore.New()
		k := negotiateKey(t, qkd.DefaultConfig())
		if err := st.Put(k); err != nil {
			t.Fatalf("登记失败: %v", err)
		}
		state, _ := st.Status(k.ID)
		if state != keystore.StateAvailable {
			t.Fatalf("初始状态应为 available，实际 %s", state)
		}
		got, err := st.Consume(k.ID)
		if err != nil {
			t.Fatalf("首次申请应成功: %v", err)
		}
		if got.Length != k.Length {
			t.Fatalf("发放长度 %d 与登记长度 %d 不一致", got.Length, k.Length)
		}
		for i := range k.Bits {
			if got.Bits[i] != k.Bits[i] {
				t.Fatalf("发放内容与协商密钥第 %d 位不一致", i)
			}
		}
		if _, err := st.Consume(k.ID); !errors.Is(err, keystore.ErrKeyAlreadyUsed) {
			t.Fatalf("重复申请必须被拒绝，实际: %v", err)
		}
		state, _ = st.Status(k.ID)
		if state != keystore.StateConsumed {
			t.Fatalf("消费后状态应为 consumed，实际 %s", state)
		}
		t.Logf("业务[生命周期] 用例=%q 密钥=%s 长度=%d available→consumed，重复申请被拒",
			"单次消费", k.ID, k.Length)
	})

	t.Run("可用→已作废，作废后申请被拒", func(t *testing.T) {
		st := keystore.New()
		k := negotiateKey(t, qkd.DefaultConfig())
		_ = st.Put(k)
		if err := st.Revoke(k.ID); err != nil {
			t.Fatalf("作废失败: %v", err)
		}
		if _, err := st.Consume(k.ID); !errors.Is(err, keystore.ErrKeyRevoked) {
			t.Fatalf("已作废密钥的申请必须被拒绝，实际: %v", err)
		}
		t.Logf("业务[生命周期] 用例=%q available→revoked，申请返回 ErrKeyRevoked", "作废")
	})

	t.Run("中止会话记录不提供任何密钥材料", func(t *testing.T) {
		st := keystore.New()
		cfg := qkd.DefaultConfig()
		cfg.Eavesdrop = true
		r, _ := qkd.Run(cfg)
		if r.Succeeded() {
			t.Fatalf("该用例应为中止会话")
		}
		if err := st.PutAborted(r.SessionID, r.AbortReason); err != nil {
			t.Fatalf("登记中止会话失败: %v", err)
		}
		if _, err := st.Consume("aborted:" + r.SessionID); !errors.Is(err, keystore.ErrKeyAborted) {
			t.Fatalf("中止会话必须拒绝发放，实际: %v", err)
		}
		t.Logf("业务[生命周期] 用例=%q 会话=%s 状态=aborted，无密钥可发放",
			"中止会话", r.SessionID)
	})
}

// 业务域：并发申请同一密钥，恰好一个成功
func TestKeyStore_ConcurrentConsume_BusinessCases(t *testing.T) {
	k := negotiateKey(t, qkd.DefaultConfig())
	st := keystore.New()
	_ = st.Put(k)

	const n = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	success, alreadyUsed, other := 0, 0, 0
	start := make(chan struct{})
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, err := st.Consume(k.ID)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				success++
			case errors.Is(err, keystore.ErrKeyAlreadyUsed):
				alreadyUsed++
			default:
				other++
			}
		}()
	}
	close(start)
	wg.Wait()

	if success != 1 {
		t.Fatalf("并发申请必须恰好 1 个成功，实际成功 %d", success)
	}
	if alreadyUsed != n-1 || other != 0 {
		t.Fatalf("其余请求应全部为 ErrKeyAlreadyUsed，实际 已消费=%d 其他=%d", alreadyUsed, other)
	}
	t.Logf("业务[并发发放] 用例=%q %d 个并发请求: 成功=1 拒绝(已消费)=%d",
		"同一份密钥", n, alreadyUsed)
}

// 业务域：双端标识/长度一致，重复与乱序申请不错配
func TestKeyStore_TwoEndpointsConsistency_BusinessCases(t *testing.T) {
	cfg := qkd.DefaultConfig()
	k := negotiateKey(t, cfg)

	alice, bob := keystore.New(), keystore.New()
	if err := alice.Put(k); err != nil {
		t.Fatalf("Alice 登记失败: %v", err)
	}
	if err := bob.Put(k); err != nil {
		t.Fatalf("Bob 登记失败: %v", err)
	}

	// 重复登记必须被拒绝，避免覆盖造成错配。
	if err := alice.Put(k); !errors.Is(err, keystore.ErrKeyDuplicate) {
		t.Fatalf("重复登记应返回 ErrKeyDuplicate，实际: %v", err)
	}

	// Bob 先乱序申请（先尝试不存在的，再申请真实 ID）。
	if _, err := bob.Consume("key-not-exist"); !errors.Is(err, keystore.ErrKeyNotFound) {
		t.Fatalf("未知 ID 应返回 ErrKeyNotFound，实际: %v", err)
	}
	bobGot, err := bob.Consume(k.ID)
	if err != nil {
		t.Fatalf("Bob 申请失败: %v", err)
	}
	aliceGot, err := alice.Consume(k.ID)
	if err != nil {
		t.Fatalf("Alice 申请失败: %v", err)
	}
	if aliceGot.ID != bobGot.ID || aliceGot.Length != bobGot.Length {
		t.Fatalf("两端密钥标识/长度不一致: %s/%d vs %s/%d",
			aliceGot.ID, aliceGot.Length, bobGot.ID, bobGot.Length)
	}
	for i := range aliceGot.Bits {
		if aliceGot.Bits[i] != bobGot.Bits[i] {
			t.Fatalf("两端密钥第 %d 位不一致", i)
		}
	}

	// 重复申请（乱序后的再次申请）双方均被拒绝。
	if _, err := alice.Consume(k.ID); !errors.Is(err, keystore.ErrKeyAlreadyUsed) {
		t.Fatalf("Alice 重复申请应被拒绝，实际: %v", err)
	}
	if _, err := bob.Consume(k.ID); !errors.Is(err, keystore.ErrKeyAlreadyUsed) {
		t.Fatalf("Bob 重复申请应被拒绝，实际: %v", err)
	}
	t.Logf("业务[双端一致] 用例=%q 两端ID=%s 长度=%d 内容一致；乱序/重复申请均不错配",
		"双端消费", k.ID, k.Length)
}
