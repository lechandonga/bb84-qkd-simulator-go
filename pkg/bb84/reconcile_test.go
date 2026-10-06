package bb84

import (
	"testing"

	"github.com/lechandonga/bb84-qkd-simulator-go/internal/randutil"
)

// 业务：级联纠错（含回溯与修复轮）能在中等误码下使两端逐位一致。
func TestReconcile_CorrectsScatteredErrors(t *testing.T) {
	rng := randutil.New(11)
	n := 2000
	alice := make([]byte, n)
	bob := make([]byte, n)
	for i := range alice {
		alice[i] = rng.Bit()
		bob[i] = alice[i]
	}
	noise := randutil.New(22)
	flipped := 0
	for i := range bob {
		if noise.Float64() < 0.06 {
			bob[i] ^= 1
			flipped++
		}
	}
	out, revealed, err := reconcile(randutil.New(33), alice, bob, 0)
	if err != nil {
		t.Fatalf("纠错失败：%v", err)
	}
	for i := range alice {
		if alice[i] != out[i] {
			t.Fatalf("位置 %d 纠错后仍不一致", i)
		}
	}
	if revealed <= 0 || revealed >= n {
		t.Fatalf("披露比特数 %d 不合理（应介于 0 与密钥长度 %d 之间）", revealed, n)
	}
	t.Logf("业务[纠错成功]: %d 比特中翻转 %d 处，披露奇偶信息 %d bit 后逐位一致", n, flipped, revealed)
}

// 业务：单轮纠错无法纠正大量分散错误时，整体校验和必须检出并返回失败。
func TestReconcile_DetectsResidualErrors(t *testing.T) {
	rng := randutil.New(11)
	n := 3000
	alice := make([]byte, n)
	bob := make([]byte, n)
	for i := range alice {
		alice[i] = rng.Bit()
		bob[i] = alice[i]
	}
	noise := randutil.New(44)
	for i := range bob {
		if noise.Float64() < 0.13 {
			bob[i] ^= 1
		}
	}
	_, _, err := reconcile(randutil.New(55), alice, bob, 1)
	if err == nil {
		t.Fatal("单轮纠错面对 13% 误码应检出残留错误并失败")
	}
	t.Logf("业务[纠错检出]: 整体 SHA-256 校验检出残留错误：%v", err)
}
