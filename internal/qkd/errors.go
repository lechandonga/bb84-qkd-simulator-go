package qkd

import "errors"

// 会话中止原因：疑似窃听 / 误码率超限 / 有效样本不足 / 纠错失败。
var (
	// ErrAbortedEavesdrop 表示抽样误码率超过安全门限，判定疑似窃听。
	ErrAbortedEavesdrop = errors.New("qkd: session aborted: eavesdrop suspected, qber over threshold")
	// ErrAbortedQBERExceeded 表示无窃听配置下自然误码率仍超过安全门限。
	ErrAbortedQBERExceeded = errors.New("qkd: session aborted: qber exceeds safe threshold")
	// ErrAbortedInsufficientSample 表示有效抽样样本不足，无法给出可信安全判定。
	ErrAbortedInsufficientSample = errors.New("qkd: session aborted: insufficient valid samples")
	// ErrAbortedCorrectionFailed 表示 CASCADE 纠错在限定轮数内未收敛，仍有残余误码。
	ErrAbortedCorrectionFailed = errors.New("qkd: session aborted: error correction failed")
	// ErrAbortedNoKey 表示保密放大后成钥长度收缩为 0，没有可用密钥材料。
	ErrAbortedNoKey = errors.New("qkd: session aborted: privacy amplification yielded zero-length key")
)

// AbortReason 是对中止原因的稳定字符串编码，便于日志与测试断言。
type AbortReason string

const (
	ReasonNone               AbortReason = ""
	ReasonEavesdrop          AbortReason = "eavesdrop_suspected"
	ReasonQBERExceeded       AbortReason = "qber_exceeded"
	ReasonInsufficientSample AbortReason = "insufficient_sample"
	ReasonCorrectionFailed   AbortReason = "correction_failed"
	ReasonNoKey              AbortReason = "zero_length_key"
)

func reasonOf(err error) AbortReason {
	switch {
	case errors.Is(err, ErrAbortedEavesdrop):
		return ReasonEavesdrop
	case errors.Is(err, ErrAbortedQBERExceeded):
		return ReasonQBERExceeded
	case errors.Is(err, ErrAbortedInsufficientSample):
		return ReasonInsufficientSample
	case errors.Is(err, ErrAbortedCorrectionFailed):
		return ReasonCorrectionFailed
	case errors.Is(err, ErrAbortedNoKey):
		return ReasonNoKey
	default:
		return AbortReason("unknown")
	}
}
