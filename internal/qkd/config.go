package qkd

import "errors"

// ErrInvalidConfig 表示协商参数本身不合法（区别于会话被中止）。
var ErrInvalidConfig = errors.New("qkd: invalid configuration")

// Config 描述一次本地 BB84 模拟的全部可注入条件。
type Config struct {
	// PhotonCount 为 Alice 发送的光子（脉冲）总数。
	PhotonCount int

	// NoiseRate 为信道自然噪声导致比特翻转的概率（0..1）。
	NoiseRate float64
	// LossRate 为光子在信道中丢失（接收端收不到）的概率（0..1）。
	LossRate float64

	// Eavesdrop 开启后，窃听者 Eve 对未丢失的光子逐个拦截-测量-重发，
	// 其行为完全由 Seed 决定，因而可复现。
	Eavesdrop bool

	// SampleFraction 为筛选后密钥中用于抽样估计误码率的比例（0..1）。
	SampleFraction float64

	// QBERThreshold 为安全判定的误码率上限，超过即判定疑似窃听并中止。
	QBERThreshold float64

	// MinSampleSize 为抽样有效样本的最小数量，不足则中止。
	MinSampleSize int

	// CascadePasses 为 CASCADE 纠错的最大轮数。
	CascadePasses int

	// Seed 为随机种子；相同配置 + 相同 Seed 重复运行结果完全一致。
	Seed int64
}

// DefaultConfig 返回一组可正常成钥的典型参数。
func DefaultConfig() Config {
	return Config{
		PhotonCount:    4096,
		NoiseRate:      0.02,
		LossRate:       0.1,
		Eavesdrop:      false,
		SampleFraction: 0.2,
		QBERThreshold:  0.11,
		MinSampleSize:  32,
		CascadePasses:  4,
		Seed:           1,
	}
}

func (c Config) validate() error {
	if c.PhotonCount <= 0 {
		return ErrInvalidConfig
	}
	if c.NoiseRate < 0 || c.NoiseRate > 1 || c.LossRate < 0 || c.LossRate > 1 {
		return ErrInvalidConfig
	}
	if c.SampleFraction <= 0 || c.SampleFraction >= 1 {
		return ErrInvalidConfig
	}
	if c.QBERThreshold <= 0 || c.QBERThreshold >= 1 {
		return ErrInvalidConfig
	}
	if c.MinSampleSize < 1 || c.CascadePasses < 1 {
		return ErrInvalidConfig
	}
	return nil
}
