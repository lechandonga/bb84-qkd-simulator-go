// Package channel 模拟 BB84 所使用的光量子信道。
//
// 信道完全运行在进程内，不依赖任何外部服务或真实量子设备。
// 丢包、信道噪声以及窃听者（Eve）的拦截-重发攻击均由本地配置驱动，
// 且所有随机事件取自可注入种子的确定性随机源，因此传输结果可复现。
package channel

import (
	"fmt"

	"github.com/lechandonga/bb84-qkd-simulator-go/internal/randutil"
)

const (
	// BasisRectilinear 直线基（+）：|0>、|1>。
	BasisRectilinear byte = 0
	// BasisDiagonal 对角基（x）：|+>、|->。
	BasisDiagonal byte = 1
)

// Photon 是 Alice 制备并发送的单光子（用偏振态编码一个比特）。
type Photon struct {
	// Bit 是编码的经典比特 0/1。
	Bit byte
	// Basis 是制备所用基矢，BasisRectilinear 或 BasisDiagonal。
	Basis byte
	// Seq 是该光子在发送序列中的序号，用于双方对齐位置。
	Seq int
}

// Detection 是 Bob 端的探测结果。
type Detection struct {
	// Photon 是经过信道（噪声/窃听）后实际到达的光子；丢包时为 nil。
	Photon *Photon
	// Detected 表示该位置的光子是否被成功探测到。
	Detected bool
}

// Config 描述信道的本地模拟参数。
type Config struct {
	// LossRate 为光子丢包率，取值 [0,1)。0 表示无丢包。
	LossRate float64
	// NoiseRate 为信道噪声导致偏振翻转的概率，取值 [0,1)。
	// 物理上对应光学对准误差、暗计数、退相干等引起的误码贡献。
	NoiseRate float64
	// Eavesdropping 为 true 时模拟 Eve 的拦截-重发攻击：
	// Eve 以随机基测量每个光子并按测量结果重发。
	Eavesdropping bool
}

// Channel 是可复用的模拟光量子信道实例。
type Channel struct {
	cfg Config
	rng *randutil.RNG
}

// New 创建模拟信道。seed 决定丢包、噪声翻转与窃听测量的随机序列。
func New(cfg Config, seed uint64) (*Channel, error) {
	if cfg.LossRate < 0 || cfg.LossRate >= 1 {
		return nil, fmt.Errorf("channel: LossRate 必须落在 [0,1)，当前为 %v", cfg.LossRate)
	}
	if cfg.NoiseRate < 0 || cfg.NoiseRate >= 1 {
		return nil, fmt.Errorf("channel: NoiseRate 必须落在 [0,1)，当前为 %v", cfg.NoiseRate)
	}
	return &Channel{cfg: cfg, rng: randutil.New(seed)}, nil
}

// Transmit 按发送顺序逐个传输光子，返回与输入等长、位置对齐的探测结果。
// 处理顺序固定为：丢包判定 -> Eve 拦截重发 -> 信道噪声翻转，
// 随机数按同样顺序消耗，保证结果确定、可复现。
func (c *Channel) Transmit(photons []Photon) []Detection {
	out := make([]Detection, len(photons))
	for i := range photons {
		p := photons[i]

		// 丢包：光子在信道中损耗，Bob 端无法探测。
		if c.rng.Float64() < c.cfg.LossRate {
			out[i] = Detection{Photon: nil, Detected: false}
			continue
		}

		delivered := p

		// Eve 拦截-重发：用随机基测量。基矢一致时测得正确比特；
		// 基矢不一致时结果完全随机（测量塌缩），随后按测量结果重发。
		if c.cfg.Eavesdropping {
			eveBasis := c.rng.Bit()
			eveBit := delivered.Bit
			if eveBasis != delivered.Basis {
				eveBit = c.rng.Bit()
			}
			delivered = Photon{Bit: eveBit, Basis: eveBasis, Seq: delivered.Seq}
		}

		// 信道噪声：以 NoiseRate 概率翻转偏振编码的比特。
		if c.rng.Float64() < c.cfg.NoiseRate {
			delivered.Bit ^= 1
		}

		out[i] = Detection{Photon: &delivered, Detected: true}
	}
	return out
}
