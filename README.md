# BB84 量子密钥分发模拟器（Go，进程内）

完全运行在本地进程内的 BB84 量子密钥分发（QKD）模拟与密钥管理组件。
模拟光量子信道的**噪声、丢包、窃听**全部由本地配置驱动，不依赖任何
外部服务或真实量子设备；所有随机行为由可注入的随机种子决定，
**同一配置重复运行（包括并发）结果逐位一致、可复现**。

## 目录结构

| 路径 | 职责 |
| --- | --- |
| `internal/randutil` | 种子驱动的确定性 PCG 随机源 |
| `pkg/channel` | 模拟光量子信道：丢包、偏振翻转噪声、Eve 拦截-重发 |
| `pkg/bb84` | BB84 协议引擎：制备/测量/筛选/抽样/纠错/保密放大 |
| `pkg/qkd` | 会话安全判定 + 并发安全的带状态密钥库 |
| `cmd/qkd-demo` | 五种典型信道条件的本地演示 |

## BB84 协商流程

`pkg/bb84/bb84.go` 中一次协商依次执行：

1. **态制备**：Alice 对每个脉冲随机选择比特与基矢（直线基 `+` / 对角基 `x`）。
2. **信道传输**（`pkg/channel`）：按顺序处理 丢包判定 → Eve 拦截重发 → 噪声翻转，
   随机数按同样顺序消耗，保证确定可复现。
3. **测量**：Bob 随机选基测量；基矢不一致时结果随机塌缩。
4. **基矢比对与筛选（sifting）**：保留“成功探测且双方基一致”的位置，两端按位置对齐。
5. **抽样估计 QBER**：从筛选密钥中随机抽取 `SampleFraction` 比例公开比对，
   抽样位随后从密钥中剔除。
6. **信息协调（纠错）**：Cascade 风格的逐块奇偶校验 + 二分定位 + 历史轮次回溯；
   默认块长 64/32/16/8/4，随后追加随机配对修复轮消除残留偶数错；
   最终用整体 SHA-256 校验确认两端逐位一致，不一致即中止。
7. **保密放大**：按估计误码率扣除 Eve 潜在信息量、纠错披露量、确认哈希与
   安全余量后，用通用哈希族（SHA-256 计数器模式扩展掩码的线性通用哈希）压缩。
   **误码率越高，可提取密钥越短**；可提取量耗尽时中止。

### 确定性保证

- 协议随机源与信道随机源都只由 `Config.Seed` 派生（不同异或常量分流），
  不接触时间、网络、协程 ID 等环境因素。
- 引擎是单次无状态对象，多个协商并发运行互不共享状态。
- 测试 `TestBB84_DeterministicAcrossRuns` 与
  `TestChannel_DeterministicAndConcurrencySafe` 验证了串行/并发结果完全一致。

## 安全判定与中止原因

抽样比对后按下表判定，中止原因用 `bb84.AbortReason` 区分（可类型断言为
`*bb84.NegotiationError` 读取 `Reason`）：

| 中止原因 | 触发条件 |
| --- | --- |
| `insufficient_sample` | 筛选后有效比特少于 `MinSiftedBits`，或抽样样本少于 `MinSampleBits` |
| `qber_exceeded` | 抽样 QBER 严格大于 `QBERThreshold`（默认演示 0.15），疑似窃听；或保密放大后可提取长度 ≤ 0 |
| `error_correction_failed` | 纠错后整体 SHA-256 校验仍不一致（可通过 `ReconciliationRounds=1` 在高误码下复现） |

- **正常噪声不被误判**：拦截-重发攻击在“基一致”位置引入约 25% 的误码，
  而几个百分点的光学噪声远低于默认阈值 0.15。
- **中止即无密钥**：中止会话只登记会话记录，密钥库中不产生任何密钥材料
  （`TestQKD_AbortedSessionHoldsNoKey` 覆盖）。

## 密钥生命周期与消费语义

密钥状态（`qkd.KeyStatus`）：

| 状态 | 语义 |
| --- | --- |
| `available` | 协商成功入库，可申请 |
| `consumed` | 已被唯一一次消费取走，不再发放 |
| `revoked` | 被管理方作废，不再发放 |
| `aborted` | 会话中止标记；中止会话不持有密钥字节 |

消费规则（`KeyStore.Consume`，互斥锁内原子完成）：

- 同一份密钥**恰好消费一次**；64 个并发申请时恰有 1 个成功，
  其余以 `already_consumed` 拒绝（`TestQKD_ConcurrentConsumeExactlyOneWinner`）。
- 已作废 / 不存在的申请分别返回 `key_revoked` / `key_not_found`。
- 密钥标识由 `(会话标识, 协商种子, 最终比特长度)` 的 SHA-256 派生，
  不含随机量；**两端独立执行同一协商得到相同标识与长度**，
  重复或乱序申请不会错配，重复 `sessionID` 登记返回 `session_exists`。

## 使用示例

```go
store := qkd.NewKeyStore()
mgr := qkd.NewManager(store)

sess, err := mgr.Run("link-20261006-01", bb84.Config{
    Pulses:               8192,
    MinSiftedBits:        256,
    SampleFraction:       0.2,
    MinSampleBits:        64,
    QBERThreshold:        0.15,
    SafetyBits:           16,
    ReconciliationRounds: 3,
    Channel: channel.Config{LossRate: 0.3, NoiseRate: 0.04},
    Seed:    42,
})
if err != nil {
    var ne *bb84.NegotiationError
    errors.As(err, &ne)
    log.Fatalf("协商中止，原因 %s：%v", ne.Reason, err)
}
key, material, err := store.Consume(sess.KeyID) // 仅第一次成功
```

## 本地验证

```bash
go run ./cmd/qkd-demo          # 五种信道场景演示
go test ./... -v               # 全部用例，日志按“业务[名称]”标注覆盖点
CGO_ENABLED=1 go test -race ./...   # 竞态检测
go test -cover ./pkg/...       # 覆盖率（channel 100%，bb84/qkd > 77%）
go vet ./...
```

`go run ./cmd/qkd-demo` 依次演示：理想信道、噪声 4%+丢包 30%、
噪声 6%（密钥进一步收缩）、高噪声单轮纠错失败、Eve 拦截-重发中止。

## 测试覆盖的业务场景

- **信道层**：同种子重复/并发传输逐位一致；丢包率与噪声翻转率符合配置；非法配置拒绝。
- **协议层**：正常协商；噪声+丢包成功且密钥随 QBER 收缩；窃听 QBER≈25% 中止且无密钥；
  筛选不足/抽样不足两类 `insufficient_sample`；纠错失败独立中止；并发重复协商确定性。
- **会话/密钥库**：一次性消费与重复消费拒绝；64 并发唯一赢家；中止会话零密钥材料；
  三类中止原因可区分；作废/乱序/未知标识的拒绝原因；两端密钥标识与长度一致、重复登记拒绝。
