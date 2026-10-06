package qkd

// Session 表示一次带身份标识的 BB84 协商会话。
type Session struct {
	id string
}

// NewSession 创建会话。
func NewSession(id string) *Session { return &Session{id: id} }

// Negotiate 执行一次协商。成功时返回包含共享密钥的 Result，
// 失败时返回带明确中止原因的 Result（且 Key 为 nil）。
func (s *Session) Negotiate(cfg Config) (*Result, error) {
	res, err := Run(cfg)
	if err != nil {
		return nil, err
	}
	res.SessionID = s.id
	if res.Key != nil {
		res.Key.SessionID = s.id
	}
	return res, nil
}
