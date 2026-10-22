package shared

import (
	"bytes"
	"context"

	"github.com/google/uuid"
)

// Bus 基于 Redis pub/sub 的实例间广播。消息不持久化，只送达当时已订阅的实例；
// 自己发出的消息不会回调给自己。消息格式："<发送方实例 ID>\n<payload>"
type Bus struct {
	c       *Client
	channel string
	id      string // 本实例 ID，用于过滤自己发出的消息
}

// Bus 返回名为 name 的广播频道
func (c *Client) Bus(name string) *Bus {
	return &Bus{c: c, channel: c.key("bus:" + name), id: uuid.NewString()}
}

// Publish 广播 payload，返回错误表示 Redis 不可用（消息未发出）
func (b *Bus) Publish(ctx context.Context, payload []byte) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	msg := make([]byte, 0, len(b.id)+1+len(payload))
	msg = append(append(append(msg, b.id...), '\n'), payload...)
	return b.c.rdb.Publish(ctx, b.channel, msg).Err()
}

// Run 订阅频道并对其它实例发来的每条消息调用 handle，阻塞到 ctx 取消。
// 断线后 go-redis 自动重连并重新订阅，断线期间的消息会丢失
func (b *Bus) Run(ctx context.Context, handle func(payload []byte)) {
	ps := b.c.rdb.Subscribe(ctx, b.channel)
	defer func() { _ = ps.Close() }()
	b.c.log.Info("subscribed to cluster bus", "channel", b.channel, "instance", b.id)
	ch := ps.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case m, ok := <-ch:
			if !ok {
				return
			}
			from, payload, found := bytes.Cut([]byte(m.Payload), []byte{'\n'})
			if !found || string(from) == b.id {
				continue
			}
			handle(payload)
		}
	}
}
