package network

import (
	"time"
)

type RateLimiter struct {
	interval time.Duration
	ticker   *time.Ticker
	stopCh   chan struct{}
}

func NewRateLimiter(pps int) *RateLimiter {
	if pps <= 0 {
		pps = 1000
	}
	interval := time.Second / time.Duration(pps)
	if interval <= 0 {
		interval = time.Millisecond
	}
	return &RateLimiter{
		interval: interval,
		ticker:   time.NewTicker(interval),
		stopCh:   make(chan struct{}),
	}
}

func (r *RateLimiter) Wait() {
	if r.ticker == nil {
		return
	}
	<-r.ticker.C
}

func (r *RateLimiter) SetRate(pps int) {
	if pps <= 0 {
		return
	}
	if r.ticker != nil {
		r.ticker.Stop()
	}
	r.interval = time.Second / time.Duration(pps)
	r.ticker = time.NewTicker(r.interval)
}

func (r *RateLimiter) Stop() {
	if r.ticker != nil {
		r.ticker.Stop()
	}
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
}

type TokenBucket struct {
	rate   int
	tokens chan struct{}
	stopCh chan struct{}
}

func NewTokenBucket(rate int) *TokenBucket {
	tb := &TokenBucket{
		rate:   rate,
		tokens: make(chan struct{}, rate),
		stopCh: make(chan struct{}),
	}

	go tb.fill()
	return tb
}

func (tb *TokenBucket) fill() {
	interval := time.Second / time.Duration(tb.rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			select {
			case tb.tokens <- struct{}{}:
			default:
			}
		case <-tb.stopCh:
			return
		}
	}
}

func (tb *TokenBucket) Wait() {
	<-tb.tokens
}

func (tb *TokenBucket) SetRate(rate int) {
	tb.rate = rate
}

func (tb *TokenBucket) Stop() {
	close(tb.stopCh)
}
