package network

import (
	"time"
)

type RateLimiter struct {
	interval time.Duration
	lastTime time.Time
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
		lastTime: time.Now().Add(-time.Second),
	}
}

func (r *RateLimiter) Wait() {
	now := time.Now()
	next := r.lastTime.Add(r.interval)
	if next.After(now) {
		time.Sleep(next.Sub(now))
	}
	r.lastTime = time.Now()
}

func (r *RateLimiter) SetRate(pps int) {
	if pps <= 0 {
		return
	}
	r.interval = time.Second / time.Duration(pps)
}

func (r *RateLimiter) Stop() {
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
