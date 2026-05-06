package forwarder

import "time"

func Backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := time.Duration(attempt*attempt) * 200 * time.Millisecond
	if d > 30*time.Second {
		return 30 * time.Second
	}
	return d
}

