package cmd

import (
	"errors"

	crawlsnap "github.com/crawlsnap/crawlsnap-go"
)

// Exit codes. 0 = success, 1 = generic failure; the rest map specific API
// failure modes so scripts can branch on them.
const (
	exitOK           = 0
	exitGeneric      = 1
	exitBadRequest   = 3
	exitAuth         = 4
	exitQuota        = 5
	exitRateLimit    = 6
	exitNotFound     = 7
	exitSubscription = 8
	exitServer       = 10
	exitTimeout      = 11
	exitConnection   = 12
)

// exitFromError maps an error to a process exit code, preferring the most
// specific CrawlSnap API error type.
func exitFromError(err error) int {
	if err == nil {
		return exitOK
	}
	var (
		badReq  *crawlsnap.BadRequestError
		authErr *crawlsnap.AuthenticationError
		quota   *crawlsnap.QuotaExceededError
		rate    *crawlsnap.RateLimitError
		notFnd  *crawlsnap.NotFoundError
		sub     *crawlsnap.SubscriptionInactiveError
		server  *crawlsnap.ServerError
		timeout *crawlsnap.APITimeoutError
		conn    *crawlsnap.APIConnectionError
	)
	switch {
	case errors.As(err, &authErr):
		return exitAuth
	case errors.As(err, &quota):
		return exitQuota
	case errors.As(err, &rate):
		return exitRateLimit
	case errors.As(err, &notFnd):
		return exitNotFound
	case errors.As(err, &sub):
		return exitSubscription
	case errors.As(err, &badReq):
		return exitBadRequest
	case errors.As(err, &server):
		return exitServer
	case errors.As(err, &timeout):
		return exitTimeout
	case errors.As(err, &conn):
		return exitConnection
	default:
		return exitGeneric
	}
}
