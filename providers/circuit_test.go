package providers_test

import (
	"sync"
	"testing"
	"time"

	"github.com/mori-box/moribox-shared/providers"
	"github.com/stretchr/testify/require"
)

// The breaker exists to stop retry amplification: when a provider is already
// struggling, the worst thing MoriBox can do is send it more traffic. These
// tests pin the three decisions that behaviour depends on — when it opens, how
// many probes it admits, and what closes it again.

func TestBreakerStartsClosed(t *testing.T) {
	breaker := providers.NewCircuitBreaker("moriwin", 3, time.Minute, time.Second)

	require.Equal(t, providers.CircuitClosed, breaker.State())
	require.True(t, breaker.Allow())
}

// TestBreakerOpensAtTheThresholdNotBefore is the off-by-one that matters: a
// breaker that trips one failure early takes a healthy provider offline, and
// one that trips late sends an extra round of doomed traffic.
func TestBreakerOpensAtTheThresholdNotBefore(t *testing.T) {
	breaker := providers.NewCircuitBreaker("moriwin", 3, time.Minute, time.Hour)

	breaker.RecordFailure()
	breaker.RecordFailure()
	require.Equal(t, providers.CircuitClosed, breaker.State(),
		"two failures below a threshold of three must not open the circuit")
	require.True(t, breaker.Allow())

	breaker.RecordFailure()
	require.Equal(t, providers.CircuitOpen, breaker.State())
	require.False(t, breaker.Allow(), "an open circuit must refuse calls")
}

func TestOpenBreakerRefusesUntilTheCooldownElapses(t *testing.T) {
	breaker := providers.NewCircuitBreaker("moriwin", 1, time.Minute, 50*time.Millisecond)
	breaker.RecordFailure()

	require.False(t, breaker.Allow())
	require.False(t, breaker.Allow(), "the cooldown is not consumed by asking")

	time.Sleep(60 * time.Millisecond)
	require.True(t, breaker.Allow(), "after the cooldown a probe must be admitted")
}

// TestHalfOpenAdmitsExactlyOneProbe is the property that stops a recovering
// provider from being knocked over again. Every worker asks at once when the
// cooldown expires; exactly one may go through.
func TestHalfOpenAdmitsExactlyOneProbe(t *testing.T) {
	breaker := providers.NewCircuitBreaker("moriwin", 1, time.Minute, 20*time.Millisecond)
	breaker.RecordFailure()
	time.Sleep(30 * time.Millisecond)

	require.True(t, breaker.Allow(), "the first caller after the cooldown is the probe")
	require.Equal(t, providers.CircuitHalfOpen, breaker.State())

	require.False(t, breaker.Allow(), "a second probe must not be admitted")
	require.False(t, breaker.Allow())
	require.Equal(t, providers.CircuitHalfOpen, breaker.State(),
		"refusing a second probe must not change the state")
}

// TestHalfOpenAdmitsExactlyOneProbeUnderConcurrency runs the same assertion the
// way it actually happens: a whole worker pool waking up together.
func TestHalfOpenAdmitsExactlyOneProbeUnderConcurrency(t *testing.T) {
	breaker := providers.NewCircuitBreaker("moriwin", 1, time.Minute, 20*time.Millisecond)
	breaker.RecordFailure()
	time.Sleep(30 * time.Millisecond)

	const callers = 64
	var (
		start    sync.WaitGroup
		done     sync.WaitGroup
		mu       sync.Mutex
		admitted int
	)
	start.Add(1)
	done.Add(callers)

	for i := 0; i < callers; i++ {
		go func() {
			defer done.Done()
			start.Wait()
			if breaker.Allow() {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	start.Done()
	done.Wait()

	require.Equal(t, 1, admitted, "exactly one probe may cross a half-open circuit")
}

func TestSuccessfulProbeClosesTheCircuit(t *testing.T) {
	breaker := providers.NewCircuitBreaker("moriwin", 1, time.Minute, 20*time.Millisecond)
	breaker.RecordFailure()
	time.Sleep(30 * time.Millisecond)

	require.True(t, breaker.Allow())
	breaker.RecordSuccess()

	require.Equal(t, providers.CircuitClosed, breaker.State())
	require.True(t, breaker.Allow())
	require.True(t, breaker.Allow(), "a closed circuit admits everyone, not one probe")
}

// TestFailedProbeReopensImmediately checks that a half-open failure does not
// have to re-reach the threshold. One failed probe is enough evidence that the
// provider is still down.
func TestFailedProbeReopensImmediately(t *testing.T) {
	breaker := providers.NewCircuitBreaker("moriwin", 5, time.Minute, 20*time.Millisecond)
	for i := 0; i < 5; i++ {
		breaker.RecordFailure()
	}
	require.Equal(t, providers.CircuitOpen, breaker.State())

	time.Sleep(30 * time.Millisecond)
	require.True(t, breaker.Allow())
	require.Equal(t, providers.CircuitHalfOpen, breaker.State())

	breaker.RecordFailure()
	require.Equal(t, providers.CircuitOpen, breaker.State(),
		"a single failed probe must reopen the circuit")
	require.False(t, breaker.Allow(), "and the cooldown must restart")
}

// TestSuccessClearsAccumulatedFailures stops a provider that fails
// intermittently over a long window from eventually tripping the breaker on
// failures that are no longer related to each other.
func TestSuccessClearsAccumulatedFailures(t *testing.T) {
	breaker := providers.NewCircuitBreaker("moriwin", 3, time.Minute, time.Hour)

	breaker.RecordFailure()
	breaker.RecordFailure()
	breaker.RecordSuccess()

	breaker.RecordFailure()
	breaker.RecordFailure()
	require.Equal(t, providers.CircuitClosed, breaker.State(),
		"failures before a success must not count toward the threshold")

	breaker.RecordFailure()
	require.Equal(t, providers.CircuitOpen, breaker.State())
}

// TestFailuresOutsideTheWindowAreForgotten is what makes the counter a rate
// rather than a total. Without it, any provider would eventually open its
// circuit given enough uptime.
func TestFailuresOutsideTheWindowAreForgotten(t *testing.T) {
	breaker := providers.NewCircuitBreaker("moriwin", 3, 40*time.Millisecond, time.Hour)

	breaker.RecordFailure()
	breaker.RecordFailure()
	time.Sleep(60 * time.Millisecond)

	// The first two are now outside the window, so these two cannot reach three.
	breaker.RecordFailure()
	breaker.RecordFailure()
	require.Equal(t, providers.CircuitClosed, breaker.State(),
		"stale failures must not count toward the threshold")

	breaker.RecordFailure()
	require.Equal(t, providers.CircuitOpen, breaker.State(),
		"three failures inside the window still open it")
}

// TestNonPositiveSettingsFallBackToDefaults guards the zero value. A breaker
// built from an unset config must not have a threshold of zero, which would
// open it on the first call and take the provider offline permanently.
func TestNonPositiveSettingsFallBackToDefaults(t *testing.T) {
	breaker := providers.NewCircuitBreaker("moriwin", 0, 0, 0)

	require.Equal(t, providers.CircuitClosed, breaker.State())
	for i := 0; i < 9; i++ {
		breaker.RecordFailure()
	}
	require.Equal(t, providers.CircuitClosed, breaker.State(),
		"the default threshold is 10, so nine failures must not open it")

	breaker.RecordFailure()
	require.Equal(t, providers.CircuitOpen, breaker.State())
}

// TestClosedBreakerNeverRefuses is the invariant a caller relies on: while the
// provider is healthy the breaker is not a bottleneck.
func TestClosedBreakerNeverRefuses(t *testing.T) {
	breaker := providers.NewCircuitBreaker("moriwin", 3, time.Minute, time.Second)

	for i := 0; i < 1000; i++ {
		require.True(t, breaker.Allow())
		breaker.RecordSuccess()
	}
}

// TestConcurrentUseIsRaceFree exercises the breaker the way the client does,
// from many goroutines at once. Run with -race; the assertion is that the state
// remains one of the three legal values throughout.
func TestConcurrentUseIsRaceFree(t *testing.T) {
	breaker := providers.NewCircuitBreaker("moriwin", 5, 50*time.Millisecond, 10*time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if breaker.Allow() {
					if (n+j)%3 == 0 {
						breaker.RecordFailure()
					} else {
						breaker.RecordSuccess()
					}
				}
				state := breaker.State()
				if state != providers.CircuitClosed &&
					state != providers.CircuitOpen &&
					state != providers.CircuitHalfOpen {
					t.Errorf("breaker reached an illegal state %q", state)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
