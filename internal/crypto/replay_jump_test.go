package crypto

import "testing"

// A first packet may have any counter, not just 0.
func TestFirstPacketLargeCounter(t *testing.T) {
	var w ReplayWindow
	const c = uint64(1) << 40
	if !w.Check(c) {
		t.Fatal("first packet must be acceptable whatever its counter")
	}
	w.Update(c)
	if w.Check(c) {
		t.Error("duplicate of the first packet must be rejected")
	}
	if !w.Check(c - 1) {
		t.Error("c-1 is inside the window and unseen: accept")
	}
	if w.Check(c - DefaultWindowSize) {
		t.Error("exactly one window below highest is too old: reject")
	}
}

// Jump of 2047: still inside the window, so old bits must SURVIVE.
func TestJumpJustInsideWindowKeepsOldBits(t *testing.T) {
	var w ReplayWindow
	accept(&w, 10)
	accept(&w, 10+DefaultWindowSize-1) // jump of 2047: loop path
	if w.Check(10) {
		t.Error("10 is still in the window and was seen: must be rejected as a replay")
	}
	if !w.Check(11) {
		t.Error("11 was skipped, never seen: must be acceptable")
	}
}

// Jump of 2048: the whole old window is stale; the bitmap is wiped.
// Counter 10 and counter 2058 share a slot, and 2058 is now INSIDE the window
// (highest = 2060), so a leftover bit would wrongly reject it.
func TestJumpOfWindowSizeWipesStaleBits(t *testing.T) {
	var w ReplayWindow
	accept(&w, 10)
	accept(&w, 2060) // jump of 2050: wipe path
	if w.Check(10) {
		t.Error("10 is too old now: reject")
	}
	if !w.Check(2058) {
		t.Error("2058 shares a slot with old counter 10; stale bit must have been cleared")
	}
}

// Same boundary, exactly 2048.
func TestJumpExactlyWindowSize(t *testing.T) {
	var w ReplayWindow
	accept(&w, 10)
	accept(&w, 10+DefaultWindowSize)
	if w.Check(10) {
		t.Error("10 is exactly one window below highest: reject")
	}
	if !w.Check(11) {
		t.Error("11 is the oldest counter still in the window: accept")
	}
}

// A smaller jump must keep the bits of counters that are still in the window.
func TestSmallJumpKeepsRecentBits(t *testing.T) {
	var w ReplayWindow
	accept(&w, 100)
	accept(&w, 101)
	accept(&w, 1000) // jump of 899
	for _, c := range []uint64{100, 101, 1000} {
		if w.Check(c) {
			t.Errorf("%d was accepted before: must be a replay", c)
		}
	}
	if !w.Check(500) {
		t.Error("500 was never seen and is in the window: accept")
	}
}

// A huge jump must be instant (constant time), not a loop over every skipped counter.
func TestHugeJumpIsConstantTime(t *testing.T) {
	var w ReplayWindow
	accept(&w, 1)
	accept(&w, uint64(1)<<62) // looping over this would never finish
	if w.Check(1) {
		t.Error("1 is far too old")
	}
	if !w.Check(uint64(1)<<62 - 1) {
		t.Error("just below highest, unseen: accept")
	}
}

// Counter at the maximum uint64 must not overflow or wrap.
func TestMaxCounter(t *testing.T) {
	const max = ^uint64(0)
	var w ReplayWindow
	accept(&w, 5)
	if !accept(&w, max) {
		t.Fatal("max counter should be accepted as a new high")
	}
	if w.Check(max) {
		t.Error("duplicate of max must be rejected")
	}
	if !w.Check(max - 1) {
		t.Error("max-1 is in the window and unseen: accept")
	}
	if w.Check(5) {
		t.Error("5 is far too old")
	}
}

// Update on a too-old counter must be ignored, not corrupt a shared slot.
func TestUpdateTooOldIsIgnored(t *testing.T) {
	var w ReplayWindow
	accept(&w, 5000)
	w.Update(1) // 1 shares a slot with 4097, which is inside the window
	if !w.Check(4097) {
		t.Error("Update of an ancient counter must not mark the shared slot")
	}
}

// Each session has its own window: a new window starts from scratch.
func TestWindowsAreIndependentPerSession(t *testing.T) {
	var s1, s2 ReplayWindow
	accept(&s1, 5)
	accept(&s1, 3000)
	if s1.Check(5) {
		t.Fatal("setup: 5 should be rejected in session 1")
	}
	if !s2.Check(5) {
		t.Error("a fresh window (new session) must accept counter 5 again")
	}
}

// Jump smaller than the window, but it skips a counter whose slot still holds a
// stale bit from the previous lap: the loop in Update must clear it.
// 10 and 2058 share slot 10. After 10 -> 1000 -> 2500, counter 2058 was skipped
// (never seen) and is inside the window, so it must be acceptable.
func TestSmallJumpClearsSkippedSlots(t *testing.T) {
	var w ReplayWindow
	accept(&w, 10)
	accept(&w, 1000)
	accept(&w, 2500) // jump of 1500: loop path, not wipe
	if w.Check(10) {
		t.Error("10 is too old now")
	}
	if !w.Check(2058) {
		t.Error("2058 was skipped and is in the window; the stale bit from counter 10 must be cleared")
	}
}
