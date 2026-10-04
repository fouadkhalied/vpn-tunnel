package crypto

const DefaultWindowSize = 2048

// ReplayWindow is a sliding anti-replay window. The zero value is ready to use
// and means "nothing received yet".
type ReplayWindow struct {
	highest uint64
	started bool
	bitmap  [DefaultWindowSize / 64]uint64
}

// locate maps a counter to its slot: which word, and which bit inside it.
// Slots are reused in a ring: counter and counter+DefaultWindowSize share one.
func (w *ReplayWindow) locate(counter uint64) (word int, mask uint64) {
	idx := counter % DefaultWindowSize
	return int(idx / 64), uint64(1) << (idx % 64)
}

// Check reports whether counter is acceptable (not a replay, not too old).
// It does not modify the window: call Update only after the packet has
// been authenticated.
func (w *ReplayWindow) Check(counter uint64) bool {
	if !w.started || counter > w.highest {
		return true // first packet, or a new high-water mark
	}
	if w.highest-counter >= DefaultWindowSize {
		return false // too old (safe to subtract: counter <= highest here)
	}
	word, mask := w.locate(counter)
	return w.bitmap[word]&mask == 0 // acceptable only if not seen yet
}

// Update records counter as accepted.
func (w *ReplayWindow) Update(counter uint64) {
	switch {
	case !w.started || counter > w.highest:
		if !w.started || counter-w.highest >= DefaultWindowSize {
			// everything in the old window is now stale
			w.bitmap = [DefaultWindowSize / 64]uint64{}
		} else {
			// clear the slots of the counters we skipped over, so stale
			// bits from the previous lap don't look like "already seen"
			for c := w.highest + 1; c < counter; c++ {
				word, mask := w.locate(c)
				w.bitmap[word] &^= mask
			}
		}
		w.highest = counter
		w.started = true
	case w.highest-counter >= DefaultWindowSize:
		return // too old: ignore
	}
	word, mask := w.locate(counter)
	w.bitmap[word] |= mask
}
