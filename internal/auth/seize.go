package auth

import "maps"

func (v *Verifier) LastSeen() map[AccountID]int64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return maps.Clone(v.lastSeen)
}
