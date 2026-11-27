package sqlstore

// Every test in this package refuses a session end in an untracked
// transaction, so the suite checks that each path reports its ends.
func init() { strictSessionEnds = true }
