package service

// SwapDummyCompareForTest replaces the dummyCompare seam with the given function
// and returns a restore func the test must defer or register with t.Cleanup. It
// lets an external test assert that a not-found login path spends a bcrypt
// compare (HG-B3) without reaching into unexported state directly.
//
// WARNING: it mutates a package-global seam, so it is NOT safe to use with
// t.Parallel(); concurrent swaps would race. No test uses t.Parallel() today.
func SwapDummyCompareForTest(f func(string) bool) func() {
	orig := dummyCompare
	dummyCompare = f
	return func() { dummyCompare = orig }
}
