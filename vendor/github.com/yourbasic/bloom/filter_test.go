package bloom

import (
	"crypto/sha1"
	"testing"
)

func testHash(s string) [20]byte {
	hasher := sha1.New()
	hasher.Write([]byte(s))
	slice := hasher.Sum(nil)
	var h [20]byte
	copy(h[:], slice)
	return h
}

func TestFilterHash(t *testing.T) {
	s1 := testHash("asöldkgjaösldkgaösldkasldgjkaösldkgjöasgkdjg")
	s2 := testHash("elasödlnkgaölsdkfgaölsdkjfaölsdkgaölskgnaösl")
	s3 := testHash("aölsdgkaösldkgaösldkgjaölsdkjgaölsdkgjaösldk")
	for n := 0; n < 100; n++ {
		for p := 1; p <= 128; p *= 2 {
			filter := New(n, p)
			member := filter.TestHash(s1)
			if member {
				t.Errorf("TestHash(s1) = %v; want false\n", member)
			}
			count := filter.Count()
			if count != 0 {
				t.Errorf("Count() = %d; want 0\n", count)
			}

			member = filter.AddHash(s1)
			if member {
				t.Errorf("AddHash(s1) = %v; want false\n", member)
			}
			count = filter.Count()
			if count != 1 {
				t.Errorf("Count() = %d; want 1\n", count)
			}
			member = filter.TestHash(s1)
			if !member {
				t.Errorf("TestHash(s1) = %v; want true\n", member)
			}
			member = filter.TestHash(s2)
			if member {
				t.Errorf("TestHash(s2) = %v; want false\n", member)
			}

			member = filter.AddHash(s1)
			if !member {
				t.Errorf("AddHash(s1) = %v; want true\n", member)
			}
			count = filter.Count()
			if count != 1 {
				t.Errorf("Count() = %d; want 1\n", count)
			}

			member = filter.AddHash(s3)
			if member {
				t.Errorf("AddHash(s3) = %v; want false\n", member)
			}
			count = filter.Count()
			if count != 2 {
				t.Errorf("Count() = %d; want 2\n", count)
			}
		}
	}
}

func TestFalsePositive(t *testing.T) {
	maxP := 1000000

	pSlice := make([][]float64, maxP+1)

	for n := 0; n < 100; n++ {
		for p := 1; p <= maxP; p *= 2 {
			filter := New(n, p)
			fpRate := filter.EstimateFalsePositiveRate(uint(n))
			if pSlice[p] == nil {
				pSlice[p] = make([]float64, 0)
			}
			pSlice[p] = append(pSlice[p], fpRate)
		}
	}

	for p := 1; p <= maxP; p *= 2 {
		total := float64(0)
		for _, fpRate := range pSlice[p] {
			total += fpRate
		}
		avg := total / float64(len(pSlice[p]))
		if avg != float64(1.0/p) {
			t.Errorf("p = %d, got average false positive rate %.10f, expected 1.0 error rate", p, avg)
		}
	}
}

func TestFalsePositiveHash(t *testing.T) {
	maxP := 1000000

	pSlice := make([][]float64, maxP+1)

	for n := 0; n < 100; n++ {
		for p := 1; p <= maxP; p *= 2 {
			filter := New(n, p)
			fpRate := filter.EstimateFalsePositiveRateHash(uint(n))
			if pSlice[p] == nil {
				pSlice[p] = make([]float64, 0)
			}
			pSlice[p] = append(pSlice[p], fpRate)
		}
	}

	for p := 1; p <= maxP; p *= 2 {
		total := float64(0)
		for _, fpRate := range pSlice[p] {
			total += fpRate
		}
		avg := total / float64(len(pSlice[p]))
		if avg != float64(1.0/p) {
			t.Errorf("p = %d, got average false positive rate %.10f, expected 1.0 error rate", p, avg)
		}
	}
}
