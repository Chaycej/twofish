package main

import "testing"

func TestInt64ToKeyblock(t *testing.T) {
	var num uint64 = 12977601823743685594
	arr := make([]uint16, 4)
	int64ToKeyBlock(num, arr)

	if arr[0] != 46105 || arr[1] != 46105 || arr[2] != 46260 || arr[3] != 13274 {
		t.Errorf("uint16 block was incorrect\n")
		t.Errorf("expected: %d %d %d %d", 46105, 46105, 46260, 13274)
		t.Errorf("got: %d %d %d %d", arr[0], arr[1], arr[2], arr[3])
	}
}

func TestReverseSlice(t *testing.T) {
	arr := []uint8{1, 2, 3, 4, 5}
	reverseSlice(arr)

	for i := len(arr) - 1; i >= 0; i-- {
		if arr[i] != uint8(5-i) {
			t.Error("reverseSlice() failed")
			t.Errorf("expected %d, got: %d\n", uint8(5-i), arr[i])
		}
	}

}
