package main

import "math/big"

// maxBigInt 返回大整数切片中的最大值
func maxBigInt(values []big.Int) *big.Int {
	if len(values) == 0 {
		return nil
	}
	max := values[0]
	for _, val := range values[1:] {
		if val.Cmp(&max) == 1 {
			max = val
		}
	}
	return &max
}

// meanBigInt 返回大整数切片中的平均值
func meanBigInt(values []big.Int) *big.Int {
	if len(values) == 0 {
		return nil
	}
	sum := big.NewInt(0)
	for _, val := range values {
		sum.Add(sum, &val)
	}
	return sum.Div(sum, big.NewInt(int64(len(values))))
}

func selfBitInt(values []big.Int) *big.Int {
	if len(values) == 0 {
		return nil
	}
	return &values[len(values)-1]
}
