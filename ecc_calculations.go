package ecc

import (
	"math/big"
)

// Point represents a point on the elliptic curve
type Point struct {
	X, Y *big.Int
}

// ECParams represents the parameters of the elliptic curve
type ECParams struct {
	P, A, B, N *big.Int
	BasePoint  *Point
}

// ScalarMult performs scalar multiplication k * P on the elliptic curve
func ScalarMult(k *big.Int, P *Point, ec *ECParams) *Point {
	result := &Point{X: big.NewInt(0), Y: big.NewInt(0)}
	temp := &Point{X: new(big.Int).Set(P.X), Y: new(big.Int).Set(P.Y)}

	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			result = addPoints(result, temp, ec)
		}
		temp = doublePoint(temp, ec)
	}

	return result
}

// addPoints adds two points on the elliptic curve
func addPoints(P, Q *Point, ec *ECParams) *Point {
	if P.X.Cmp(big.NewInt(0)) == 0 && P.Y.Cmp(big.NewInt(0)) == 0 {
		return &Point{X: new(big.Int).Set(Q.X), Y: new(big.Int).Set(Q.Y)}
	}
	if Q.X.Cmp(big.NewInt(0)) == 0 && Q.Y.Cmp(big.NewInt(0)) == 0 {
		return &Point{X: new(big.Int).Set(P.X), Y: new(big.Int).Set(P.Y)}
	}

	m := new(big.Int)
	if P.X.Cmp(Q.X) == 0 {
		if P.Y.Cmp(Q.Y) != 0 {
			return &Point{X: big.NewInt(0), Y: big.NewInt(0)}
		}
		// P == Q, so we're doubling
		return doublePoint(P, ec)
	}

	// Calculate the slope
	m.Sub(Q.Y, P.Y)
	xDiff := new(big.Int).Sub(Q.X, P.X)
	m.Mul(m, new(big.Int).ModInverse(xDiff, ec.P))
	m.Mod(m, ec.P)

	// Calculate the new X coordinate
	xR := new(big.Int).Mul(m, m)
	xR.Sub(xR, P.X)
	xR.Sub(xR, Q.X)
	xR.Mod(xR, ec.P)

	// Calculate the new Y coordinate
	yR := new(big.Int).Sub(P.X, xR)
	yR.Mul(yR, m)
	yR.Sub(yR, P.Y)
	yR.Mod(yR, ec.P)

	return &Point{X: xR, Y: yR}
}

// doublePoint doubles a point on the elliptic curve
func doublePoint(P *Point, ec *ECParams) *Point {
	if P.Y.Cmp(big.NewInt(0)) == 0 {
		return &Point{X: big.NewInt(0), Y: big.NewInt(0)}
	}

	m := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(P.X, P.X))
	m.Add(m, ec.A)
	m.Mul(m, new(big.Int).ModInverse(new(big.Int).Mul(big.NewInt(2), P.Y), ec.P))
	m.Mod(m, ec.P)

	xR := new(big.Int).Mul(m, m)
	xR.Sub(xR, new(big.Int).Mul(big.NewInt(2), P.X))
	xR.Mod(xR, ec.P)

	yR := new(big.Int).Sub(P.X, xR)
	yR.Mul(yR, m)
	yR.Sub(yR, P.Y)
	yR.Mod(yR, ec.P)

	return &Point{X: xR, Y: yR}
}
