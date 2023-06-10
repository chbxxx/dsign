package bhsssa

import (
	"errors"
	"math/big"
)

type CurveType int

const (
	Ed25519N               = "7237005577332262213973186563042994240857116359379907606001950938285454250989"
	S256k1N                = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
	Ed25519Prime CurveType = 0x1
	S256k1Prime  CurveType = 0x2
)

type ShareXY struct {
	X, Y *big.Int
}

func GetPrime(curve CurveType) *big.Int {
	var prime *big.Int
	if curve == Ed25519Prime {
		prime, _ = big.NewInt(0).SetString(Ed25519N, 10)
	} else if curve == S256k1Prime {
		prime, _ = big.NewInt(0).SetString(S256k1N, 10)
	} else {
		prime, _ = big.NewInt(0).SetString(S256k1N, 10)
	}
	return prime
}

func CreateShareSecrets(minimum int, shares int, priKey *big.Int, coeff []*big.Int, curveType CurveType) (map[string]ShareXY, []*big.Int, error) {
	// Verify minimum isn't greater than shares; there is no way to recreate
	// the original polynomial in our current setup, therefore it doesn't make
	// sense to generate fewer shares than are needed to reconstruct the secret.

	// Convert the secret to its respective 256-bit big.Int representation
	//var secret []*big.Int = splitByteToInt([]byte(raw))
	prime := GetPrime(curveType)
	copy := big.NewInt(0).Set(priKey)
	if copy.Cmp(prime) >= 0 {
		return nil, nil, errors.New("prikey too large")
	}
	secret := big.NewInt(0).Set(copy)

	// List of currently used numbers in the polynomial
	var numbers []*big.Int = make([]*big.Int, 0)
	numbers = append(numbers, big.NewInt(0))
	var coefficients []*big.Int = make([]*big.Int, 0)

	// CreateShareSecrets the polynomial of degree (minimum - 1); that is, the highest
	// order term is (minimum-1), though as there is a constant term with
	// order 0, there are (minimum) number of coefficients.
	//
	// However, the polynomial object is a 2d array, because we are constructing
	// a different polynomial for each part of the secret
	// polynomial[parts][minimum]
	polynomial := make([]*big.Int, minimum)
	polynomial[0] = secret

	for j := range polynomial[1:] {
		// Each coefficient should be unique
		number := random(curveType)
		for inNumbers(numbers, number) {
			number = random(curveType)
		}
		numbers = append(numbers, number)

		polynomial[j+1] = number
	}
	coefficients = polynomial

	// CreateShareSecrets the secrets object; this holds the (x, y) points of each share.
	// Again, because secret is an array, each share could have multiple parts
	// over which we are computing Shamir's Algorithm. The last dimension is
	// always two, as it is storing an x, y pair of points.
	//
	// Note: this array is technically unnecessary due to creating result
	// in the inner loop. Can disappear later if desired. [TODO]
	//
	// secrets[shares][parts][2]
	var secrets [][]*big.Int = make([][]*big.Int, shares)
	var result map[string]ShareXY = make(map[string]ShareXY, shares)

	// For every share...
	for i := range secrets {
		secrets[i] = make([]*big.Int, 2)

		number := big.NewInt(0).Set(coeff[i])
		numbers = append(numbers, number)

		// ...and evaluate the polynomial at that point...
		secrets[i][0] = number
		secrets[i][1] = evaluatePolynomial(polynomial, number, curveType)
		temp := ShareXY{
			X: secrets[i][0],
			Y: secrets[i][1],
		}
		result[coeff[i].String()] = temp
	}

	// ...and return!
	return result, coefficients, nil
}

/**
 * Takes a string array of shares encoded in base64 created via Shamir's
 * Algorithm; each string must be of equal length of a multiple of 88 characters
 * as a single 88 character share is a pair of 256-bit numbers (x, y).
 *
 * Note: the polynomial will converge if the specified minimum number of shares
 *       or more are passed to this function. Passing thus does not affect it
 *       Passing fewer however, simply means that the returned secret is wrong.
**/
func Combine(shares map[string]ShareXY, curveType CurveType) (*big.Int, error) {
	// Recreate the original object of x, y points, based upon number of shares
	// and size of each share (number of parts in the secret).
	var secrets map[string][]*big.Int = make(map[string][]*big.Int)
	// Set constant prime
	prime := GetPrime(curveType)

	// For each share...
	var all_x []string
	for label, _ := range shares {
		all_x = append(all_x, label)

		// ...find the number of parts it represents...
		share := shares[label]
		// ...and for each part, find the x,y pair...
		secrets[label] = make([]*big.Int, 2)
		secrets[label][0] = share.X
		secrets[label][1] = share.Y
	}

	// Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secret.
	// For each part of the secert (clearest to iterate over)...
	var secret *big.Int
	secret = big.NewInt(0)
	// ...and every share...
	for i := range secrets { // LPI sum loop
		// ...remember the current x and y values...
		curr_x := secrets[i][0]
		curr_y := secrets[i][1]

		numerator, denominator := CalBs(all_x, curr_x.String(), curveType)
		// LPI product
		working := CalFinal(curr_y, numerator, denominator, curveType)
		// LPI sum
		secret = secret.Add(secret, working)
		secret = secret.Mod(secret, prime)
	}

	// ...and return the result!
	return secret, nil
}

//threshhold，计算下标为label的节点的bs值
func CalBs(participate []string, label string, curveType CurveType) (*big.Int, *big.Int) {
	prime := GetPrime(curveType)
	origin, _ := big.NewInt(0).SetString(label, 10)
	numerator := big.NewInt(1)      // LPI numerator
	denominator := big.NewInt(1)    // LPI denominator
	for _, v := range participate { // LPI product loop
		if label != v {
			// ...combine them via half products...
			current, _ := big.NewInt(0).SetString(v, 10)
			negative := big.NewInt(0)
			negative = negative.Mul(current, big.NewInt(-1))
			added := big.NewInt(0)
			added = added.Sub(origin, current)

			numerator = numerator.Mul(numerator, negative)
			numerator = numerator.Mod(numerator, prime)

			denominator = denominator.Mul(denominator, added)
			denominator = denominator.Mod(denominator, prime)
		}
	}
	return numerator, denominator
}

func CalFinal(secret, numerator, denominator *big.Int, curveType CurveType) *big.Int {
	prime := GetPrime(curveType)
	// ...multiply together the points (y)(numerator)(denominator)^-1...
	working := new(big.Int).Mul(secret, numerator)
	working = working.Mul(working, modInverse(denominator, curveType))
	working = working.Mod(working, prime)
	return working
}

//The logic is the same as CalFinal, but we didn't apply the mul Y here.
func CalLi(numerator, denominator *big.Int, curveType CurveType) *big.Int {
	prime := GetPrime(curveType)
	working := new(big.Int).Set(numerator)
	working = working.Mul(working, modInverse(denominator, curveType))
	working = working.Mod(working, prime)
	return working
}
