package dsign

import "math/big"

func getCoeff(nodeList []string) []*big.Int {
	coeff := make([]*big.Int, len(nodeList))
	for i := range nodeList {
		c, _ := big.NewInt(0).SetString(nodeList[i], 10)
		coeff[i] = c
	}
	return coeff
}

func isInList(s string, list []string) bool {
	for _, str := range list {
		if s == str {
			return true
		}
	}
	return false
}

func getMissingStrings(has []string, all []string) []string {
	var missing []string
	for _, n := range all {
		var found bool
		for _, s := range has {
			if s == n {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, n)
		}
	}
	return missing
}
