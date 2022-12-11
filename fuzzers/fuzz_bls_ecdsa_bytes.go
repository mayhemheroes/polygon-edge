package myfuzz

import (
	"github.com/0xPolygon/polygon-edge/validators"
	"github.com/0xPolygon/polygon-edge/types"
)

func Fuzz(data []byte) int {
	validatorsTest := []struct {
		name          string
		validatorType validators.ValidatorType
		expected      validators.Validator
		err           error
	}{
		{
			name:          "ECDSAValidator",
			validatorType: validators.ECDSAValidatorType,
			expected:      new(validators.ECDSAValidator),
			err:           nil,
		},
		{
			name:          "BLSValidator",
			validatorType: validators.BLSValidatorType,
			expected:      new(validators.BLSValidator),
			err:           nil,
		},
	}

	validator, err := validators.NewValidatorFromType(validatorsTest[1].validatorType)
	if err != nil { return 1}

	// setfrombytes used for BLS
	// types.bytestoaddress used for ECDSA
	// NOTE: modify validatorsTest[0] for testing ecdsa
	
	switch typedVal := validator.(type) {
	case *validators.ECDSAValidator:
		typedVal.Address = types.BytesToAddress(data)
  	case *validators.BLSValidator:
	  	ok := typedVal.SetFromBytes(data)
	  	if ok != nil {return 1}
	}
	return 0
}
