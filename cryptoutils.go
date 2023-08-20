package cryptoutils

import (
	"bytes"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// PaddingZeros function performs right padding using zeros to the size of the blockSize param.
func PaddingZeros(data []byte, blockSize int) []byte {
	dataLength := len(data)
	padding := bytes.Repeat([]byte{0}, blockSize-dataLength%blockSize)
	data = append(data, padding...)

	return data
}

// UnpaddingZeros function performs right unpadding by removing all zeros from the right
func UnpaddingZeros(data []byte) []byte {
	data = bytes.TrimFunc(data, func(r rune) bool {
		return r == rune(0)
	})

	return data
}

// XorByteSlices function performs xor operation on provided slices of bytes.
// Slices need to be of the same length.
func XorByteSlices(b1, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return nil, errors.New("byte slices length mismatch")
	}

	result := make([]byte, len(b1))

	for i := range b1 {
		result[i] = b1[i] ^ b2[i]
	}

	return result, nil
}

// GenRandomHex function generates random slice of bytes of the length n
func GenRandomHex(n int) ([]byte, error) {
	randomBytes := make([]byte, n)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	return randomBytes, nil
}

// CalculateKCV function calculates double-length 3DES Key Check Value
func CalculateKCV(key []byte) ([]byte, error) {
	fakeData, err := hex.DecodeString("00000000000000000000000000000000")
	if err != nil {
		return nil, err
	}

	// tripleKey := make([]byte, 16, 16)
	tripleKey := make([]byte, 16)
	copy(tripleKey, key)
	k1 := tripleKey[:8]
	k2 := tripleKey[8:]

	buffer1, err := Encrypt(fakeData, k1)
	if err != nil {
		return nil, err
	}
	buffer2, err := Decrypt(buffer1, k2)
	if err != nil {
		return nil, err
	}
	kcv, err := Encrypt(buffer2, k1)
	if err != nil {
		return nil, err
	}

	return kcv[:3], nil
}

// Encrypt function performs standard single DES encryption
func Encrypt(clearData, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()

	if len(clearData)%bs != 0 {
		clearData = PaddingZeros(clearData, bs)
	}

	output := make([]byte, len(clearData))
	tmp := output

	for len(clearData) > 0 {
		block.Encrypt(tmp, clearData[:bs])
		clearData = clearData[bs:]
		tmp = tmp[bs:]
	}

	return output, nil
}

// Decrypt function performs standard single DES decryption
func Decrypt(encryptedData, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()
	output := make([]byte, len(encryptedData))
	tmp := output

	for len(encryptedData) > 0 {
		block.Decrypt(tmp, encryptedData[:bs])
		encryptedData = encryptedData[bs:]
		tmp = tmp[bs:]
	}

	return UnpaddingZeros(output), nil
}

// DESedeECBEnrypt function performs DESede encryption with padding
func DESedeECBEnrypt(clearData, key []byte) ([]byte, error) {
	// tripleKey := make([]byte, 24, 24)
	tripleKey := make([]byte, 24)
	copy(tripleKey, key)
	k1 := tripleKey[:8]
	k2 := tripleKey[8:16]
	k3 := tripleKey[16:]

	// encryption process
	// first we need to Encrypt the original data with first part of the key (first 8 bytes).
	buffer1, err := Encrypt(clearData, k1)
	if err != nil {
		return nil, err
	}
	// now, we need to Decrypt data encrypted in first step using the second part of the key (8-16 bytes)
	buffer2, err := Decrypt(buffer1, k2)
	if err != nil {
		return nil, err
	}
	// now we need to encrypt the result from the above step with third part of the key (16: bytes)
	result, err := Encrypt(buffer2, k3)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// DESedeECBDecrypt function performs DESede decryption with unpadding
func DESedeECBDecrypt(encData, key []byte) ([]byte, error) {
	// tripleKey := make([]byte, 24, 24)
	tripleKey := make([]byte, 24)
	copy(tripleKey, key)
	k1 := tripleKey[:8]
	k2 := tripleKey[8:16]
	k3 := tripleKey[16:]

	// decryption process
	// first we need to decrypt provided data with the last part of the key (16: bytes)
	buffer1, err := Decrypt(encData, k3)
	if err != nil {
		return nil, err
	}
	// now we need to Encrypt buffer1 using second part of the key (8-16 bytes)
	buffer2, err := Encrypt(buffer1, k2)
	if err != nil {
		return nil, err
	}
	// now we need to Decrypt buffer2 with the first part of the key (:8 bytes)
	result, err := Decrypt(buffer2, k1)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// SplitKey function performs splitting double-length 3DES key into 3 components
func SplitKey(key []byte) ([][]byte, error) {
	var keyComponents [][]byte

	kc1, err := GenRandomHex(16)
	if err != nil {
		return nil, err
	}
	kc2, err := GenRandomHex(16)
	if err != nil {
		return nil, err
	}

	interim, err := XorByteSlices(key, kc1)
	if err != nil {
		return nil, err
	}
	kc3, err := XorByteSlices(interim, kc2)
	if err != nil {
		return nil, err
	}

	keyComponents = append(keyComponents, kc1)
	keyComponents = append(keyComponents, kc2)
	keyComponents = append(keyComponents, kc3)

	return keyComponents, nil
}

// CombineKey function combines 3 components into double-length 3DES key
func CombineKey(keyComponents [][]byte) ([]byte, error) {
	kc1 := keyComponents[0]
	kc2 := keyComponents[1]
	kc3 := keyComponents[2]

	interim, err := XorByteSlices(kc3, kc2)
	if err != nil {
		return nil, err
	}
	key, err := XorByteSlices(interim, kc1)
	if err != nil {
		return nil, err
	}

	return key, nil
}
