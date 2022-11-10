package cryptoutils

import (
	"bytes"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// function performs right padding using zeros to the size of the blockSize param.
func paddingZeros(data []byte, blockSize int) []byte {
	dataLength := len(data)
	padding := bytes.Repeat([]byte{0}, blockSize-dataLength%blockSize)
	data = append(data, padding...)

	return data
}

// function performs right unpadding by removing all zeros from the right
func unpaddingZeros(data []byte) []byte {
	data = bytes.TrimFunc(data, func(r rune) bool {
		return r == rune(0)
	})

	return data
}

// function performs xor operation on provided slices of bytes.
// Slices need to be of the same length
func xorByteSlices(b1, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return nil, errors.New("byte slices length mismatch")
	}

	result := make([]byte, len(b1))

	for i := range b1 {
		result[i] = b1[i] ^ b2[i]
	}

	return result, nil
}

// function generates random slice of bytes of the length n
func genRandomHex(n int) ([]byte, error) {
	randomBytes := make([]byte, n)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	return randomBytes, nil
}

// functions calculates 3DES (but double length) Key Check Value
func calculateKCV(key []byte) ([]byte, error) {
	fakeData, err := hex.DecodeString("00000000000000000000000000000000")
	if err != nil {
		return nil, err
	}

	tripleKey := make([]byte, 16, 16)
	copy(tripleKey, key)
	k1 := tripleKey[:8]
	k2 := tripleKey[8:]

	buffer1, err := encrypt(fakeData, k1)
	if err != nil {
		return nil, err
	}
	buffer2, err := decrypt(buffer1, k2)
	if err != nil {
		return nil, err
	}
	kcv, err := encrypt(buffer2, k1)
	if err != nil {
		return nil, err
	}

	return kcv[:3], nil
}

// function performs standard single DES encryption
func encrypt(clearData, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()

	if len(clearData)%bs != 0 {
		clearData = paddingZeros(clearData, bs)
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

// function performs standard single DES decryption
func decrypt(encryptedData, key []byte) ([]byte, error) {
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

	return unpaddingZeros(output), nil
}

// function performs DESede encryption with padding
func DESedeECBEnrypt(clearData, key []byte) ([]byte, error) {
	tripleKey := make([]byte, 24, 24)
	copy(tripleKey, key)
	k1 := tripleKey[:8]
	k2 := tripleKey[8:16]
	k3 := tripleKey[16:]

	// ecryption process
	// first we need to encrypt the original data with first part of the key (first 8 bytes).
	buffer1, err := encrypt(clearData, k1)
	if err != nil {
		return nil, err
	}
	// now, we need to decrypt data encrypted in first step using the second part fo the key (8-16 bytes)
	buffer2, err := decrypt(buffer1, k2)
	if err != nil {
		return nil, err
	}
	// now we need to encrypte the result from the above step with third part of the key (16: bytes)
	result, err := encrypt(buffer2, k3)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// function performs DESede decryption with unpadding
func DESedeECBDecrypt(encData, key []byte) ([]byte, error) {
	tripleKey := make([]byte, 24, 24)
	copy(tripleKey, key)
	k1 := tripleKey[:8]
	k2 := tripleKey[8:16]
	k3 := tripleKey[16:]

	// decryption process
	// first we need to decrypte provided data with the last part of the key (16: bytes)
	buffer1, err := decrypt(encData, k3)
	if err != nil {
		return nil, err
	}
	// now we need to encrypt buffer1 using second part of the key (8-16 bytes)
	buffer2, err := encrypt(buffer1, k2)
	if err != nil {
		return nil, err
	}
	// now we need to decrypt buffer2 with the first part of the key (:8 bytes)
	result, err := decrypt(buffer2, k1)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// function performs splitting double-length 3DES key into 3 components
func splitKey(key []byte) ([][]byte, error) {
	var keyComponents [][]byte

	kc1, err := genRandomHex(16)
	if err != nil {
		return nil, err
	}
	kc2, err := genRandomHex(16)
	if err != nil {
		return nil, err
	}

	interim, err := xorByteSlices(key, kc1)
	if err != nil {
		return nil, err
	}
	kc3, err := xorByteSlices(interim, kc2)
	if err != nil {
		return nil, err
	}

	keyComponents = append(keyComponents, kc1)
	keyComponents = append(keyComponents, kc2)
	keyComponents = append(keyComponents, kc3)

	return keyComponents, nil
}

// function combines 3 components into double-length 3DES key
func combineKey(keyComponents [][]byte) ([]byte, error) {
	kc1 := keyComponents[0]
	kc2 := keyComponents[1]
	kc3 := keyComponents[2]

	interim, err := xorByteSlices(kc3, kc2)
	if err != nil {
		return nil, err
	}
	key, err := xorByteSlices(interim, kc1)
	if err != nil {
		return nil, err
	}

	return key, nil
}
