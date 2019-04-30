package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"os"
	"strconv"
)

type Mode int

const (
	Encrypt Mode = 0
	Decrypt Mode = 1
)

var ftable = []uint8{0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
	0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
	0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
	0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
	0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
	0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
	0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
	0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
	0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
	0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
	0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
	0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
	0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
	0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
	0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
	0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46}

type twofish struct {
	keysize        int // size in bytes
	mode           Mode
	verbose        bool
	key            []byte
	keyBlock       []uint16
	keyFilepath    string
	outputFilepath string
	inputFile      *os.File
	outputFile     *os.File
	keyFile        *os.File
}

// Logging method that prints to console when verbose mode is set
func (tf *twofish) LogInfo(msg string, args ...interface{}) {
	if tf.verbose {
		fmt.Printf("log:    ")
		fmt.Printf(msg, args...)
		fmt.Printf("\n")
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Print("\n")
	fmt.Println("encryption mode:")
	fmt.Println("    twofish -e [-v] <text filepath> <key filepath> <output filepath>")
	fmt.Print("\n")
	fmt.Println("decryption mode:")
	fmt.Println("    twofish -d [-v] <ciphertext filepath> <key filepath> <output filepath>")
	fmt.Print("\n")
}

// Converts a 16-character hex string (64 bits)
// into four 16-bit integers and stores them in res.
func hexToInt(hexKey string, res []uint16) {
	for i := 0; i < 4; i++ {
		n1, _ := strconv.ParseInt(hexKey[i*4:i*4+2], 16, 16)
		n2, _ := strconv.ParseInt(hexKey[i*4+2:i*4+4], 16, 16)
		res[i] = ((res[i] | uint16(n1)) << 8) | uint16(n2)
	}
}

// Concatenates four 16-bit integers into one 64-bit integer.
// Returns the new uint64 integer.
func keyBlockToInt64(keyblock []uint16) uint64 {
	var ans uint64
	ans = (uint64(keyblock[0]) | ans) << 16
	ans = (uint64(keyblock[1]) | ans) << 16
	ans = (uint64(keyblock[2]) | ans) << 16
	ans = uint64(keyblock[3]) | ans
	return ans
}

// Converts a unsigned 64-bit integer into
// a slice of four 16-bit integers.
func int64ToKeyBlock(num uint64, keyblock []uint16) {
	keyblock[3] = uint16(num) | keyblock[3]
	num >>= 16
	keyblock[2] = uint16(num) | keyblock[2]
	num >>= 16
	keyblock[1] = uint16(num) | keyblock[1]
	num >>= 16
	keyblock[0] = uint16(num) | keyblock[0]
}

// Attempts to read 8 characters and convert them
// into 4 16-bit integers. If there are less than 8 characters
// left in the file, the rightmost bits of the words are set to zero.
// Returns a uint16 slice of length 4.
func getBlock(textFile *os.File) []uint16 {
	buf := make([]byte, 8)
	_, err := textFile.Read(buf)
	if err != nil {
		return nil
	}

	words := make([]uint16, 4)
	words[0] = binary.BigEndian.Uint16(buf[:2])
	words[1] = binary.BigEndian.Uint16(buf[2:4])
	words[2] = binary.BigEndian.Uint16(buf[4:6])
	words[3] = binary.BigEndian.Uint16(buf[6:8])
	return words
}

// getKey attempts to read 16 characters from keyFile.
// Each character in the file represents a 16-bit hex value.
// It returns the number of characters read from keyFile
func getKey(keyFile *os.File, buf []byte) int {
	n, err := keyFile.Read(buf)

	if err != nil {
		fmt.Printf("Read error: %v\n", err)
		return -1
	}

	keyFile.Close()
	return n
}

// returns true if the filename is a file
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}

	return !info.IsDir()
}

// Generates a random hex string of the length of the byte array
// and stores it in a new key file specified by tf.keyFilepath.
//
// Note: generateKey is only ever called if the user-specified file
//       of a key does not exist and needs created.
//
// Returns the length of the generated key or -1 upon error.
func generateKey(tf *twofish, buf []byte) int {
	var n int

	// Generate random key
	if n, err := rand.Read(buf); err != nil || n != tf.keysize {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return -1
	}
	tf.key = buf

	// Create the new file and write the key
	f, err := os.Create(tf.keyFilepath)
	checkError(err)

	_, err = f.Write(buf)
	checkError(err)

	tf.LogInfo("Generated key of size %d", n)
	tf.LogInfo("Stored at file: %s", tf.keyFilepath)
	f.Close()
	return len(buf)
}

// Generates twelve 8-bit subkeys for f() and g() rounds
// and updates the 64-bit key by shifting 1 bit for each subkey generated.
// Returns an 8-bit integer slice of twelve subkeys
func generateSubkeys(round int, subkeys []uint8, tf *twofish) {
	key := keyBlockToInt64(tf.keyBlock)

	index := 0

	if tf.mode == Encrypt {
		for i := 0; i < 4; i++ {
			subkeys[index] = k(&key, 4*round+i)
			index++
		}

		for i := 0; i < 4; i++ {
			subkeys[index] = k(&key, 4*round+i)
			index++
		}

		for i := 0; i < 4; i++ {
			subkeys[index] = k(&key, 4*round+i)
			index++
		}
	} else {

	}

	int64ToKeyBlock(key, tf.keyBlock)
}

// Updates the key by rotating to the left by 1 bit.
// Returns an 8-bit integer from the key by indexing into
// the key using 8-bit blocks and an index value 7 - (round % 8).
func k(key *uint64, round int) uint8 {
	*key = bits.RotateLeft64(*key, 1)
	var ans uint8

	for i := 0; i < round%8; i++ {
		*key = *key >> 8
	}
	return uint8(*key) | ans
}

// Initalizes remaining fields in tf by setting the key
// and the input/output file descriptors.
func parseArgs(tf *twofish) {
	if len(os.Args) < 5 {
		fmt.Println("Incorrect command-line arguments")
		printHelp()
		os.Exit(1)
	}

	flag := os.Args[1]
	if flag == "-e" {
		tf.mode = Encrypt
	} else if flag == "-d" {
		tf.mode = Decrypt
	} else {
		fmt.Println("Unknown encryption mode")
		os.Exit(1)
	}

	index := 2

	// Check verbose flag
	if os.Args[index] == "-v" {
		tf.verbose = true
		index++
	}

	// Get input file
	textFile, err := os.Open(os.Args[index])
	index++
	checkError(err)
	tf.inputFile = textFile

	// Check for key file/generate key
	keyFile, err := os.Open(os.Args[index])
	tf.keyFilepath = os.Args[index]
	keyBuf := make([]byte, 16)
	index++

	// Generate new key and file
	if err != nil {
		tf.LogInfo("%s does not exist", tf.keyFilepath)
		generateKey(tf, keyBuf)
		err = nil
	} else { // Read key from existing file
		tf.keyFile = keyFile
		n := getKey(tf.keyFile, keyBuf)
		if n != tf.keysize {
			fmt.Printf("key size must be 8 bytes\n")
			os.Exit(1)
		}
		tf.key = keyBuf
	}

	hexToInt(string(tf.key), tf.keyBlock)
	tf.LogInfo("key words: %d %d %d %d", tf.keyBlock[0],
		tf.keyBlock[1], tf.keyBlock[2], tf.keyBlock[3])

	// Open output file
	tf.outputFile, err = os.Open(os.Args[index])
	tf.outputFilepath = os.Args[index]

	// Already a ciphertext file, kill the program
	if err == nil {
		fmt.Fprintf(os.Stderr, "Already a cipertext file created at %s\n", tf.outputFilepath)
		fmt.Fprintf(os.Stderr, "Delete the ciphertext file to resume encryption")
		tf.inputFile.Close()
		tf.outputFile.Close()
		os.Exit(1)
	}
	err = nil

	tf.outputFile, err = os.Create(tf.outputFilepath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		tf.inputFile.Close()
		tf.outputFile.Close()
		os.Exit(1)
	}
}

// Permutates the 16-bit word using 4 subkeys.
// Returns a new 16-bit integer
func g(round int, word uint16, subkeys []uint8) uint16 {
	var g1, g2 uint8

	g2 = g2 | uint8(word)
	word >>= 8
	g1 = g1 | uint8(word)
	g3 := (g2 ^ subkeys[0]) ^ g1
	g4 := (g3 ^ subkeys[1]) ^ g2
	g5 := (g4 ^ subkeys[2]) ^ g3
	g6 := (g5 ^ subkeys[3]) ^ g4
	var ans uint16
	ans |= uint16(g5)
	ans <<= 8
	ans |= uint16(g6)
	return ans
}

func f(round int, r0, r1 uint16, tf *twofish) (uint16, uint16) {
	subkeys := make([]uint8, 12)
	generateSubkeys(round, subkeys, tf)

	t0 := g(round, r0, subkeys[0:4])
	t1 := g(round, r1, subkeys[4:8])

	var t3, t4 uint16
	t3 |= uint16(subkeys[8])
	t3 <<= 8
	t3 |= uint16(subkeys[9])
	t4 |= uint16(subkeys[10])
	t4 <<= 8
	t4 |= uint16(subkeys[11])

	f0 := uint32(t0+2*t1+t3) % uint32(math.Pow(2, 16))
	f1 := uint32(2*t0+t1+t4) % uint32(math.Pow(2, 16))
	fmt.Printf("f0 = %d, f1 = %d\n", f0, f1)
	return uint16(f0), uint16(f1)
}

// Reads and encrypts 64 bits of the input file at a time and writes
// the result block to the output file. Each block goes through 16 rounds
// of transformations.
func twofishEncrypt(tf *twofish) {
	block := getBlock(tf.inputFile)
	var res uint64
	for block != nil {

		// whitening step
		r0 := block[0] ^ tf.keyBlock[0]
		r1 := block[1] ^ tf.keyBlock[1]
		r2 := block[2] ^ tf.keyBlock[2]
		r3 := block[3] ^ tf.keyBlock[3]
		round := 0

		for round < 16 {
			f0, f1 := f(round, r0, r1, tf)
			r0_temp := bits.RotateLeft16(r2^f0, -1)
			r1_temp := bits.RotateLeft16(r3, 1) ^ f1
			r2 = r0
			r3 = r1
			r0 = r0_temp
			r1 = r1_temp
			round++
		}

		res |= uint64(r2 ^ tf.keyBlock[0])
		res <<= 16
		res |= uint64(r3 ^ tf.keyBlock[1])
		res <<= 16
		res |= uint64(r0 ^ tf.keyBlock[2])
		res <<= 16
		res |= uint64(r1 ^ tf.keyBlock[3])
		outputBlock := make([]byte, 8)
		binary.BigEndian.PutUint64(outputBlock, res)

		n, err := tf.outputFile.Write(outputBlock)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		tf.LogInfo("Wrote %d bytes to output file", n)
		block = getBlock(tf.inputFile)
	}
	tf.outputFile.Close()
}

func twofishDecrypt(tf *twofish) {
	fmt.Printf("Decrypt\n")
}

func main() {
	tf := twofish{
		keyBlock: make([]uint16, 4),
		keysize:  16,
		verbose:  false}

	parseArgs(&tf)

	if tf.mode == Encrypt {
		twofishEncrypt(&tf)
	} else if tf.mode == Decrypt {
		twofishDecrypt(&tf)
	}
}
