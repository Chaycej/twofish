package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/bits"
	"os"
	"strconv"
)

type Mode int

const (
	Encrypt Mode = 0
	Decrypt Mode = 1
)

type twofish struct {
	keysize     int // size in bytes
	mode        Mode
	verbose     bool
	key         []byte
	keyBlock    []uint16
	keyFilepath string
	inputFile   *os.File
	outputFile  *os.File
	keyFile     *os.File
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
func generateSubkeys(round int, tf *twofish) {
	key := keyBlockToInt64(tf.keyBlock)
	subkeys := make([]uint8, 12)

	index := 0

	if tf.mode == Encrypt {
		for i := 0; i < 4; i++ {
			subkeys[index] = kEncrypt(&key, 4*round+i)
			index++
		}

		for i := 0; i < 4; i++ {
			subkeys[index] = kEncrypt(&key, 4*round+i)
			index++
		}

		for i := 0; i < 4; i++ {
			subkeys[index] = kEncrypt(&key, 4*round+i)
			index++
		}
	} else {

	}

	int64ToKeyBlock(key, tf.keyBlock)
}

// Updates the key by rotating to the left by 1 bit.
// Returns an 8-bit integer from the key by indexing into
// the key using 8-bit blocks and an index value 7 - (round % 8).
func kEncrypt(key *uint64, round int) uint8 {

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
}

func g(round, r0 int) {

}

func f(round, r0, r1 int) (int, int) {
	return 0, 0
}

func twofishEncrypt(tf *twofish) {
	//block := getBlock(tf.inputFile)
	generateSubkeys(5, tf)
	// for block != nil {

	// 	// whitening step
	// 	r0 := block[0] ^ tf.keyBlock[0]
	// 	r1 := block[1] ^ tf.keyBlock[1]
	// 	r2 := block[2] ^ tf.keyBlock[2]
	// 	r3 := block[3] ^ tf.keyBlock[3]
	// 	round := 0

	// 	for round < 16 {

	// 	}

	// 	block = getBlock(tf.inputFile)
	// }
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
