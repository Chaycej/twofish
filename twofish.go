package main

import (
	"crypto/rand"
	"fmt"
	"os"
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

func twofishEncrypt(tf *twofish) {
	fmt.Printf("encrypt\n")
}

func twofishDecrypt(tf *twofish) {
	fmt.Printf("Decrypt\n")
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
	return len(buf)
}

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
		tf.LogInfo("Read key from %s", os.Args[index-1])
	}
}

func main() {
	tf := twofish{keysize: 16, verbose: false}

	parseArgs(&tf)

	fmt.Printf("Key: %s\n", tf.key)

	// Encryption mode
	if tf.mode == Encrypt {
		twofishEncrypt(&tf)
	} else if tf.mode == Decrypt {
		twofishDecrypt(&tf)
	}
}
