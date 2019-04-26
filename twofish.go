package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
)

type Mode int

const (
	Encrypt Mode = 0
	Decrypt Mode = 1
)

type twofish struct {
	mode       Mode
	verbose    bool
	keybuf     []byte
	inputFile  *os.File
	outputFile *os.File
}

// Logging method that prints to console when verbose mode is set
func (tf *twofish) LogInfo(msg string, args ...interface{}) {
	if tf.verbose {
		fmt.Printf(msg, args...)
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

}

// getKey attempts to read 16 characters from keyFile.
// Each character in the file represents a 16-bit hex value.
// It returns the number of characters read from keyFile
func getKey(keyFile os.File, buf []byte) int {
	n, err := keyFile.Read(buf)

	if err != nil {
		fmt.Printf("Read error: %v\n", err)
		return -1
	}

	return n
}

// Generates a random hex string of the length of the byte array
// Returns the length of the generated key or -1 upon error.
func generateKey(buf []byte) int {
	if _, err := rand.Read(buf); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return -1
	}

	return len(buf)
}

func main() {
	if len(os.Args) < 5 {
		fmt.Println("Incorrect command-line arguments")
		printHelp()
		os.Exit(1)
	}

	tf := twofish{verbose: false}
	flag := os.Args[1]

	// Check verbose flag
	if os.Args[2] == "-v" {
		tf.verbose = true
	}

	// Encryption mode
	if flag == "-e" {
		tf.mode = Encrypt

		textFile, err := os.Open(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		tf.inputFile = textFile

		keyFile, err := os.Open(os.Args[3])
		keyBuf := make([]byte, 16)

		if err != nil {
			fmt.Println("No key found, generating a new key")
			n := generateKey(keyBuf)
			log.Printf("Log: generated a key of size %d\n", n)
			fmt.Printf("Generated a key of size %d\n", n)
			fmt.Printf("%x\n", keyBuf)
		} else {
			n := getKey(*keyFile, keyBuf)
			fmt.Printf("%x\n", keyBuf)
			fmt.Printf("read %d bytes\n", n)
		}

		twofishEncrypt(&tf)
	}

	if flag != "-e" && flag != "-d" {
		fmt.Println("Unknown encryption mode")
		os.Exit(1)
	}

}
