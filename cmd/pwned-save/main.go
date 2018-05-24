package main

import (
	"flag"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/pedrosland/pwned-check"
)

func main() {
	var savePath string
	var importPasswordPaths string
	var numHashes int64
	var falsePositiveRate int

	flag.StringVar(&savePath, "save-file", "", "File to save filter")
	flag.StringVar(&importPasswordPaths, "import-file", "", "Password file to import. Can be comma separated list")
	flag.Int64Var(&numHashes, "num-passwords", 502000000, "Number of password hashes in the files")
	flag.IntVar(&falsePositiveRate, "false-positive-rate", 1000000, "Acceptable false positive rate (1/n)")
	flag.Parse()

	if savePath == "" {
		fmt.Println("please specify a file to save to save the filter to")
		flag.Usage()
		return
	}
	if importPasswordPaths == "" {
		fmt.Println("please specify a password hash file to import")
		flag.Usage()
		return
	}

	cancelPrinter := startPrinter()
	defer cancelPrinter()

	filter := pwned.NewFilter(int(numHashes), falsePositiveRate)

	paths := strings.Split(importPasswordPaths, ",")
	for _, path := range paths {
		pwned.ImportPasswordFile(filter, numHashes, path)
	}

	pwned.SaveFilterToFile(filter, savePath)
}

func startPrinter() func() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				// fmt.Println(".")
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				fmt.Printf("Alloc: %d, StackInuse: %d, HeapAlloc: %d, TotalAlloc: %d\n", bToMb(m.Alloc), bToMb(m.StackInuse), bToMb(m.HeapAlloc), bToMb(m.TotalAlloc))
			}
		}
	}()
	return ticker.Stop
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}
