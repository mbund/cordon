package main

import (
	"fmt"
	"time"
)

func main() {
	fmt.Println("Sleeping forever...")
	for {
		time.Sleep(1 * time.Hour)
	}
}
