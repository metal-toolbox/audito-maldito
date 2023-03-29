package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
)

var count = 0

func main() {
	var mtx sync.Mutex
	// API routes
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var num = 0
		mtx.Lock()
		{
			count++
			num = count
		}
		mtx.Unlock()

		var b []byte
		b, err := ioutil.ReadAll(r.Body)

		if err != nil {
			fmt.Println("Error reading bytes")
		}
		fmt.Printf("log %d: %s\n\n", num, b)
		fmt.Fprintf(w, "service called\n")

		// Push to channel here
	})

	port := ":5000"
	fmt.Println("Server is running on port" + port)

	// Start server on port specified above
	log.Fatal(http.ListenAndServe(port, nil))
}
