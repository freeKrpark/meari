package main

import (
	"fmt"
	"log"
	"os"

	"github.com/freekrpark/meari/internal/seizure"
)

func main() {
	sc, err := seizure.RunScenario()
	if err != nil {
		log.Fatal(err)
	}
	r := seizure.Analyze(sc.Server.Seize())
	r.Write(os.Stdout, sc.Names)

	found, total := sc.Score(r)
	fmt.Printf("\n## Score\n\nRecovered %d of %d real contacts.\n", found, total)

}
