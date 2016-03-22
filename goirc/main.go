package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	_ "net/http/pprof"

	"github.com/matt3o12/dailyprogrammer/258_irc"
)

func main() {
	go func() {
		err := http.ListenAndServe("localhost:6061", nil)
		log.Println(err)
		if err != nil {
			log.Println(http.ListenAndServe("localhost:6062", nil))
		}

	}()

	name := fmt.Sprintf("unkown_%v", time.Now().Unix())
	s := irc.NewClient("irc.freenode.org:6667", name, name, name)
	err := s.Connect()
	defer s.Close()
	fmt.Println(err)
	time.Sleep(20 * time.Minute)
}
