package main

import (
	"github.com/Alexxanddr/k8s-vpn-gateway/internal/admission"
	"github.com/Alexxanddr/k8s-vpn-gateway/internal/network"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: gateway admission|client|guard|overlay")
	}
	var err error
	switch os.Args[1] {
	case "admission":
		err = admission.Serve()
	case "client":
		err = network.Client()
	case "guard":
		err = network.GatewayGuard()
	case "overlay":
		err = network.Overlay()
	default:
		log.Fatal("unknown mode")
	}
	if err != nil {
		log.Fatal(err)
	}
}
