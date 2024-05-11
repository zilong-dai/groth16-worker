package main

import (
	"github.com/zilong-dai/gorth16-worker/rpc"
	"github.com/zilong-dai/gorth16-worker/utils"
)

func main() {
	if ws, err := rpc.NewWorkerService(utils.CURVE_ID); err != nil {
		panic(err)
	} else {
		ws.Run(6666)
	}

}
