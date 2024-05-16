package rpc

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
)

func (ws *WorkerService) Run(port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatal("listen error:", err)
	}

	rpc.RegisterName("WorkerService", ws)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("accept error:", err)
			continue
		}

		go rpc.ServeCodec(jsonrpc.NewServerCodec(conn))
	}

}

func (ws *WorkerService) Build(args []string, reply *string) error {
	if len(args) != 3 {
		return errors.New("arg is not 3")
	}

	if ws.worker == nil {
		return errors.New("worker is nil")
	}

	*reply = ws.worker.Build(args[0], args[1], args[2])

	return nil
}

func (ws *WorkerService) GenerateProof(args []string, reply *string) error {
	if len(args) != 3 {
		return errors.New("arg is not 3")
	}

	if ws.worker == nil {
		return errors.New("worker is nil")
	}

	*reply = ws.worker.GenerateProof(args[0], args[1], args[2])
	return nil
}

func (ws *WorkerService) VerifyProof(args *string, reply *string) error {
	fmt.Println(args)
	if args == nil {
		return errors.New("args is nil")
	}
	if *args == "" {
		return errors.New("proofString is empty")
	}
	if ws.worker == nil {
		return errors.New("worker is nil")
	}

	*reply = ws.worker.VerifyProof(*args)

	return nil
}
