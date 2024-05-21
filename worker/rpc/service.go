package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"time"
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

func (ws *WorkerService) GenerateProof(args []string, reply *string) error {
	if len(args) != 3 {
		return errors.New("arg is not 3")
	}

	if ws.worker == nil {
		return errors.New("worker is nil")
	}

	if !ws.worker.IsSetup {
		*reply = ws.worker.Build(args[0], args[1], args[2])
		if *reply != "true" {
			return errors.New("build failed")
		}
		ws.worker.IsSetup = true
	}

	*reply = ws.worker.GenerateProof(args[0], args[1], args[2])
	return nil
}

func (ws *WorkerService) VerifyProof(args *string, reply *string) error {
	fmt.Println("call verifyProof", time.Now())
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

func (ws *WorkerService) GetVK(args *string, reply *string) error {
	if args == nil {
		return errors.New("args is nil")
	}
	if *args == "" {
		return errors.New("proofString is empty")
	}
	if ws.worker == nil || ws.worker.vk == nil {
		return errors.New("worker is nil")
	}

	vkBytes, err := json.Marshal(ws.worker.vk)
	if err != nil {
		*reply = "false"
		return fmt.Errorf("failed to marshal vk: %v", err)
	}
	*reply = string(vkBytes)
	return nil
}
