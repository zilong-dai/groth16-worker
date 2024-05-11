package rpc

import (
	"errors"
	"fmt"
)

func (ws *WorkerService) Build(args *string, reply *string) error {
	if args == nil {
		return errors.New("args is nil")
	}
	if *args == "" {
		return errors.New("proofDataPath is empty")
	}
	if ws.worker == nil {
		return errors.New("worker is nil")
	}

	if err := ws.worker.Build(*args); err != nil {
		*reply = "false"
		return fmt.Errorf("setup failed: %w", err)
	}
	*reply = "true"
	return nil
}

func (ws *WorkerService) Prove(args *string, reply *string) error {
	if args == nil {
		return errors.New("args is nil")
	}
	if *args == "" {
		return errors.New("proofDataPath is empty")
	}
	if ws.worker == nil {
		return errors.New("worker is nil")
	}

	if err := ws.worker.Prove(*args); err != nil {
		*reply = "false"
		return fmt.Errorf("proof failed: %w", err)
	}
	*reply = "true"
	return nil
}

func (ws *WorkerService) Verify(args *string, reply *string) error {
	if args == nil {
		return errors.New("args is nil")
	}
	if *args == "" {
		return errors.New("proofDataPath is empty")
	}
	if ws.worker == nil {
		return errors.New("worker is nil")
	}

	if err := ws.worker.Verify(*args); err != nil {
		*reply = "false"
		return fmt.Errorf("verify failed: %w", err)
	}
	*reply = "true"
	return nil
}
