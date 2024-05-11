# groth16-worker

reference: https://github.com/succinctlabs/sp1/tree/main/recursion/gnark

## Usage

### rust
```rust
// main.rs
use groth16_worker::Groth16Prover;

fn main(){
    // build dir must contain proof_with_public_inputs.json, verifier_only_circuit_data.json, common_circuit_data.json
    // build circuit, setup pk, vk, save pk, vk, circuit in data dir
    let build_dir = "./testdata";
    Groth16Prover::build(build_dir);

    // start proving, circuit, pk must exist in data dir
    let prover = Groth16Prover::new();
    prover.prove(build_dir);

    // start verifying, vk, proof, public_inputs must exist in data dir
    prover.verify(build_dir);
}
```

Cargo.toml
```
[dependencies]
groth16-worker = {git = "https://github.com/zilong-dai/groth16-worker", branch = "dev"}
```

### rpc server

server: `go run rpc/bin/rpc_server.go` or 
```go
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

```

client
```go
package main

import (
	"fmt"
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:6666")
	if err != nil {
		log.Fatal("dialing:", err)
	}

	client := rpc.NewClientWithCodec(jsonrpc.NewClientCodec(conn))
	var reply string
	args := "./testdata"
	err = client.Call("WorkerService.Verify", &args, &reply)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(reply)
}
```