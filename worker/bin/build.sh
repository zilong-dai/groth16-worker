go build cmd/local_worker.go

# circuit setup
echo "build circuit, setup pk, vk, save pk, vk, circuit in data dir"
./local_worker build --data ../testdata

# prove
echo "start proving, circuit, pk must exist in data dir"
./local_worker prove --data ../testdata

# verify
echo "start verifying, vk, proof, public_inputs must exist in data dir"
./local_worker prove --data ../testdata