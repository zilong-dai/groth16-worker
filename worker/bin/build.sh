go build main.go

# circuit setup
echo "build circuit, setup pk, vk, save pk, vk, circuit in data dir"
./main build --data ../testdata

# prove
echo "start proving, circuit, pk must exist in data dir"
./main prove --data ../testdata

# verify
echo "start verifying, vk, proof, public_inputs must exist in data dir"
./main prove --data ../testdata