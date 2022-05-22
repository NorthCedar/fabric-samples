package main

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

type TpsTestChaincode struct {
}

func (t *TpsTestChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Success(nil)
}

func (t *TpsTestChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	_, args := stub.GetFunctionAndParameters()

	Aval, _ := strconv.Atoi(args[0])
	Bval, _ := strconv.Atoi(args[1])
	Cval := uint32(Aval + Bval)

	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], Cval)

	err := stub.PutState(args[2], b[:])
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(nil)
}

func main() {
	err := shim.Start(new(TpsTestChaincode))
	if err != nil {
		fmt.Printf("Error starting TpsTest chaincode: %s", err)
	}
}
