package main

import (
	"fmt"
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

	err := stub.PutState(args[0], []byte(args[1]))
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
