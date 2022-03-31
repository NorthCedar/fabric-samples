package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
	"github.com/meshplus/crypto"
	"strings"
)

func main() {
	chaincode := &ProxyChaincode{
		CircuitIDHex: "7e26dd7b8c18330ef2deca19afb0cae29da2e97f3fdff41d74c96cf9d88064bc",
		VK:           _vk,
		PK:           _pk,
	}

	idBytes, err := hex.DecodeString(chaincode.CircuitIDHex)
	if err != nil || len(idBytes) > 32 {
		chaincode.log.Errorf("parse circuitID hex '%v' error: %s", chaincode.CircuitIDHex, err)
		return
	}
	copy(chaincode.CircuitID[:len(idBytes)], idBytes)

	chaincode.method = map[string]method{
		"finish":           chaincode.finish,
		"computeAndProve":  chaincode.computeAndProve,
		"verifyProof":      chaincode.verifyProof,
		"update":           chaincode.update,
		"deleteUnfinished": chaincode.deleteUnfinished,
		"getPK":            chaincode.getPK,
		"getVK":            chaincode.getVK,
	}
	err = shim.Start(chaincode)
	if err != nil {
		chaincode.log.Errorf("Error starting Simple chaincode: %s", err)
	}
}

const (
	statusPK = "statusPK"
	statusVK = "statusVK"
	VKTag    = "VKTag"

	statusTaskPrefix = "statusTaskPrefix"
	statusTaskRef    = "statusTaskPrefix~taskID"
)

type method func(stub shim.ChaincodeStubInterface, args []string) (string, error)

// ProxyChaincode implements a chaincode to proxy vc operation
type ProxyChaincode struct {
	PK           string   //base64
	VK           string   //base64
	CircuitIDHex string   //hex
	CircuitID    [32]byte //hex
	method       map[string]method
	log          *shim.ChaincodeLogger
}

//Init initial
func (p *ProxyChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	p.log = shim.NewLogger("proxy_chaincode")
	p.log.Notice("start init")
	pk, err := base64.URLEncoding.DecodeString(p.PK)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to decode pk: %s", err))
	}
	vk, err := base64.URLEncoding.DecodeString(p.VK)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to decode vk: %s", err))
	}

	// 在账本上设置PK和VK
	tag := getTag(vk)
	err = stub.PutState(VKTag, []byte(tag))
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to init vk tag: %s", err))
	}
	// 在账本上设置PK和VK
	err = stub.PutState(statusPK, pk)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to init pk: %s", err))
	}

	err = stub.PutState(statusVK+tag, vk)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to init vk: %s", err))
	}
	p.log.Noticef("init proxy chaincode success: %v", p.CircuitIDHex)
	return shim.Success(nil)
}

//Invoke call contract method
func (p *ProxyChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	fn, args := stub.GetFunctionAndParameters()
	if m, ok := p.method[fn]; ok {
		p.log.Noticef("=> invoke '%v' with arg %#v", fn, args)
		result, err := m(stub, args)
		if err != nil {
			return shim.Error(err.Error())
		}
		// return the result as success payload
		return shim.Success([]byte(result))
	}
	return shim.Error("unknown method name")
}

/*start a computation task
called by business contract
args:
	1. nonce as taskID
	2. public input & index of private input
	3. callback chaincode name and method name
step:
	1. check if taskID is duplicated
	2. write status: statusTaskIDPrefix || taskID => callback chaincode name and method name
	2. push a EVENT_COMPUTE event

note: callback args: taskID, result, proof
*/
func (p *ProxyChaincode) computeAndProve(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	//1.参数解析
	if len(args) < 6 {
		return "", fmt.Errorf("computeAndProve need 6 args: proxyContractAddr, input, businessContractAddr, businessContractMethod, WebHook and WebHookBodyPattern")
	}
	taskID, businessContractAddr, businessContractMethod := stub.GetTxID(), args[2], args[3]
	//2.记录合约层回调
	taskStatus, err := json.Marshal(statusTask{
		BusinessContractAddr:   businessContractAddr,
		BusinessContractMethod: businessContractMethod,
		PublicInput:            args[1],
	})
	if err != nil {
		p.log.Errorf("marshal task json error: %v", err)
		return "", fmt.Errorf("marshal task json error: %v", err)
	}
	p.log.Notice("json marshal success")
	key, _ := stub.CreateCompositeKey(statusTaskRef, []string{statusTaskPrefix, taskID})
	err = stub.PutState(key, taskStatus)
	if err != nil {
		p.log.Errorf("write to task status error: %v", err)
		return "", fmt.Errorf("write to task status error: %v", err)
	}
	p.log.Notice("write taskID to status success")
	//3.构造事件体
	event, err := json.Marshal(crypto.EventCompute{
		TaskID:                 taskID,
		CircuitID:              p.CircuitID,
		CCName:                 args[0],
		WebHook:                args[4],
		WebHookBodyPattern:     args[5],
		BusinessContractAddr:   businessContractAddr,
		BusinessContractMethod: businessContractMethod,
		Input:                  args[1],
	})
	if err != nil {
		p.log.Errorf("marshal event json error: %v", err)
		return "", fmt.Errorf("marshal event json error: %v", err)
	}

	return string(event), nil
}

type statusTask struct {
	BusinessContractAddr   string "json:\"businessContractAddr\""
	BusinessContractMethod string "json:\"businessContractMethod\""
	PublicInput            string "json:\"publicInput\""
}

/*computational task has been finished
args:
	1. taskID
	2. result
	3. proof
step:
	1. verify proof
	2. get callback chaincode name and method name from taskID
	3. callback

callback function should also receive 3 args like finish method, and at same channel
*/
func (p *ProxyChaincode) finish(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	//1.解析参数
	if len(args) < 4 {
		return "", fmt.Errorf("finish need 3 args: taskID, result, proof and error")
	}
	taskID, result, proof, msg := args[0], args[1], args[2], args[3]
	var task statusTask
	key, _ := stub.CreateCompositeKey(statusTaskRef, []string{statusTaskPrefix, taskID})
	taskStatus, err := stub.GetState(key)
	if err != nil || taskStatus == nil {
		p.log.Errorf("unknown taskID '%v': %v", taskID, err)
		return "", fmt.Errorf("unknown taskID '%v': %v", taskID, err)
	}
	p.log.Notice("get task success")
	err = json.Unmarshal(taskStatus, &task)
	if err != nil {
		p.log.Errorf("unmarshal taskStatus error: %v", err)
		msg = fmt.Sprintf("unmarshal taskStatus error: %v", err)
	}
	p.log.Notice("marshal task success")
	//2.调用系统合约验证证明
	if len(msg) == 0 {
		p.log.Notice("start verify proof")
		_, err = p.verifyProof(stub, []string{result, task.PublicInput, proof})
		if err != nil {
			p.log.Errorf("verify proof error: %v", err)
			msg = fmt.Sprintf("verify proof (tID:'%v')error: %v", taskID, err)
		}
	}

	//3.回调业务合约
	var response pb.Response
	if len(task.BusinessContractAddr) > 0 && len(task.BusinessContractMethod) > 0 {
		p.log.Noticef("start callback: [%v] : [%v]", task.BusinessContractAddr, task.BusinessContractMethod)
		if len(msg) == 0 { //计算并且验证正确
			response = stub.InvokeChaincode(task.BusinessContractAddr, [][]byte{
				[]byte(task.BusinessContractMethod), []byte(taskID), []byte(result), []byte(proof),
			}, stub.GetChannelID())
		} else { //计算错误
			response = stub.InvokeChaincode(task.BusinessContractAddr, [][]byte{
				[]byte(task.BusinessContractMethod), []byte(taskID), []byte(msg),
			}, stub.GetChannelID())
		}
	}
	var responseStruct crypto.Response
	if len(response.GetMessage()) > 0 {
		p.log.Warningf("callback fail, status %v", response.GetStatus())
		responseStruct.Response = []byte(response.GetMessage())
	} else {
		if err = json.Unmarshal(response.GetPayload(), &responseStruct); err != nil {
			p.log.Warningf("parse callback response, response %v", string(response.GetPayload()))
			responseStruct.Response = []byte(response.GetMessage())
		} else {
			p.log.Noticef("callback success, status %v, response: %v", response.GetStatus(), response.GetPayload())
		}
	}

	//4.移除taskStatus
	p.log.Notice("start delete taskID")
	compositeKey, _ := stub.CreateCompositeKey(statusTaskRef, []string{statusTaskPrefix, taskID})
	err = stub.DelState(compositeKey)
	if err != nil {
		p.log.Errorf("delete taskStatus error: %v", err)
		return "", fmt.Errorf("delete taskStatus error: %v", err)
	}
	p.log.Notice("delete taskID success")

	//5.如果需要下一轮计算
	var nextComputeEvent string
	if responseStruct.Continue {
		p.log.Notice("next compute: %v", strings.Join(responseStruct.NextParam[:], ", "))
		nextComputeEvent, err = p.computeAndProve(stub, responseStruct.NextParam[:])
		if err != nil {
			responseStruct.Response = []byte(fmt.Sprintf("call computeAndProve error: %v", err.Error()))
			nextComputeEvent = ""
			p.log.Error(string(responseStruct.Response))
		}
	}

	//6.抛出EVENT_FINISH事件
	e := crypto.EventFinish{
		TaskID:      taskID,
		CircuitID:   p.CircuitID,
		Proof:       proof,
		Result:      result,
		Error:       msg,
		Response:    responseStruct.Response,
		NextCompute: []byte(nextComputeEvent),
	}

	event, err := json.Marshal(e)
	if err != nil {
		p.log.Errorf("marshal event json error: %v", err)
		return "", fmt.Errorf("marshal event json error: %v", err)
	}
	p.log.Noticef("start set event: %v", string(event))
	if err = stub.SetEvent("EVENT_FINISH", event); err != nil {
		p.log.Errorf("generate EVENT_FINISH error: %v", err)
		return "", fmt.Errorf("generate EVENT_FINISH error: %v", err)
	}
	return "success", nil
}

/*verify proof
cc args: []string
	1. result
	2. publicInput
	3. proof
scc args: [][]byte
	1. version
	2. verifyKey
	3. result
	4. publicInput
	5. proof
*/
const cc2sccVersion1 = 0x01

func (p *ProxyChaincode) verifyProof(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	if len(args) != 3 {
		p.log.Errorf("verifyProof need 2 args: result and proof")
		return "", fmt.Errorf("verifyProof need 2 args: result and proof")
	}
	proof := args[2]
	tag, err := findTagInProof(proof)
	if err != nil {
		p.log.Error(err.Error())
		return "", err
	}
	p.log.Noticef("start get vk form status, tag is %v", tag)
	vk, err := stub.GetState(statusVK + tag)
	if err != nil || vk == nil {
		return "", fmt.Errorf("get vk error: %v", err)
	}

	input := [][]byte{
		{cc2sccVersion1},
		vk,
		[]byte(args[0]),
		[]byte(args[1]),
		[]byte(proof),
	}
	p.log.Notice("start invoke system chaincode myscc")
	p.log.Error(base64.URLEncoding.EncodeToString(vk))
	rsp := stub.InvokeChaincode("myscc", input, stub.GetChannelID())
	if rsp.Status == shim.OK {
		return "success", nil
	}

	return "fail", fmt.Errorf(rsp.Message)
}

/*
delete unfinished task
args: []string  taskID
*/
//deleteUnfinished delete unfinished task
func (p *ProxyChaincode) deleteUnfinished(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	var success, fail strings.Builder
	for _, taskID := range args {
		p.log.Notice("start delete taskID")
		compositeKey, _ := stub.CreateCompositeKey(statusTaskRef, []string{statusTaskPrefix, taskID})
		task, err := stub.GetState(compositeKey)
		if err != nil || task == nil {
			p.log.Errorf("can't find task: %v, err: %v", taskID, err)
			fail.WriteString(taskID)
			fail.WriteString(", ")
			continue
		}
		err = stub.DelState(compositeKey)
		if err != nil {
			p.log.Errorf("delete taskStatus error: %v", err)
			fail.WriteString(taskID)
			fail.WriteString(", ")
			continue
		}
		success.WriteString(taskID)
		success.WriteString(", ")
	}
	if fail.Len() > 0 {
		return "", fmt.Errorf("delete (%v) success, and (%v) fail", success.String(), fail.String())
	}
	return fmt.Sprintf("delete (%v) success", success.String()), nil
}

/*update PK and VK
args:
	1. pk
	2. vk
step:
	1. check args
	2. fail if there are tasks in progress
	3. change statusPK and statusVK
*/
func (p *ProxyChaincode) update(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	//1. check args
	if len(args) < 2 {
		return "", fmt.Errorf("update need 2 args in base64: pk and vk")
	}
	pk, err := base64.StdEncoding.DecodeString(args[0])
	if err != nil {
		return "", fmt.Errorf("args 'pk' should be hex form")
	}
	vk, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		return "", fmt.Errorf("args 'vk' should be hex form")
	}

	//2. fail if there are tasks in progress
	iter, err := stub.GetStateByPartialCompositeKey(statusTaskRef, []string{statusTaskPrefix})
	if err != nil {
		return "", fmt.Errorf("get all taskStatus error: %v", err)
	}

	var buf strings.Builder
	for iter.HasNext() {
		kv, innererr := iter.Next()
		if innererr != nil {
			_ = iter.Close()
			return "", fmt.Errorf("failed to traverse all tasks:%v", innererr)
		}
		_, ids, _ := stub.SplitCompositeKey(kv.Key)
		if len(ids) != 2 {
			p.log.Errorf("status dirty, unknown status: %v", kv.Key)
			continue
		}
		buf.WriteString(ids[1])
		buf.WriteString(", ")
	}
	err = iter.Close()
	if err != nil {
		return "", fmt.Errorf("close iter error: %v", err)
	}
	if buf.Len() > 0 {
		return "", fmt.Errorf("there are still unfinished tasks: %v", buf.String())
	}

	//3. change statusPK and statusVK
	tag := getTag(vk)
	err = stub.PutState(VKTag, []byte(tag))
	if err != nil {
		return "", fmt.Errorf("update vk tag errror: %v", err)
	}

	err = stub.PutState(statusPK, pk)
	if err != nil {
		return "", fmt.Errorf("update pk errror: %v", err)
	}

	err = stub.PutState(statusVK+tag, vk)
	if err != nil {
		return "", fmt.Errorf("update vk errror: %v", err)
	}
	return "success", nil
}

func (p *ProxyChaincode) getPK(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	pk, err := stub.GetState(statusPK)
	if err != nil || pk == nil {
		return "", fmt.Errorf("get pk error: %v", err)
	}
	return hex.EncodeToString(pk), nil
}

func (p *ProxyChaincode) getVK(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	tag, err := stub.GetState(VKTag)
	if err != nil || tag == nil {
		return "", fmt.Errorf("get vk error: %v", err)
	}

	vk, err := stub.GetState(statusVK + string(tag))
	if err != nil || vk == nil {
		return "", fmt.Errorf("get vk error: %v", err)
	}
	return hex.EncodeToString(vk), nil
}

func getTag(vk []byte) string {
	hasher := sha256.New()
	hasher.Write(vk)
	return hex.EncodeToString(hasher.Sum(nil))
}

func findTagInProof(p string) (string, error) {
	index := strings.Index(p, "VkTag")
	if index == -1 {
		return "", fmt.Errorf("parse vk tag error")
	}
	all := strings.Split(p[index:], "\"")
	if len(all) < 3 {
		return "", fmt.Errorf("parse vk tag error")
	}
	return all[2], nil
}

var _vk = "MIIDoQQFYm4yNTQwAASCAYAKbHGGToDcFVe_kX6CGvc70t-YJYGsiNzrHj2oOfCEMRnOUrzt0GGDvcngCDwETKjwyinrhaQqIHuPA3EqBbf1FdIK-MX7Dpy_Qsn95nKjymjD2HK-oR0VAhAwQnUU0AccPpKC_pmCMB8FakpfGlEfWWwFkJ-1I5tOwZoXwAhwxReyIJ9WYQRsX6jreiv532tv1_p79GZZFtfDzf6lj5_EGtpqaBZD0hky9BNRcCGoAPhS9mC_LhCMRI94Y7ue0zUb7EsC8xK6aB1m77pkj1aaMxyTelRVc9hNCXOHAVT25BgngLrw6rqXYtTQ_xleDdaQWT5_NozAxKLojMl1ct5-HsDEmsedSeG-3DE0MG1O_6xQva43R0pRLzJupMJk_BsDcJASaLnwSmjL6JDyHtfYWImSENbfcowOw6xWOHRtRQF9QdEuw9BgMIEzLkzw3CyPLzpwqvC7AQ4OaaZ9Ey0iK7HFNZEWifxuTWdyOhyktfTFDp3DBB13pE5Npwg_oWswggEIBEALE6co4to0a8YbNnHLHhFfJ_DlGQ2mKlZLsa6h8f1ePyVfA5S_sXy27JyUK9hn-F8_o1g2F4VDQqr35Qm1V51FBEAZZYZxlXGPDNGLbgJaTh5uIMUwDIy_qUwR1CKZ1F_bkRxIwKvXxGxWDLwPf2dXCFM5W41i-bZtG47p7WHdQFAABEAZZYZxlXGPDNGLbgJaTh5uIMUwDIy_qUwR1CKZ1F_bkRQbjccJbTPTq5Q2NxoqUApeJd0ubrtdca02nrT7PK1HBEAZZYZxlXGPDNGLbgJaTh5uIMUwDIy_qUwR1CKZ1F_bkRQbjccJbTPTq5Q2NxoqUApeJd0ubrtdca02nrT7PK1HBIGACX9sU-Hur-OpYZzCqmcLeKp7SWb2d4ntsuMRwLk2UlIHXhdTNakxH6frKC1OqZ2x-uRKTtu5GSBc7cpLSWg2TQTnahBYVNY1dMqee3ZvhHK4no9qtajV1ItU5EO7M9HFA1HOx_HOjT4FeoJj_sSZrbuaWWp-bUZM12ElBMDUZ3kEgYAKtPuWcI5wMiafLcq1spTddvFzdCxQo1FA9ylJ7bszJCzPb3Q2MpH4M_0aISeGr95SBxmmVt1QVV20TRTB-DaiJfR49yI6bNaJDDcej7TAT-VWdSlFXULTRx4gkigkRFIIE3PK4sCpt4x77QmYVotXW08EgnxIRAc5O_BUv8NwNTAA"
var _pk = "MIIIFgQFYm4yNTQEggGPMIIBiwEB_wQFYm4yNTQCAQEEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEEIDBkTnLhMaApuFBFtoGBWF0oM-hIeblwkUPh9ZPwAAAABCAwZE5y4TGgKbhQRbaBgVhdKDPoSHm5cJFD4fWT8AAAADAiBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATAiBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQgMGROcuExoCm4UEW2gYFYXSgz6Eh5uXCRQ-H1k_AAAAAwRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEEIDBkTnLhMaApuFBFtoGBWF0oM-hIeblwkUPh9ZPwAAAABEAgudglwnB4i75YFMlpmcyicaTyvY3XuoQ1GiTy2w1IGhss_W69NpVtdNIO9ifPOpUn67tH72gzrb7UpTT3YFVKBEAK7ommYHt7GiexABwuY_rt7gGmegJ_eO_jVOIkDqDTaQVPopPuQtwGuiy1RztuZgEDVSEiK2v_tCPP6Go96MV0BEAACiVtvBCWyn7N8oG4Vdt-nkLGpu6PQKLyQI9dmzdzRxbGUxB0aZ8QWphcKK_2u6xEgQYHstfdUnWaY-bTSjCqMAAwggEIBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATBkTnLhMaApuFBFtoGBWF2XgWqRaHHKjTwgjBbYfP1FBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATBkTnLhMaApuFBFtoGBWF2XgWqRaHHKjTwgjBbYfP1FMIIBCARAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADBCBEABDMSzeAd4fLe1c7rFjVKYLBTQYUun7R3pcgkqradxuCGN_2e_ufFj2kovS-_gOA8fWDS4sJ3BYsY0hW7nhEsRBIGALSbUDCiz7X-3UK9UsCeOwKxvM7Ngq4ukp94LJxMbZVwKDa8V78bR315p4A5pxji0ZhD10DWcG9EH4_mOjmitWgK_R_E1sj3MCFW3odyizLnaLBFo7OKa6H1-DTXoAHvkJHqUdml2BGz5gv2SFQfBwEuCsiZA6v3Dl4byalkdt4IEgYAJf2xT4e6v46lhnMKqZwt4qntJZvZ3ie2y4xHAuTZSUgdeF1M1qTEfp-soLU6pnbH65EpO27kZIFztyktJaDZNBOdqEFhU1jV0yp57dm-Ecriej2q1qNXUi1TkQ7sz0cUDUc7H8c6NPgV6gmP-xJmtu5pZan5tRkzXYSUEwNRneTCCAgwEgYAZjpOTkg1IOnJgv7cx-10l8apJMzWp5xKX5IW3rvMSwhgA3u8SHx52QmoAZl5cRHlnQyLU917a3UbevVzZkvbtCQaJ0Fhf8HXsnpmtaQwzlbxLMTNws47zVaza3NEil1sSyF6l24xt60qrcYCNy0CP49HnaQxD03tM5swBZvp9qgSBgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEgYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARAYTg2Yjk1MDMzMDA2NDg2MjAzZjc0Y2IyNGViNjU2NWVhMTM1Mzc2NzliOThkMjI2MGI5MzVhOTQ4NTJmNjBjYg=="
