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
		CircuitIDHex: "d19f4c78ecb9b4133ba36274587cbf948beaa482444277f976fcaf44ec260f11",
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
	p.log.Notice("start invoke system chaincode vpscc")
	p.log.Debug(base64.URLEncoding.EncodeToString(vk))
	rsp := stub.InvokeChaincode("vpscc", input, stub.GetChannelID())
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

var _vk = "MIIDoQQFYm4yNTQwAASCAYAtGVRlGYrAt0cSbHJllfhNUTETBTCe63f9cuDWuWme3wj6pE-MGOUGVyMHlTxvMmwVDgOP5l6SPavdbk6s6PtFJzg0jzseM121_Q7cdL44opuxp4BRWuDszzyAL2l7XD4EdEG0BUaolD8v2ENtammH5LAVhkQ04jrSQjtFzNOLdBGaFm28EKoPK_9vPUQL8wVWwrrUmYpdxLsY2RucQcYpKL444X-mOORQqwuEE4_MiiK6xWqtukKi3FufY8Omy_kjQ3Xd1eRoArX8dHjDJcsf13A91dHeBMP3F139v69KZgTabNjK1jk_ayNrUXIDybNuNS7zyhvsbGJX5aFLoB33K-hgZDcQVwVAtuSvmRSHwy32ADsHOASyZl51wibUeOsWDOE0zY7r0aXMKOPJHenAMPcYuMxccKilhfVeajKzwCqM3QbZ2cR5aPWy7dWrpQoMmfpEiAY7LMoJvTDQcnFKBUf8JS-DkR34SiSDWsbxig9-oDPqOfaJuOhTEzGKP84wggEIBEAW-fbJNHfaEUwELsmJ5brMctCAOSd4MltJndnh7OFjzhK3LKfpZwtT2ANFUb4QINR0WSrpUEp_zP29djm9L-iuBEAXsejSj4ivZ_S-tSmXBOriGOunpoAjwU7kTJXMumIDMhlLF67WleqFLczeC_L3kK19gIfTs8cn9lRs6vvNDu6UBEAXsejSj4ivZ_S-tSmXBOriGOunpoAjwU7kTJXMumIDMhcZNsQKm7WkioNnqo6Jx7AaAOK9tKqiluezoRsLbg6zBEAXsejSj4ivZ_S-tSmXBOriGOunpoAjwU7kTJXMumIDMhcZNsQKm7WkioNnqo6Jx7AaAOK9tKqiluezoRsLbg6zBIGALQmu2VqfcodHBiv4mgKi_59kSrqAO0VkrEMAvA9-seYrEqn-a1IuzrmDETS60AijU0h4529zfTJ4NXgoAzfXnRqXNumZmY9Hsvby9--CBpzWPzG7QG95CY_HFuLyosvNJwdaZEYJvmAmSaQa1ViN1vEh8LntQnnWSUPJ5e5Ad5MEgYAWH2D_HBIcTRYsoKRPDd9kCS6g3FelozQpNHj-VopQzCZEzmECF_mXgMTNxSCkYQWFEgMizRyuTT1nBEtX1-iTHyiTzfu-9u8iCgicxIeYqb7DoM_ivwn0kaqrpbvb7x4peO-e6RSEsGAKo7chfdWe7cQWpewvPwFYPaUCHSQxETAA"
var _pk = "MIIIFgQFYm4yNTQEggGPMIIBiwEB_wQFYm4yNTQCAQEEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEEIDBkTnLhMaApuFBFtoGBWF0oM-hIeblwkUPh9ZPwAAAABCAwZE5y4TGgKbhQRbaBgVhdKDPoSHm5cJFD4fWT8AAAADAiBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATAiBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQgMGROcuExoCm4UEW2gYFYXSgz6Eh5uXCRQ-H1k_AAAAAwRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEEIDBkTnLhMaApuFBFtoGBWF0oM-hIeblwkUPh9ZPwAAAABEAdnLAXUgKtrcFL-5YXCVuJIcrWcQJq2-IvHJV_X8aahS8R4nGAFY3qlgit0KkzhO9gskZtb27eON7vsHFfjIhBBEADV4YOKI84vl7Rx8TNPBvIMn7JRpKQ9qa1BS3b30ZN3RVCtX8L5aU930EzSE7rLlX7vnt-_yKl-6iAGOQq_V0lBEAvNgby_QfffNH62TxIHD1cA2Lm6ILuMQG-CE9TdvnA-gmpK7CgNBSm8Fk7VL0lYnHUXMdDcNLa8mLiWe8lKVWmMAAwggEIBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATBkTnLhMaApuFBFtoGBWF2XgWqRaHHKjTwgjBbYfP1FBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATBkTnLhMaApuFBFtoGBWF2XgWqRaHHKjTwgjBbYfP1FMIIBCARAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADBCBEAmZgTX0WPF4DkiUeuytA7C6T_ABhus0y8owAWUTFCT3BIxhPWPXlqvjg6yZGIUt-FnVLKmkgXqdIYmv0F5oB1jBIGAAfY06TJVBhlJqZvdlJ7vTtvNPRAil7GPfLzvJABcf0gBiEz6t9PInjctiNMNlz4nsilsPNEat9qFrSkkJYlkgR0S8_lbbLwZOuW9zuV4UxFA871UtpCLtnV7cUm1StMTJ7geJtkTZSApw-g8Q4Pr2m9JiscGKZd3Lj87fsK53FQEgYAtCa7ZWp9yh0cGK_iaAqL_n2RKuoA7RWSsQwC8D36x5isSqf5rUi7OuYMRNLrQCKNTSHjnb3N9Mng1eCgDN9edGpc26ZmZj0ey9vL374IGnNY_MbtAb3kJj8cW4vKiy80nB1pkRgm-YCZJpBrVWI3W8SHwue1CedZJQ8nl7kB3kzCCAgwEgYAZjpOTkg1IOnJgv7cx-10l8apJMzWp5xKX5IW3rvMSwhgA3u8SHx52QmoAZl5cRHlnQyLU917a3UbevVzZkvbtCQaJ0Fhf8HXsnpmtaQwzlbxLMTNws47zVaza3NEil1sSyF6l24xt60qrcYCNy0CP49HnaQxD03tM5swBZvp9qgSBgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEgYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARAOGYwMWQ3NmEwZmI3ZTQwMmY0ODRlMmIyZWM0NzQ2OGM3ZWJjOTczNDUwZmM2NTVkNDVlNWJiZWYwZWIxNDQ4Zg=="
