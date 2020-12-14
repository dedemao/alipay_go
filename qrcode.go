package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

/*** 请填写以下配置信息 ***/
var appid string = "2021001157638209"                                    //https://open.alipay.com 账户中心->密钥管理->开放平台密钥，填写添加了电脑网站支付的应用的APPID
var returnUrl string = "https://www.dedemao.com/alipay/return.php"       //付款成功后的同步回调地址
var notifyUrl string = "https://www.dedemao.com/alipay/notify_redis.php" //付款成功后的异步回调地址
var outTradeNo string = Uniqid()                                         //你自己的商品订单号，不能重复
var payAmount float64 = 0.01                                             //付款金额，单位:元
var orderName string = "支付测试"                                            //订单标题
var signType string = "RSA2"                                             //签名算法类型，支持RSA2和RSA，推荐使用RSA2

//商户私钥，填写对应签名算法类型的私钥，如何生成密钥参考：https://docs.open.alipay.com/291/105971和https://docs.open.alipay.com/200/105310
var rsaPrivateKey string = "MIIEpAIBAAKCAQEA1MV+OY6MvGfXPM0MkpjT+FdzGmPOvVmX2wF3gjwQpeHBEUP9jLXhVS32fZ1iXI1e7WUGQ5tvXn28P8190kpOn/c/G5t2CAksUvemvF7uJN/N3Z1HFMdt3omvCd14K05lgcFYz7Z4c+A7ZJF5bPCB6oshjjUmbCY3hibuWzX/1j8AgsoD9lLyxoFqxLj98k5ZrYIhk900gMQs/WJ3A1FC09Dln9fuhBUyjtPHaml+4w+sdkdzxPktxdFrMcI7M7rNEwg25XtST5Z49oFpE84AlXM7+oC9jYvIpTGE00WomsgtakN039ucT/59Bup6pLkO08Rv85UXbqzGTcYAhNHLfQIDAQABAoIBAQCbuPM58s+j8KgB8ty5yiqRPoeaj+O2h4Txn7A02/sfPQvNtCI0wsTpT5twsihULo+EVYTxJCitUn7df2sP5pyGzTEd5njLRtNu4Zvhj+Thjf8grERiu9b4oXI/WRzjLRxzi+uREi40OK+fWi0xgxDCdROY/eNiEdJfV8zpaqsUxG7VdwZIJQ/8d3Mi31OWv30kr9jfEd15DBInGJgSqR+qwrAB4pBSMcW8hL6PYlzoPi1ygceFjRrnbeMG40zt0OUPSexQIgAmFvGqxTl5xo3dFEziGHdfWYsBKZ2M8ubAe+R6LcndxI+o2Hw4TNcC1tDeNMtjw7+h9S5aef5A8uWBAoGBAPxCLWPhUHCYlIXUz0D1SoolZs9WK7Kz1YSWnzqrpegN+foS5/ji93YylGE+KL31TwbnGQLAwknwMX3qTzmkvTovmy8jevXBsCSEFm81q0wG/35e1SKkTXL66RqB2y0xFLdcF3f9s8ZiEclqkYwNSHh0nqzREfIxMMAsj+3n2vHdAoGBANftYkZYrbs4iI/ZcjmBYguYikNfNmrD+Ta6ckOGZqsHfwXJCAz1rF4/XCqVAc9nxuzJR/72qkn9z07uH6qSZCqlZDRkiiKaK2UVqFDB+0abMk/TGHXuMmdvMkyj2jEZxG2rkg0kmg4qYkkg/5tGG1On/0GeZNVPu8JpsFr1pDYhAoGBANr8pCTKC6fDfWP1C3qrtmrY7zhc6RB4d4pjq5UmP5+EypaiZQi2F/dfD1qfuIS3eURXyGmQZtoDDyPtDZvP/ImPnFs+pNbFryD0HfmrEKquhIvyzXoGQknnsgbV5iyEKCTJaII9FxzINAKzZei7+0a+jqUd1kN3Gogp50Sze2ltAoGARaM5Xpaa8RZ6dGocfI9Nn4/Ch5fdZPFvHkdjMoPV+LKiNKtw/Tz+KiclAlasDsfZT+RaY9AJe3NvuHTzoX807swIVR1Xr3EpLaCed+0XrN3AjB34dZAskU87WZw+cjdtMjFzGOoFBSyGJi+OP/WMOp6jo/YBbwoX88tCJROzsgECgYAT8pHHIyPt5Y/5pDb8EDvD3XNES1fBkfZffSoAodsrkeoKgrsKl+9M3rcGX+S9dscyoH0ur3BFTMHtIOOhC5qytt+BhMHIP5mAs4di4u/joQCWQbUyrUggVK5it+6BFgAT+jeB7zTAUtgGpTVFq3kLbV0NZ+XQyEHVlnoJnHYpQg=="

/*** 配置结束 ***/

type AlipayService struct {
	appId         string
	returnUrl     string
	notifyUrl     string
	charset       string
	rsaPrivateKey *rsa.PrivateKey
	totalFee      float64
	outTradeNo    string
	orderName     string
}

func (this *AlipayService) SetAppId(appId string) {
	this.appId = appId
}

func (this *AlipayService) SetReturnUrl(returnUrl string) {
	this.returnUrl = returnUrl
}

func (this *AlipayService) SetNotifyUrl(notifyUrl string) {
	this.notifyUrl = notifyUrl
}

func (this *AlipayService) SetCharset(charset string) {
	this.charset = charset
}

// FormatPrivateKey 格式化 普通应用秘钥
func (this *AlipayService) FormatPrivateKey(privateKey string) (pKey string) {
	var buffer strings.Builder
	buffer.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
	rawLen := 64
	keyLen := len(privateKey)
	raws := keyLen / rawLen
	temp := keyLen % rawLen
	if temp > 0 {
		raws++
	}
	start := 0
	end := start + rawLen
	for i := 0; i < raws; i++ {
		if i == raws-1 {
			buffer.WriteString(privateKey[start:])
		} else {
			buffer.WriteString(privateKey[start:end])
		}
		buffer.WriteByte('\n')
		start += rawLen
		end = start + rawLen
	}
	buffer.WriteString("-----END RSA PRIVATE KEY-----\n")
	pKey = buffer.String()
	return
}

func (this *AlipayService) SetRsaPrivateKey(pkcs1keyStr string) {

	var block *pem.Block
	var privateKey *rsa.PrivateKey
	var err error
	pk := this.FormatPrivateKey(pkcs1keyStr)
	if block, _ = pem.Decode([]byte(pk)); block == nil {
		panic("pem.Decode：privateKey decode error")
	}

	if privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		panic(err)
	}

	this.rsaPrivateKey = privateKey
}

func (this *AlipayService) SetTotalFee(totalFee float64) {
	this.totalFee = totalFee
}

func (this *AlipayService) SetOutTradeNo(outTradeNo string) {
	this.outTradeNo = outTradeNo
}

func (this *AlipayService) SetOrderName(orderName string) {
	this.orderName = orderName
}

// GenSign 产生签名
func (this *AlipayService) GenSign(m map[string]string) string {
	var data []string
	var encryptedBytes []byte
	for k, v := range m {
		if v != "" && k != "sign" {
			data = append(data, fmt.Sprintf(`%s=%s`, k, v))
		}
	}
	sort.Strings(data)
	signData := strings.Join(data, "&")
	//println(signData)
	//return ""
	s := sha256.New()
	_, err := s.Write([]byte(signData))
	if err != nil {
		panic(err)
	}
	hashByte := s.Sum(nil)
	hashs := crypto.SHA256
	rsaPrivateKey := this.rsaPrivateKey
	if encryptedBytes, err = rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, hashs, hashByte); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes)
}

func (this *AlipayService) buildRequestForm(m map[string]string) string {
	var buf []string
	buf = append(buf, fmt.Sprintf("正在跳转至支付页面...<form id='alipaysubmit' name='alipaysubmit' action='https://openapi.alipay.com/gateway.do?charset=%s' method='POST'>", this.charset))
	for k, v := range m {
		buf = append(buf, fmt.Sprintf("<input type='hidden' name='%s' value='%s'/>", k, v))
	}
	buf = append(buf, "<input type='submit' value='ok' style='display:none;''></form>")
	buf = append(buf, "<script>document.forms['alipaysubmit'].submit();</script>")
	return strings.Join(buf, "")
}

func (this AlipayService) DoPay() (string, error) {

	//请求参数
	var bizContent = make(map[string]string)
	bizContent["out_trade_no"] = this.outTradeNo
	bizContent["product_code"] = "FAST_INSTANT_TRADE_PAY"
	bizContent["total_amount"] = strconv.FormatFloat(float64(this.totalFee), 'f', 2, 64) //2表示保留2位小数
	bizContent["subject"] = this.orderName
	bizContentJson, err := json.Marshal(bizContent)
	if err != nil {
		return "", errors.New("json.Marshal: " + err.Error())
	}

	//公共参数
	var m = make(map[string]string)
	m["app_id"] = this.appId
	m["method"] = "alipay.trade.precreate" //接口名称
	m["format"] = "JSON"
	m["return_url"] = this.returnUrl
	m["charset"] = this.charset
	m["sign_type"] = "RSA2"
	m["timestamp"] = time.Now().Format("2006-01-02 15:04:05")
	m["version"] = "1.0"
	m["notify_url"] = this.notifyUrl
	m["biz_content"] = string(bizContentJson)

	//获取签名
	sign := this.GenSign(m)
	m["sign"] = sign
	requestUrl := "https://openapi.alipay.com/gateway.do?charset=" + this.charset
	return postData(requestUrl, m), nil
}

func postData(requestUrl string, m map[string]string) string {
	data := make(url.Values)
	for k, v := range m {
		data[k] = []string{v}
	}

	resp, err := http.PostForm(requestUrl, data)
	if err != nil || resp.StatusCode != http.StatusOK {
		// 处理错误
		return "请求错误"
	}
	defer resp.Body.Close()
	// body, _ := ioutil.ReadAll(resp.Body)
	// fmt.Println(string(body))
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	return buf.String()
}

//生成订单号
func Uniqid() string {
	now := time.Now()
	return fmt.Sprintf("%s%08x%05x", "", now.Unix(), now.UnixNano()%0x100000)
}

func pcPay(w http.ResponseWriter, r *http.Request) {
	aliPay := AlipayService{}
	aliPay.SetAppId(appid)
	aliPay.SetReturnUrl(returnUrl)
	aliPay.SetNotifyUrl(notifyUrl)
	aliPay.SetCharset("utf-8")
	aliPay.SetRsaPrivateKey(rsaPrivateKey)
	aliPay.SetTotalFee(payAmount)
	aliPay.SetOutTradeNo(outTradeNo)
	aliPay.SetOrderName(orderName)
	response, err := aliPay.DoPay()
	if err != nil {
		panic(err)
	}
	// $result = $result['alipay_trade_precreate_response'];
	// if($result['code'] && $result['code']=='10000'){
	// 	//生成二维码
	// 	$url = 'https://sapi.k780.com/?app=qr.get&level=H&size=6&data='.$result['qr_code'];
	// 	echo "<img src='{$url}' style='width:300px;'><br>";
	// 	echo '二维码内容：'.$result['qr_code'];
	// }else{
	// 	echo $result['msg'].' : '.$result['sub_msg'];
	// }
	// w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, response)
}

func main() {
	//开启web服务器
	port := "8080"
	http.HandleFunc("/", pcPay)
	log.Println("服务器启动成功，监听端口：", port)
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
