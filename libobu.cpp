//libobu.cpp : 定义 DLL 应用程序的导出函数。
// test for git commit

#include <tcaobu/def/ObuRetDef.h>
#include <tcaobu/dbio/SqlHelper.h>
#include <tcaobu/innerFunc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string>
using namespace std;

#ifdef __cplusplus
extern "C"
{
#endif

/**
* 5.1.列举证书
* 描述：列举OBU上指定证书池中的证书。
* 接口：Int ObuListCert(int certStoreType, int* certStartId, int* certEndId);
* 参数：	certStoreType   [IN]证书池类型。0 - 存储EC证书，1 - 存储当前使用的PC证书，2 - 存储预备的PC证书，3 - CA证书。
*           certStartId     [OUT]证书起始编号。
*           certEndId       [OUT]证书终止编号。
* 返回值：	0 - 成功，非0 - 错误码
* 说明：如果证书起始编号为1，证书终止编号为20，则证书编号取值区间为[1, 20]。
**/
int ObuListCert(int certStoreType, int* certStartId, int* certEndId)
{
    return listCert(certStoreType, certStartId, certEndId);
}


/** 5.2.生成证书申请数据
* 生成证书申请数据。
* 描述：生成证书申请数据。
* 接口：Int ObuGenCertApplyData(unsigned char* subject, int subjectLen, int certType, int hashAlg, unsigned char** applyData, int* applyDataLen);
* 参数：	subject         [IN]使用者名称数据缓冲区指针。
*           subjectLen      [IN]使用者名称数据长度。
*           certType        [IN]证书类型。0 - 申请EC证书，1 - 申请当前使用的PC证书，2 - 申请预备的PC证书。
*           applyData       [OUT]证书申请数据缓冲区指针。
*           applyDataLen    [OUT]证书申请数据长度。
* 返回值：	0 - 成功，非0 - 错误码
* 说明：摘要算法取值参照《GB / T 37374 - 2019 智能交通 数字证书应用接口规范》。
**/
int ObuGenCertApplyData(unsigned char* subject, int subjectLen, int certType, unsigned char** applyData, int* applyDataLen)
{
    return genCertApplyData(subject, subjectLen, certType, applyData, applyDataLen);
}


/** 5.3.安装证书
* 描述：将从CA下载的证书，安装到OBU的存储模块。
* 接口：Int ObuInstallCert(int certType, const char* b64CertData);
* 参数：	certType		    [IN]安装证书的类型。0-EC证书，1-当前使用的PC证书，2-预备的PC证书，3-CA证书。
*           b64CertData         [IN]Base64编码后的证书数据缓冲区指针。
* 返回值：	0 - 成功，非0 - 错误码
**/
int ObuInstallCert(int certType, const char* b64CertData)
{
    return installCert(certType, b64CertData);
}

/** 5.4.删除证书
* 描述：删除指定证书池中指定的证书。
* 接口：Int ObuDeleteCert(int certStoreType, int certId);
* 参数：	certStoreType   [IN]证书池类型。0 - 存储EC证书，1 - 存储当前使用的PC证书，2 - 存储预备的PC证书，3 - CA证书。
*           certId          [IN]证书编号。当证书编号为0时，删除指定证书池中全部证书。
* 返回值：	0 - 成功，非0 - 错误码
**/
int ObuDeleteCert(int certStoreType, int certId)
{
    return delCert(certStoreType, certId);
}

/** 5.5.获取证书
* 描述：根据证书编号获取证书和密钥标识。
* 接口：Int ObuGetCert(int certStoreType, int certId, int* keyId, unsigned char** certData, int* certDataLen);
* 参数：	certStoreType       [IN]证书池类型。0 - 存储EC证书，1 - 存储当前使用的PC证书，2 - 存储预备的PC证书，3 - CA证书。
*           certId              [IN]证书编号。当证书编号为0时，可随机从证书池获取一张证书。
*           keyId               [OUT]密钥标识。
*           certData            [OUT]证书数据缓冲区指针。
*           certDataLen         [OUT]证书数据长度。
* 返回值：	0 - 成功，非0 - 错误码
**/
int ObuGetCert(int certStoreType, int certId, int* keyId, unsigned char** certData, int* certDataLen)
{
    return getCert(certStoreType, certId, keyId, certData, certDataLen);
}

/** 5.6.切换证书
* 描述：当前使用证书池中的证书失效时，将预备证书池中的所有证书切换到当前使用的证书池中，预备证书池置为初始状态。
* 接口：Int ObuMoveCert();
* 返回值：	0 - 成功，非0 - 错误码
**/
int ObuMoveCert()
{
    return moveCert();
}

/** 5.7.验证证书
* 描述：验证证书有效性。
* 接口：Int ObuVerifyCert(unsigned char* certData, int certDataLen);
* 参数：	certData        [IN]待验证证书数据缓冲区指针。
*           certDataLen     [IN]待验证证书数据长度。
* 返回值：	0 - 成功，非0 - 错误码
**/
int ObuVerifyCert(unsigned char* certData, int certDataLen)
{
    return verifyCert(certData, certDataLen);
}

/** 5.8.签名
* 描述：当OBU发送数据时，用于对数据进行签名。
* 接口：Int ObuSignData(unsigned char* plain, int plainLen, int keyId, unsigned char** sign, int* signLen);
* 参数：	plain       [IN]待签名的数据缓冲区指针。
*           plainLen    [IN]待签名数据长度。
*           keyId       [IN]签名密钥标识。
*           sign        [OUT]签名值。
*           signLen     [OUT]签名值长度。
* 返回值：	0 - 成功，非0 - 错误码
**/
int ObuSignData(unsigned char* plain, int plainLen, int keyId, unsigned char** sign, int* signLen)
{
    return signData(plain, plainLen, keyId, sign, signLen);
}

/** 5.9.验签
* 描述：当OBU收到数据时，验证数据的有效性。
* 接口：Int ObuVerifySignData(unsigned char* plain, int plainLen, unsigned char* signCert, int signCertLen, unsigned char* sign, int signLen);
* 参数：	plain           [IN]签名原文数据缓冲区指针。
*           plainLen        [IN]签名原文数据长度。
*           signCert        [IN]签名证书数据缓冲区指针。
*           signCertLen     [IN]签名证书数据长度。
*           sign            [IN]签名值。
*           signLen         [IN]签名值长度。
* 返回值：	0 - 成功，非0 - 错误码
**/
int ObuVerifySignData(unsigned char* plain, int plainLen, unsigned char* signCert, int signCertLen, unsigned char* sign, int signLen)
{
    return verifySignData(plain, plainLen, signCert, signCertLen, sign, signLen);
}

/** 5.10.加密
* 描述：对数据进行加密, 生成被加密的对称密钥密文和使用对称密钥加密的密文。
* 接口：Int ObuEncryptData(unsigned char* plain, int plainLen, int symAlg, unsigned char* encCert, int encCertLen, unsigned char** encSymKey, int* encSymKey Len, unsigned char** encData, int* encDataLen);
* 参数：	plain               [IN]待加密原文数据缓冲区指针。
*           plainLen            [IN]待加密原文数据长度。
*           symAlg              [IN]对称加密算法。
*           encCert             [IN]加密证书数据缓冲区指针。
*           encCertLen          [IN]加密证书数据长度。
*           encSymKey           [OUT]对随机产生的对称密钥，使用加密证书加密的密文。
*           encSymKeyLen        [OUT]对随机产生的对称密钥，使用加密证书加密的密文长度。
*           encData             [OUT]使用随机产生的对称密钥加密的密文。
*           encDataLen          [OUT]使用随机产生的对称密钥加密的密文长度。
* 返回值：	0 - 成功，非0 - 错误码
* 说明：对称加密算法取值参照《GB / T 37374 - 2019 智能交通 数字证书应用接口规范》。
**/
int ObuEncryptData(unsigned char* plain, int plainLen, int symAlg, unsigned char* encCert, int encCertLen, unsigned char** encSymKey, int* encSymKeyLen, unsigned char** encData, int* encDataLen)
{
    return encryptData(plain, plainLen, symAlg, encCert, encCertLen, encSymKey, encSymKeyLen, encData, encDataLen);
}

/** 5.11.解密
* 描述：对数据进行解密, 得到数据原文。
* 接口：Int ObuDecryptData(unsigned char* encData, int encDataLen, int symAlg, unsigned char* encSymKey, int encSymKeyLen, unsigned char** plain, int* plainLen);
* 参数：	encData             [IN]使用对称密钥加密的密文。
*           encDataLen          [IN]使用对称密钥加密的密文长度。
*           symAlg              [IN]对称加密算法。
*           encSymKey           [IN]使用加密证书加密的对称密钥密文。
*           encSymKeyLen        [IN]使用加密证书加密的对称密钥密文的长度。
*           plain               [OUT]数据原文数据缓冲区指针。
*           plainLen            [OUT]数据原文数据长度。
* 返回值：	0 - 成功，非0 - 错误码
* 说明：对称加密算法取值参照《GB / T 37374 - 2019 智能交通 数字证书应用接口规范》。
**/
int ObuDecryptData(unsigned char* encData, int encDataLen, int symAlg, unsigned char* encSymKey, int encSymKeyLen, unsigned char** plain, int* plainLen)
{
    return decryptData(encData, encDataLen, symAlg, encSymKey, encSymKeyLen, plain, plainLen);
}

/** 5.12.对称加密
* 描述：对数据进行加密, 生成被加密的对称密钥密文和使用对称密钥加密的密文。
* 接口：Int ObuSymEncryptData(unsigned char* plain, int plainLen, int symAlg, unsigned char* symmKey, int symmKeyLen, unsigned char** encSymKey, int* encSymKeyLen, unsigned char** encData, int* encDataLen);
* 参数：	plain               [IN]待加密原文数据缓冲区指针。
*           plainLen            [IN]待加密原文数据长度。
*           symAlg              [IN]对称加密算法。
*           symmKey             [IN]对称密钥数据缓冲区指针。
*           symmKeyLen          [IN]对称密钥数据长度。
*           encSymKey           [OUT]被内部对称密钥加密的symmKey的密文。
*           encSymKeyLen        [OUT]被内部对称密钥加密的symmKey的密文长度。
*           encData             [OUT]使用symmKey加密的密文。
*           encDataLen          [OUT]使用symmKey加密的密文长度。
* 返回值：	0 - 成功，非0 - 错误码
* 说明：对称加密算法取值参照《GB / T 37374 - 2019 智能交通 数字证书应用接口规范》。
**/
int ObuSymEncryptData(unsigned char* plain, int plainLen, int symAlg, unsigned char* symmKey, int symmKeyLen, unsigned char** encSymKey, int* encSymKeyLen, unsigned char** encData, int* encDataLen)
{
    return symEncryptData(plain, plainLen, symAlg, symmKey, symmKeyLen, encSymKey, encSymKeyLen, encData, encDataLen);
}

/** 5.13.对称解密
* 描述：对数据进行解密, 得到数据原文。
* 接口：Int ObuSymDecryptData(unsigned char* encData, int encDataLen, int symAlg, unsigned char* encSymKey, int encSymKeyLen, unsigned char** plain, int* plainLen);
* 参数：	encData             [IN]使用对称密钥加密的密文。
*           encDataLen          [IN]使用对称密钥加密的密文长度。
*           symAlg              [IN]对称加密算法。
*           encSymKey           [IN]使用内部对称密钥加密的对称密钥密文。
*           encSymKeyLen        [IN]使用内部对称密钥加密的对称密钥密文的长度。
*           plain               [OUT]数据原文数据缓冲区指针。
*           plainLen            [OUT]数据原文数据长度。
* 返回值：	0 - 成功，非0 - 错误码
* 说明：对称加密算法取值参照《GB / T 37374 - 2019 智能交通 数字证书应用接口规范》。
**/
int ObuSymDecryptData(unsigned char* encData, int encDataLen, int symAlg, unsigned char* encSymKey, int encSymKeyLen, unsigned char** plain, int* plainLen)
{
    return symDecryptData(encData, encDataLen, symAlg, encSymKey, encSymKeyLen, plain, plainLen);
}

/** 5.14.计算摘要
* 描述：对数据计算摘要。
* 接口：Int ObuHashData(unsigned char* plain, int plainLen, int hashAlg, unsigned char** hash);
* 参数：	plain       [IN]待计算摘要原文数据缓冲区指针。
*           plainLen    [IN]待计算摘要原文数据长度。
*           symAlg      [IN]摘要算法。
*           hash        [OUT]摘要数据缓冲区指针，32字节长。
* 返回值：	0 - 成功，非0 - 错误码
* 说明：摘要算法取值参照《GB / T 37374 - 2019 智能交通 数字证书应用接口规范》。
**/
int ObuHashData(unsigned char* plain, int plainLen, int hashAlg, unsigned char** hash)
{
    return hashData(plain, plainLen, hashAlg, hash);
}

/** 5.15.生成签名安全消息
* 描述：生成签名安全消息。
* 接口：Int ObuGenSecMsg(int keyId, int itsAid, unsigned char* plain, int plainLen, int latitude, int longitude, int elevation, unsigned char* secMsg, int secMsgLen);
* 参数：	keyId               [IN]签名密钥标识。
*           itsAid              [IN]智能交通应用标识
*           plain               [IN]需要签名的消息原文数据缓冲区指针。
*           plainLen            [IN]需要签名的消息原文数据长度。
*           latitude            [IN]纬度。
*           longitude           [IN]经度。
*           elevation           [IN]海拔。
*           secMsg              [OUT]安全消息数据缓冲区指针。
*           secMsgLen           [OUT]安全消息数据长度。
* 返回值：	0 - 成功，非0 - 错误码
* 说明：secMsg是符合合作式ITS安全消息语法的数据流；纬度、经度和海拔取值范围参照《GB / T 37374 - 2019 智能交通 数字证书应用接口规范》。
**/
int ObuGenSecMsg(int keyId, int itsAid, unsigned char* plain, int plainLen, int latitude, int longitude, int elevation, unsigned char** secMsg, int* secMsgLen)
{
    return genSecMsg(keyId, itsAid, plain, plainLen, latitude, longitude, elevation, secMsg, secMsgLen);
}

/** 5.16.验证签名安全消息
* 描述：验证签名安全消息。
* 接口：Int ObuVerifySecMsg(unsigned char* secMsg, int secMsgLen, int* latitude, int* longitude, int* elevation, unsigned char** plain, int* plainLen);
* 参数：	secMsg          [IN]安全消息数据缓冲区指针。
*           secMsgLen       [IN]安全消息数据长度。
*           latitude        [OUT]纬度。
*           longitude       [OUT]经度。
*           elevation       [OUT]海拔。
*           plain           [OUT]消息原文数据缓冲区指针。
*           plainLen        [OUT]消息原文数据长度。
* 返回值：	0 - 成功，非0 - 错误码
* 说明：secMsg是符合合作式ITS安全消息语法的数据流；纬度、经度和海拔取值范围参照《GB / T 37374 - 2019 智能交通 数字证书应用接口规范》。
**/
int ObuVerifySecMsg(unsigned char* secMsg, int secMsgLen, int* latitude, int* longitude, int* elevation, unsigned char** plain, int* plainLen)
{
    return verifySecMsg(secMsg, secMsgLen, latitude, longitude, elevation, plain, plainLen);
}

/** 5.17.添加CRL
* 描述：添加CRL数据。
* 接口：Int ObuInstallCrl(unsigned char* crlData, int crlDataLen);
* 参数：	crlData         [IN]CRL数据缓冲区指针。
*           crlDataLen      [IN]CRL数据长度。
* 返回值：	0 - 成功，非0 - 错误码
* 说明：安装新的CRL数据会覆盖旧数据。
**/
int ObuInstallCrl(unsigned char* crlData, int crlDataLen)
{
    return installCrl(crlData, crlDataLen);
}

/** 5.18.删除CRL
* 描述：删除CRL数据。
* 接口：Int ObuDeleteCrl();
* 返回值：	0 - 成功，非0 - 错误码
**/
int ObuDeleteCrl()
{
    return deleteCrl();
}

/** 5.19.Base64编码
* 描述：对二进制数据进行Base64编码。
* 接口：Int ObuB64Enc(unsigned char* pbBin, int pbBinLen, char** pszB64);
* 参数：	pbBin           [IN]二进制数据缓冲区指针。
*           pbBinLen        [IN]二进制数据长度。
*           pszB64          [OUT]Base64编码后的数据缓冲区指针。
* 返回值：	0 - 成功，非0 - 错误码
**/
int ObuB64Enc(unsigned char* pbBin, int pbBinLen, char** pszB64)
{
    return b64Enc(pbBin, pbBinLen, pszB64);
}

/** 5.20.Base64解码
* 描述：对二进制数据进行Base64解码。
* 接口：Int ObuB64Dec(const char *pszB64, unsigned char **pbBin, int *pbBinLen);
* 参数：	pszB64          [IN]Base64编码后的数据缓冲区指针。
*           pbBin           [OUT]二进制数据缓冲区指针。
*           pbBinLen        [OUT]二进制数据长度。
* 返回值：	0 - 成功，非0 - 错误码
**/
int ObuB64Dec(const char *pszB64, unsigned char **pbBin, int *pbBinLen)
{
    return b64Dec(pszB64, pbBin, pbBinLen);
}

////未确定
/** 5.21.应答解析
* 描述：对证书申请应答数据进行解析。
* 接口：Int ObuResponseAnalysis(unsigned char* response, int responseLen, unsigned char** certDLUrl, int* certDLUrlLen);
* 参数：	response            [IN]证书申请应答数据缓冲区指针。
*           responseLen         [IN]证书申请应答数据长度。
*           certDLUrl           [OUT]证书下载URL地址数据缓冲区指针。
*           certDLUrlLen        [OUT]证书下载URL地址数据长度。
* 返回值：	0 - 成功，非0 - 错误码
* 说明：如果response是PC消息证书申请应答数据，返回证书下载URL地址；如果response是EC注册证书申请应答数据，里面包含证书，直接安装，不返回证书下载URL地址，此时certDLUrlLen返回值为0。
**/
int ObuResponseAnalysis(unsigned char* response, int responseLen, unsigned char** certDLUrl, int* certDLUrlLen)
{
    return responseAnalysis(response, responseLen, certDLUrl, certDLUrlLen);
}

#ifdef __cplusplus
}
#endif