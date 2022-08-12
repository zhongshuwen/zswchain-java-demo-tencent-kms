package org.zswdemo;

import com.tencentcloudapi.common.Credential;
import com.tencentcloudapi.common.profile.ClientProfile;
import com.tencentcloudapi.common.profile.HttpProfile;
import com.tencentcloudapi.common.exception.TencentCloudSDKException;
import com.tencentcloudapi.kms.v20190118.KmsClient;
import com.tencentcloudapi.kms.v20190118.models.*;

import java.util.Base64;


public class TencentCloudKMSClient {

    private KmsClient kmsClient;
    public TencentCloudKMSClient(String regionId, String accessKeyId, String accessKeySecret){
        Credential cred = new Credential(accessKeyId,accessKeySecret);
        // 实例化一个http选项，可选的，没有特殊需求可以跳过
        HttpProfile httpProfile = new HttpProfile();
        httpProfile.setEndpoint("kms.tencentcloudapi.com");
        // 实例化一个client选项，可选的，没有特殊需求可以跳过
        ClientProfile clientProfile = new ClientProfile();
        clientProfile.setHttpProfile(httpProfile);
        // 实例化要请求产品的client对象,clientProfile是可选的
        kmsClient = new KmsClient(cred, regionId, clientProfile);
    }

    public String GetPublicKey(String keyId) throws TencentCloudSDKException {
        final GetPublicKeyRequest gpkReq = new GetPublicKeyRequest();

        GetPublicKeyRequest req = new GetPublicKeyRequest();
        req.setKeyId(keyId);

        // 返回的resp是一个GetPublicKeyResponse的实例，与请求对象对应
        GetPublicKeyResponse resp = kmsClient.GetPublicKey(req);
        // 输出json格式的字符串回包
        System.out.println(resp.getPublicKeyPem());
        return resp.getPublicKeyPem();
    }

    public byte[] AsymmetricSign(String keyId, String algorithm, byte[] digest) throws TencentCloudSDKException {
        SignByAsymmetricKeyRequest req = new SignByAsymmetricKeyRequest();
        String base64Digest = Base64.getEncoder().encodeToString(digest);
        req.setAlgorithm(algorithm);
        req.setMessage(base64Digest);
        req.setKeyId(keyId);
        req.setMessageType("DIGEST");

        // 返回的resp是一个SignByAsymmetricKeyResponse的实例，与请求对象对应
        SignByAsymmetricKeyResponse resp = kmsClient.SignByAsymmetricKey(req);
        // 输出json格式的字符串回包
        System.out.println(SignByAsymmetricKeyResponse.toJsonString(resp));
        //签名要进行base64解码
        return Base64.getDecoder().decode(resp.getSignature());
    }


}