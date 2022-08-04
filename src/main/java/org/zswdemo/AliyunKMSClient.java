package org.zswdemo;


import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.List;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.http.ProtocolType;

import com.aliyuncs.kms.model.v20160120.*;
import com.aliyuncs.kms.model.v20160120.ListKeysResponse.Key;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class AliyunKMSClient {

    private DefaultAcsClient kmsClient;
    public AliyunKMSClient(String regionId, String accessKeyId, String accessKeySecret){
        IClientProfile profile = DefaultProfile.getProfile(regionId, accessKeyId, accessKeySecret);
        HttpClientConfig clientConfig = HttpClientConfig.getDefault();
        //clientConfig.setIgnoreSSLCerts(true);
        profile.setHttpClientConfig(clientConfig);
        ((DefaultProfile) profile).addEndpoint(regionId, "Kms", "kms.cn-hangzhou.aliyuncs.com");

        kmsClient = new DefaultAcsClient(profile);

    }
    public List<String> ListKeys() throws ClientException {
        Integer pageNumber = 1;
        String keyId;
        List<String> listKeys = new ArrayList<>();
        for (; ; ) {
            ListKeysRequest listKeysReq = new ListKeysRequest();
            listKeysReq.setSysProtocol(ProtocolType.HTTPS);
            listKeysReq.setAcceptFormat(FormatType.JSON);
            listKeysReq.setSysMethod(MethodType.POST);
            listKeysReq.setPageNumber(pageNumber);
            listKeysReq.setPageSize(10);
            ListKeysResponse listKeysRes = kmsClient.getAcsResponse(listKeysReq);
            List<Key> keys = listKeysRes.getKeys();
            Iterator<Key> iterator = keys.iterator();

            for (; iterator.hasNext(); ) {
                keyId = iterator.next().getKeyId();
                listKeys.add(keyId);
            }
            pageNumber = listKeysRes.getPageNumber();
            Integer totalCount = listKeysRes.getTotalCount();
            if (pageNumber * 10 >= totalCount) {
                break;
            }
            pageNumber++;
        }
        return listKeys;
    }

    public DescribeKeyResponse DescribeKey(String keyId) throws ClientException {
        final DescribeKeyRequest decKeyReq = new DescribeKeyRequest();

        decKeyReq.setSysProtocol(ProtocolType.HTTPS);
        decKeyReq.setAcceptFormat(FormatType.JSON);
        decKeyReq.setSysMethod(MethodType.POST);
        decKeyReq.setKeyId(keyId);

        return kmsClient.getAcsResponse(decKeyReq);
    }

    private String CreateKey(String keyDesc, String keyUsage) throws ClientException {
        final CreateKeyRequest ckReq = new CreateKeyRequest();

        ckReq.setSysProtocol(ProtocolType.HTTPS);
        ckReq.setAcceptFormat(FormatType.JSON);
        ckReq.setSysMethod(MethodType.POST);
        ckReq.setDescription(keyDesc);
        ckReq.setKeyUsage(keyUsage);
        CreateKeyResponse keyRes = kmsClient.getAcsResponse(ckReq);

        return keyRes.getKeyMetadata().getKeyId();
    }

    private List<ListKeyVersionsResponse.KeyVersion> ListKeyVersions(String keyId) throws ClientException {
        Integer pageNumber = 1;
        List<ListKeyVersionsResponse.KeyVersion> listKeyVersions = new ArrayList<>();
        for (; ; ) {
            ListKeyVersionsRequest listKeyVersionsReq = new ListKeyVersionsRequest();
            listKeyVersionsReq.setSysProtocol(ProtocolType.HTTPS);
            listKeyVersionsReq.setAcceptFormat(FormatType.JSON);
            listKeyVersionsReq.setSysMethod(MethodType.POST);
            listKeyVersionsReq.setKeyId(keyId);
            listKeyVersionsReq.setPageNumber(pageNumber);
            listKeyVersionsReq.setPageSize(10);
            ListKeyVersionsResponse listKeyVersionsRes = kmsClient.getAcsResponse(listKeyVersionsReq);
            List<ListKeyVersionsResponse.KeyVersion> keyVersions = listKeyVersionsRes.getKeyVersions();
            Iterator<ListKeyVersionsResponse.KeyVersion> iterator = keyVersions.iterator();

            for (; iterator.hasNext(); ) {
                listKeyVersions.add(iterator.next());
            }
            pageNumber = listKeyVersionsRes.getPageNumber();
            Integer totalCount = listKeyVersionsRes.getTotalCount();
            if (pageNumber * 10 >= totalCount) {
                break;
            }
            pageNumber++;
        }
        return listKeyVersions;
    }

    private String DescribeKeyVersion(String keyId, String keyVersionId) throws ClientException {
        final DescribeKeyVersionRequest dkvReq = new DescribeKeyVersionRequest();

        dkvReq.setSysProtocol(ProtocolType.HTTPS);
        dkvReq.setAcceptFormat(FormatType.JSON);
        dkvReq.setSysMethod(MethodType.POST);
        dkvReq.setKeyId(keyId);
        dkvReq.setKeyVersionId(keyVersionId);
        DescribeKeyVersionResponse keyVersion = kmsClient.getAcsResponse(dkvReq);

        return keyVersion.getKeyVersion().getKeyVersionId();
    }

    private String CreateKeyVersion(String keyId) throws ClientException {
        final CreateKeyVersionRequest ckvReq = new CreateKeyVersionRequest();

        ckvReq.setSysProtocol(ProtocolType.HTTPS);
        ckvReq.setAcceptFormat(FormatType.JSON);
        ckvReq.setSysMethod(MethodType.POST);
        ckvReq.setKeyId(keyId);
        CreateKeyVersionResponse keyVersion = kmsClient.getAcsResponse(ckvReq);

        return keyVersion.getKeyVersion().getKeyVersionId();
    }

    public String GetPublicKey(String keyId, String keyVersionId) throws ClientException {
        final GetPublicKeyRequest gpkReq = new GetPublicKeyRequest();

        gpkReq.setSysProtocol(ProtocolType.HTTPS);
        gpkReq.setAcceptFormat(FormatType.JSON);
        gpkReq.setSysMethod(MethodType.POST);
        gpkReq.setKeyId(keyId);
        gpkReq.setKeyVersionId(keyVersionId);

        GetPublicKeyResponse publicKeyRes = kmsClient.getAcsResponse(gpkReq);

        return publicKeyRes.getPublicKey();
    }

    public byte[] AsymmetricSign(String keyId, String keyVersionId, String algorithm, byte[] digest) throws ClientException, NoSuchAlgorithmException {
        final AsymmetricSignRequest asReq = new AsymmetricSignRequest();
        //digest要进行base64编码
        String base64Digest = Base64.getEncoder().encodeToString(digest);
        asReq.setSysProtocol(ProtocolType.HTTPS);
        asReq.setAcceptFormat(FormatType.JSON);
        asReq.setSysMethod(MethodType.POST);
        asReq.setKeyId(keyId);
        asReq.setKeyVersionId(keyVersionId);
        asReq.setAlgorithm(algorithm);
        asReq.setDigest(base64Digest);
        AsymmetricSignResponse asymSignRes = kmsClient.getAcsResponse(asReq);
        //签名要进行base64解码
        return Base64.getDecoder().decode(asymSignRes.getValue().getBytes(StandardCharsets.UTF_8));
    }

    public boolean AsymmetricVerify(String keyId, String keyVersionId, String algorithm, byte[] digest, byte[] signature) throws ClientException, NoSuchAlgorithmException {
        final AsymmetricVerifyRequest avReq = new AsymmetricVerifyRequest();
        //digest，signature要进行base64编码
        String base64Digest = Base64.getEncoder().encodeToString(digest);
        String base64Signature = Base64.getEncoder().encodeToString(signature);
        avReq.setSysProtocol(ProtocolType.HTTPS);
        avReq.setAcceptFormat(FormatType.JSON);
        avReq.setSysMethod(MethodType.POST);
        avReq.setKeyId(keyId);
        avReq.setKeyVersionId(keyVersionId);
        avReq.setAlgorithm(algorithm);
        avReq.setDigest(base64Digest);
        avReq.setValue(base64Signature);
        AsymmetricVerifyResponse asymVerifyRes = kmsClient.getAcsResponse(avReq);

        return asymVerifyRes.getValue();
    }

}
