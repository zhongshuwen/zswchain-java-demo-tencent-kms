package org.zswdemo;

import org.bitcoinj.core.Base58;
import org.bitcoinj.core.Sha256Hash;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;
import org.zhongshuwen.zswjava.enums.AlgorithmEmployed;
import org.zhongshuwen.zswjava.error.ErrorConstants;
import org.zhongshuwen.zswjava.error.ImportKeyError;
import org.zhongshuwen.zswjava.error.SoftKeySignatureErrorConstants;
import org.zhongshuwen.zswjava.error.signatureProvider.GetAvailableKeysError;
import org.zhongshuwen.zswjava.error.signatureProvider.SignTransactionError;
import org.zhongshuwen.zswjava.error.utilities.Base58ManipulationError;
import org.zhongshuwen.zswjava.error.utilities.PEMProcessorError;
import org.zhongshuwen.zswjava.error.utilities.ZSWFormatterError;
import org.zhongshuwen.zswjava.interfaces.ISignatureProvider;
import org.zhongshuwen.zswjava.models.signatureProvider.ZswChainTransactionSignatureRequest;
import org.zhongshuwen.zswjava.models.signatureProvider.ZswChainTransactionSignatureResponse;
import org.zhongshuwen.zswjava.utilities.PEMProcessor;
import org.zhongshuwen.zswjava.utilities.SM2Formatter;
import org.zhongshuwen.zswjava.utilities.ZSWFormatter;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Util;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AliyunKMSSigner implements ISignatureProvider {
    private AliyunKMSClient kmsClient;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public AliyunKMSSigner(String region, String akId, String akSecret){
        this.kmsClient = new AliyunKMSClient(region, akId, akSecret);


    }
    public class KmsKeyVersion {
        public String id;
        public String versionId;
        public KmsKeyVersion(String id, String versionId){
            this.id = id;
            this.versionId = versionId;
        }
    }
    /**
     * Keep a Set (Unique) of private keys in PEM format
     */
    private Map<String, KmsKeyVersion> keyMap = new HashMap<String, KmsKeyVersion>();
    private static byte[] GetRSBytesFromSignaturePEM(String signaturePem) throws PEMProcessorError {

        PEMProcessor pp = new PEMProcessor(signaturePem);
        return pp.getKeyData();

    }

    private static String pemToZSWPublicKey(String publicKeyPEM) throws ZSWFormatterError {

        try {
            //Add checksum,Base58 encode key, and add prefix
            return ZSWFormatter.encodePublicKey(BCECUtil.convertECPublicKeyPEMToCompressedBasic(publicKeyPEM),
                    AlgorithmEmployed.SM2P256V1, false);
        } catch (Base58ManipulationError e) {
            throw new ZSWFormatterError(e);
        } catch (Exception e){
            throw new ZSWFormatterError(e);
        }

    }
    public void importKey(@NotNull String id, @NotNull String versionId) throws ImportKeyError {
        if (id.isEmpty()) {
            throw new ImportKeyError(SoftKeySignatureErrorConstants.IMPORT_KEY_INPUT_EMPTY_ERROR);
        }
        try {
            String key = kmsClient.GetPublicKey(id, versionId);
            String zswKey = pemToZSWPublicKey(key);
            keyMap.put(zswKey, new KmsKeyVersion(id, versionId));

        }catch(Exception e){
            throw new ImportKeyError(e);
        }
    }

    @Override
    public @NotNull ZswChainTransactionSignatureResponse signTransaction(@NotNull ZswChainTransactionSignatureRequest zswhqTransactionSignatureRequest) throws SignTransactionError {

        if (zswhqTransactionSignatureRequest.getSigningPublicKeys().isEmpty()) {
            throw new SignTransactionError(SoftKeySignatureErrorConstants.SIGN_TRANS_EMPTY_KEY_LIST);

        }

        if (zswhqTransactionSignatureRequest.getChainId().isEmpty()) {
            throw new SignTransactionError(SoftKeySignatureErrorConstants.SIGN_TRANS_EMPTY_CHAIN_ID);
        }

        if (zswhqTransactionSignatureRequest.getSerializedTransaction().isEmpty()) {
            throw new SignTransactionError(SoftKeySignatureErrorConstants.SIGN_TRANS_EMPTY_TRANSACTION);
        }

        // Getting serializedTransaction and preparing signable transaction
        String serializedTransaction = zswhqTransactionSignatureRequest.getSerializedTransaction();

        // This is the un-hashed message which is used to recover public key
        byte[] message;

        // This is the hashed message which is signed.
        byte[] hashedMessage;

        try {
            message = Hex.decode(ZSWFormatter.prepareSerializedTransactionForSigning(serializedTransaction, zswhqTransactionSignatureRequest.getChainId()).toUpperCase());
            hashedMessage = Sha256Hash.hash(message);
        } catch (ZSWFormatterError eosFormatterError) {
            throw new SignTransactionError(String.format(SoftKeySignatureErrorConstants.SIGN_TRANS_PREPARE_SIGNABLE_TRANS_ERROR, serializedTransaction), eosFormatterError);
        }

        List<String> signatures = new ArrayList<>();

        for(String requestKey : zswhqTransactionSignatureRequest.getSigningPublicKeys()) {
            if (keyMap.containsKey(requestKey)) {
                KmsKeyVersion keyVersion =  keyMap.get(requestKey);
                try {
                    byte[] data = kmsClient.AsymmetricSign(keyVersion.id, keyVersion.versionId, "SM2DSA", hashedMessage);
                    System.out.println("sig: "+Hex.encode(data));





                    String signatureWithCheckSum =
                            Base58.encode(ZSWFormatter.addCheckSumToSignature(
                                    SM2Formatter.combineSignatureParts(
                                            ZSWFormatter.decodePublicKey(requestKey.substring(7), "PUB_GM_"),
                                            data
                                    ),

                                    "GM".getBytes()
                            ));
                    signatures.add("SIG_GM_".concat(signatureWithCheckSum));
                } catch (com.aliyuncs.exceptions.ClientException error) {
                    throw new SignTransactionError(error);
                } catch (Base58ManipulationError error) {
                    throw new SignTransactionError(error);
                } catch (NoSuchAlgorithmException e) {
                    throw new SignTransactionError(e);
                }
            }
        }
        return new ZswChainTransactionSignatureResponse(serializedTransaction, signatures, null);
    }

    /**
     * Gets available keys from signature provider <br> Check createSignatureRequest() flow in
     * "complete workflow" for more detail of how the method is used.
     * <p>
     * Public key of SM2 has only the "PUB_GM_" + [key] variant
     *
     * @return the available keys of signature provider in ZSW format
     */
    @Override
    public @NotNull List<String> getAvailableKeys() {
        return new ArrayList<String>(this.keyMap.keySet());

    }
}
