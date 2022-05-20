package org.zswdemo;

import org.zhongshuwen.zswjava.SoftSM2KeySignatureProviderImpl;
import org.zhongshuwen.zswjava.error.ImportKeyError;
import org.zhongshuwen.zswjava.implementations.ABIProviderImpl;
import org.zhongshuwen.zswjava.implementations.ZswChainRpcProviderImpl;
import org.zhongshuwen.zswjava.models.rpcProvider.Action;
import org.zhongshuwen.zswjava.models.rpcProvider.Authorization;
import org.zhongshuwen.zswjava.models.rpcProvider.response.SendTransactionResponse;
import org.zhongshuwen.zswjava.session.TransactionSession;
import org.zhongshuwen.zswjavaabieosserializationprovider.AbiZswSerializationProviderImpl;

import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) {

        try {
            System.out.println("Hello world!");
            var rpcProvider = new ZswChainRpcProviderImpl("http://localhost:3031");
            var serializationProvider = new AbiZswSerializationProviderImpl();
            var abiProvider = new ABIProviderImpl(rpcProvider, serializationProvider);
            var signatureProvider = new SoftSM2KeySignatureProviderImpl();
            signatureProvider.importKey("5JryqVcPDHqJXD2oNQ4NH6pJb7Xr42zdAMsYLpUuP7oNP4cu78d");
            System.out.println("Imported Private Key with Public Key: "+signatureProvider.getAvailableKeys().get(0));

            var session = new TransactionSession(
                    serializationProvider,
                    rpcProvider,
                    abiProvider,
                    signatureProvider
            );

            var processor = session.getTransactionProcessor();

// Now the TransactionConfig can be altered, if desired
            var transactionConfig = processor.getTransactionConfig();

// Use blocksBehind (default 3) the current head block to calculate TAPOS
            transactionConfig.setUseLastIrreversible(false);
// Set the expiration time of transactions 600 seconds later than the timestamp
// of the block used to calculate TAPOS
            transactionConfig.setExpiresSeconds(600);

// Update the TransactionProcessor with the config changes
            processor.setTransactionConfig(transactionConfig);
            String senderName = "zsw.admin";
            String recipientName = "zswblkprod1a";
            String memo = "Hello World!";

            //admin给用户给recipientName移10个不可转移的计算分
            String jsonData = "{\n" +
                    "\"from\": \""+senderName+"\",\n" +
                    "\"to\": \""+recipientName+"\",\n" +
                    "\"quantity\": \"10.0000 ZSWCC\",\n" +
                    "\"memo\" : \""+memo+"\"\n" +
                    "}";

            List<Authorization> authorizations = new ArrayList<>();
            authorizations.add(new Authorization("zsw.admin", "active"));
            List<Action> actions = new ArrayList<>();
            actions.add(new Action("zswhq.token", "transfer", authorizations, jsonData));

            processor.prepare(actions);

            SendTransactionResponse sendTransactionResponse = processor.signAndBroadcast();
            System.out.println(sendTransactionResponse.getTransactionId());
        }catch(Exception e){
            System.err.println("ERROR: "+e.toString());
        }
    }
}