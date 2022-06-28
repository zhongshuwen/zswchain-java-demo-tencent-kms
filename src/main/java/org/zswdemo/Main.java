package org.zswdemo;


import com.google.gson.Gson;
import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;
import org.zhongshuwen.zswjava.SoftSM2KeySignatureProviderImpl;
import org.zhongshuwen.zswjava.abitypes.ZSWAPIV1;
import org.zhongshuwen.zswjava.enums.AlgorithmEmployed;
import org.zhongshuwen.zswjava.error.session.TransactionPrepareError;
import org.zhongshuwen.zswjava.error.session.TransactionSignAndBroadCastError;
import org.zhongshuwen.zswjava.error.utilities.Base58ManipulationError;
import org.zhongshuwen.zswjava.implementations.ABIProviderImpl;
import org.zhongshuwen.zswjava.implementations.ZswChainRpcProviderImpl;
import org.zhongshuwen.zswjava.models.ZSWItems.*;
import org.zhongshuwen.zswjava.models.ZSWItems.ZSWItemsTables.*;
import org.zhongshuwen.zswjava.models.ZSWTokenTransfer;
import org.zhongshuwen.zswjava.models.rpcProvider.Action;
import org.zhongshuwen.zswjava.models.rpcProvider.Authorization;
import org.zhongshuwen.zswjava.models.rpcProvider.TransactionConfig;
import org.zhongshuwen.zswjava.models.rpcProvider.request.GetTableRowsRequest;
import org.zhongshuwen.zswjava.models.rpcProvider.response.SendTransactionResponse;
import org.zhongshuwen.zswjava.session.TransactionProcessor;
import org.zhongshuwen.zswjava.session.TransactionSession;
import org.zhongshuwen.zswjava.utilities.ZSWFormatter;
import org.zhongshuwen.zswjava.utilities.ZSWHelpers;
import org.zhongshuwen.zswjava.utilities.ZSWIdHelper;
import org.zhongshuwen.zswjava.utilities.ZSWTableRowResponse;
import org.zhongshuwen.zswjavacrossplatformabi.ZswCoreSerializationProvider;
import org.zz.gmhelper.SM2Util;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.zhongshuwen.zswjava.utilities.ZSWHelpers.CreateVariantFieldValue;

public class Main {

    private static SendTransactionResponse createChainUser(TransactionProcessor processor, String name, String ownerPublicKey, String activePublicKey, long ram, long net, long cpu) throws TransactionPrepareError, TransactionSignAndBroadCastError {
        Action createAccountAction = new Action(
                "zswhq",
                "newaccount",
                Arrays.asList(new Authorization[]{
                        new Authorization("zsw.admin", "active")
                }),
                "{\n" +
                        "  \"creator\": \"zsw.admin\",\n" +
                        "  \"name\": \""+name+"\",\n" +
                        "  \"owner\": {\n" +
                        "    \"threshold\": 1,\n" +
                        "    \"keys\": [\n" +
                        "      {\n" +
                        "        \"key\": \""+ownerPublicKey+"\",\n" +
                        "        \"weight\": 1\n" +
                        "      }\n" +
                        "    ],\n" +
                        "    \"accounts\": [],\n" +
                        "    \"waits\": []\n" +
                        "  },\n" +
                        "  \"active\": {\n" +
                        "    \"threshold\": 1,\n" +
                        "    \"keys\": [\n" +
                        "      {\n" +
                        "        \"key\": \""+activePublicKey+"\",\n" +
                        "        \"weight\": 1\n" +
                        "      }\n" +
                        "    ],\n" +
                        "    \"accounts\": [],\n" +
                        "    \"waits\": []\n" +
                        "  }\n" +
                        "}"
        );
        Action buyRamAction = new Action(
                "zswhq",
                "buyrambytes",
                Arrays.asList(new Authorization[]{
                        new Authorization("zsw.admin", "active")
                }),
                "{\n" +
                        "  \"payer\": \"zsw.admin\",\n" +
                        "  \"receiver\": \""+name+"\",\n" +
                        "  \"bytes\": "+ram+"\n" +
                        "}"
        );
        Action delegateBwAction = new Action(
                "zswhq",
                "delegatebw",
                Arrays.asList(new Authorization[]{
                        new Authorization("zsw.admin", "active")
                }),
                "{\n" +
                        "  \"from\": \"zsw.admin\",\n" +
                        "  \"receiver\": \""+name+"\",\n" +
                        "  \"stake_net_quantity\": \""+net+".0000 ZSWCC\",\n" +
                        "  \"stake_cpu_quantity\": \""+cpu+".0000 ZSWCC\",\n" +
                        "  \"transfer\": true\n" +
                        "}"
        );



        List<Action> actions = new ArrayList<>();
        actions.add(createAccountAction);
        actions.add(buyRamAction);
        actions.add(delegateBwAction);
        processor.prepare(actions);

        return processor.signAndBroadcast();
    }
    private static SendTransactionResponse giveUserKexinJiedianPermissions(TransactionProcessor processor, String name, String zswUuid) throws TransactionPrepareError, TransactionSignAndBroadCastError {
        String zswId = ZSWIdHelper.getZSWIdFromUUID(zswUuid);
        Action makeCustodianAction = new Action(
                "zsw.items",
                "mkcustodian",
                Arrays.asList(new Authorization[]{
                        new Authorization("zsw.admin", "active")
                }),
                "{\n" +
                        "  \"creator\": \"zsw.admin\",\n" +
                        "  \"custodian_name\": \""+name+"\",\n" +
                        "  \"zsw_id\": \""+zswId+"\",\n" +
                        "  \"alt_id\": 0,\n" +
                        "  \"permissions\": 163,\n" +
                        "  \"status\": 0,\n" +
                        "  \"incoming_freeze_period\": 0,\n" +
                        "  \"notify_accounts\": [\""+name+"\"]\n" +
                        "}"
        );
        Action makeIssuerAction = new Action(
                "zsw.items",
                "mkissuer",
                Arrays.asList(new Authorization[]{
                        new Authorization("zsw.admin", "active")
                }),
                "{\n" +
                        "    \"authorizer\": \"zsw.admin\",\n" +
                        "    \"issuer_name\": \""+name+"\",\n" +
                        "    \"zsw_id\": \""+zswId+"\",\n" +
                        "    \"alt_id\": 0,\n" +
                        "    \"permissions\": 32784,\n" +
                        "    \"status\": 0\n" +
                        "  }"
        );
        Action makeRoyaltyUserAction = new Action(
                "zsw.items",
                "mkroyaltyusr",
                Arrays.asList(new Authorization[]{
                        new Authorization("zsw.admin", "active")
                }),
                "{\n" +
                        "  \"authorizer\": \"zsw.admin\",\n" +
                        "  \"newroyaltyusr\": \""+name+"\",\n" +
                        "  \"zsw_id\": \""+zswId+"\",\n" +
                        "  \"alt_id\": 0,\n" +
                        "  \"status\": 0\n" +
                        "}"
        );
        Action setPermsAction = new Action(
                "zsw.perms",
                "setperms",
                Arrays.asList(new Authorization[]{
                        new Authorization("zsw.admin", "active")
                }),
                "{\n" +
                        "      \"sender\": \"zsw.admin\",\n" +
                        "      \"scope\": \"zsw.prmcore\",\n" +
                        "      \"user\": \""+name+"\",\n" +
                        "      \"perm_bits\": 24576\n" +
                        "    }"
        );



        List<Action> actions = new ArrayList<>();
        actions.add(makeCustodianAction);
        actions.add(makeIssuerAction);
        actions.add(setPermsAction);
        actions.add(makeRoyaltyUserAction);
        processor.prepare(actions);

        return processor.signAndBroadcast();
    }

    private static SendTransactionResponse createCollectionDemo(TransactionProcessor processor, String keXinJieDianName, String collectionUUID, String collectionSchemaName, ZSWAPIV1.KVPair[] collectionMetadata) throws TransactionPrepareError, TransactionSignAndBroadCastError {
        String collectionZswId = ZSWIdHelper.getZSWIdFromUUID(collectionUUID);
        String collection40BitId = ZSWIdHelper.getZSW64BitIdFromUUID(collectionUUID);
        System.out.println("id: "+collection40BitId);
        Action makeCollectionAction = Action.fromSerializable(
                "zsw.items",
                "mkcollection",
                new Authorization[]{
                        new Authorization("zsw.admin", "active"),
                        new Authorization(keXinJieDianName, "active"),
                },
                new ZSWItemsMakeCollection(
                        "zsw.admin",
                        collectionZswId,
                        collection40BitId,
                        0,
                        keXinJieDianName,
                        keXinJieDianName,
                        11,
                        500,
                        500,
                        keXinJieDianName,
                        99999999L,
                        999999999L,
                        0,
                        collectionSchemaName,
                        new String[]{keXinJieDianName},
                        new String[]{keXinJieDianName},

                        new String[]{},
                        collectionMetadata,
                        ""
                )
        );


        List<Action> actions = new ArrayList<>();
        actions.add(makeCollectionAction);
        processor.prepare(actions);

        return processor.signAndBroadcast();
    }
    static class ItemInTemplateDef {
        public String zswUUID;
        public ZSWAPIV1.KVPair[] values;

        public ItemInTemplateDef(String zswUUID, ZSWAPIV1.KVPair[] values) {
            this.zswUUID = zswUUID;
            this.values = values;
        }
    }
    private static SendTransactionResponse makeItemTemplateAndItems(TransactionProcessor processor, String keXinJieDianName, String collectionUUID, String itemTemplateUUID,String itemTemplateSchemaName, ZSWAPIV1.KVPair[] itemTemplateMetadata, ItemInTemplateDef[] itemDefinitions) throws TransactionPrepareError, TransactionSignAndBroadCastError {
        String itemTemplateZswId = ZSWIdHelper.getZSWIdFromUUID(itemTemplateUUID);
        String itemTemplate64BitId = ZSWIdHelper.getZSW64BitIdFromUUID(itemTemplateUUID);
        String collection64BitId = ZSWIdHelper.getZSW64BitIdFromUUID(collectionUUID);

        List<Action> actions = new ArrayList<>();
        Action makeItemTemplateAction = Action.fromSerializable(
                "zsw.items",
                "mkitemtpl",
                new Authorization[]{
                        new Authorization("zsw.admin", "active"),
                        new Authorization(keXinJieDianName, "active"),
                },
                new ZSWItemsMakeItemTemplate(
                        "zsw.admin",
                        keXinJieDianName,
                        itemTemplateZswId,
                        itemTemplate64BitId,
                        collection64BitId,
                        0,
                        itemTemplateSchemaName,
                        itemTemplateMetadata,
                        ""
                )
        );


        actions.add(makeItemTemplateAction);
        for(ItemInTemplateDef item : itemDefinitions){
            Action createItemAction = Action.fromSerializable(
                    "zsw.items",
                    "mkitem",
                    new Authorization[]{
                            new Authorization("zsw.admin", "active"),
                            new Authorization(keXinJieDianName, "active"),
                    },
                    new ZSWItemsMakeItem(
                            "zsw.admin",
                            keXinJieDianName,
                            ZSWIdHelper.getZSW40BitIdFromUUID(item.zswUUID),
                            ZSWIdHelper.getZSWIdFromUUID(item.zswUUID),
                            11,
                            itemTemplate64BitId,

                            9999999999L,
                            itemTemplateSchemaName,
                            item.values,
                            new ZSWAPIV1.KVPair[]{}
                    )
            );
            actions.add(createItemAction);
        }

        processor.prepare(actions);

        return processor.signAndBroadcast();
    }
    public static void TestFull() {
        // 把"zswAdminPrivateKey"改成docker-compose.yaml
        String zswAdminPrivateKey = "PVT_GM_2HDJ438CqpDcfpXcrHVdwXT79bAQfWq5Foz9d3SBCDKC4vHrob";


        String keXinJieDianPrivateKey = "PVT_GM_2EMuJ8xjvEmikuA7pDa5miN7qAFWtPU1RVaSr3rXErCdkxJzBN";
        String userAPublicKey = "PUB_GM_79mhnfDTtUiHALKUk35ziBU9MgynfdwKCsvsEAkUwaWPU1GYaU";
        String userBPublicKey = "PUB_GM_7hspJH3JGijxNMUCEVCkg5t7ZULrcuR1RxBe9WmxZkDkDud9Mr";
        String keXinJieDianName = "kxjdtestzzza";
        String userAName = "usertestzzza";
        String userBName = "usertestzzzb";

        String kexinJieDianZhongShuWenUUID = "2b9768c8-1d7c-4428-a7e7-3c04ae8c339a";

        String basicCollectionCoreSchemaName = "yishupinxxv2";
        ZSWItemsSchemaFieldDefinition[] basicCollectionCoreSchema = new ZSWItemsSchemaFieldDefinition[]{
                new ZSWItemsSchemaFieldDefinition("name", "string"),
                new ZSWItemsSchemaFieldDefinition("description", "string"),
                new ZSWItemsSchemaFieldDefinition("artist", "string"),
                new ZSWItemsSchemaFieldDefinition("website", "string"),
                new ZSWItemsSchemaFieldDefinition("logo", "string"),
        };

        String collectionAUUID = "4d08ce12-b11f-4ace-8382-edce59f604ca";
        ZSWAPIV1.KVPair[] collectionAMetadata = new ZSWAPIV1.KVPair[]{
                CreateVariantFieldValue("name", "string","上海知名地"),
                CreateVariantFieldValue("description", "string","一个关于上海知名地的数字艺术品组合"),
                CreateVariantFieldValue("artist", "string","周卡特"),
                CreateVariantFieldValue("website", "string","https://examplecollection.zhongshuwen.com/about.html"),
                CreateVariantFieldValue("logo", "string","https://examplecollection.zhongshuwen.com/logo.png")
        };

        String commonLocationShuZiCangPinSchemaName = "locationszcz";
        ZSWItemsSchemaFieldDefinition[] commonLocationShuZiCangPinSchema = new ZSWItemsSchemaFieldDefinition[]{
                new ZSWItemsSchemaFieldDefinition("name", "string"),
                new ZSWItemsSchemaFieldDefinition("region", "string"),
                new ZSWItemsSchemaFieldDefinition("city", "string"),
                new ZSWItemsSchemaFieldDefinition("district", "string"),
                new ZSWItemsSchemaFieldDefinition("latitude", "float"),
                new ZSWItemsSchemaFieldDefinition("longitude", "float"),
                new ZSWItemsSchemaFieldDefinition("image_url", "string"),
        };


        String itemTemplateAUUID = "bc2c7eaa-a2ff-4b49-be37-fcfdc53f8cea";
        ZSWAPIV1.KVPair[] itemTemplateACommonMetadata = new ZSWAPIV1.KVPair[]{
                CreateVariantFieldValue("city", "string","上海市"),
                CreateVariantFieldValue("district", "string","徐汇区"),
                CreateVariantFieldValue("region", "string","中国"),
        };

        String itemAUUID = "4462c722-23ce-4193-a78b-a0ca9cd6b31a";
        ZSWAPIV1.KVPair[] itemAImmutableMetadata = new ZSWAPIV1.KVPair[]{
                CreateVariantFieldValue("name", "string","上海交通大学"),
                CreateVariantFieldValue("image_url", "string","https://images.testnet.zhongshuwen.com/c/124912847/13118.png"),
        };

        String itemBUUID = "ae13217b-2efa-413f-9abd-11171aec354a";
        ZSWAPIV1.KVPair[] itemBImmutableMetadata = new ZSWAPIV1.KVPair[]{
                CreateVariantFieldValue("name", "string","上海交通大学"),
                CreateVariantFieldValue("image_url", "string","https://images.testnet.zhongshuwen.com/c/124912847/13118.png"),
        };



        try {
            String keXinJieDianPublicKey = ZSWHelpers.PrivateKeyToPublicKeyGM(keXinJieDianPrivateKey);

            ZswChainRpcProviderImpl rpcProvider = new ZswChainRpcProviderImpl("http://localhost:3031/");
            ZswCoreSerializationProvider serializationProvider = new ZswCoreSerializationProvider();
            //serializationProvider.registerActionType("zswhq.token","transfer", ZSWTokenTransfer.class);
            ABIProviderImpl abiProvider = new ABIProviderImpl(rpcProvider, serializationProvider);
            SoftSM2KeySignatureProviderImpl signatureProvider = new SoftSM2KeySignatureProviderImpl();

            //可以使用https://tools.banquan.sh.cn/zsw-key-generator.html生成测试密钥，改成docker-compose设置的admin密钥
            signatureProvider.importKey(zswAdminPrivateKey);
            //System.out.println("Imported Private Key with Public Key: "+signatureProvider.getAvailableKeys().get(0));

            signatureProvider.importKey(keXinJieDianPrivateKey);

            TransactionSession session = new TransactionSession(
                    serializationProvider,
                    rpcProvider,
                    abiProvider,
                    signatureProvider
            );
            serializationProvider.setUpGSON();
            TransactionProcessor processor = session.getTransactionProcessor();

            // Now the TransactionConfig can be altered, if desired
            TransactionConfig transactionConfig = processor.getTransactionConfig();

            // Use blocksBehind (default 3) the current head block to calculate TAPOS
            transactionConfig.setUseLastIrreversible(false);
            // Set the expiration time of transactions 600 seconds later than the timestamp
            // of the block used to calculate TAPOS
            transactionConfig.setExpiresSeconds(600);

            // Update the TransactionProcessor with the config changes
            processor.setTransactionConfig(transactionConfig);

            Thread.sleep(5000);

            createChainUser(getProcessor(session), keXinJieDianName, keXinJieDianPublicKey,keXinJieDianPublicKey,100000,10000,10000);

            createChainUser(getProcessor(session), userAName, userAPublicKey,userAPublicKey,100000,10000,10000);

            createChainUser(getProcessor(session), userBName, userBPublicKey,userBPublicKey,100000,10000,10000);
            System.out.println("created base accounts");

            Thread.sleep(5000);
            giveUserKexinJiedianPermissions(getProcessor(session), keXinJieDianName, kexinJieDianZhongShuWenUUID);
            System.out.println("created accounts with kexinjiedian permissions");

            Thread.sleep(5000);

            SendTx(session,Arrays.asList(
                    new Action[]{
                            Action.fromSerializable(
                                    "zsw.items",
                                    "mkschema",
                                    new Authorization[]{
                                            new Authorization("zsw.admin", "active"),
                                            new Authorization("zsw.admin", "active"),
                                    },
                                    new ZSWItemsMakeSchema(
                                            "zsw.admin",
                                            "zsw.admin",
                                            basicCollectionCoreSchemaName,
                                            basicCollectionCoreSchema
                                    )
                            ),
                            Action.fromSerializable(
                                    "zsw.items",
                                    "mkschema",
                                    new Authorization[]{
                                            new Authorization("zsw.admin", "active"),
                                            new Authorization("zsw.admin", "active"),
                                    },
                                    new ZSWItemsMakeSchema(
                                            "zsw.admin",
                                            "zsw.admin",
                                            commonLocationShuZiCangPinSchemaName,
                                            commonLocationShuZiCangPinSchema
                                    )
                            ),
                    }
            ));

            System.out.println("created schema");
            Thread.sleep(5000);
            createCollectionDemo(getProcessor(session), keXinJieDianName, collectionAUUID, basicCollectionCoreSchemaName, collectionAMetadata);
            Thread.sleep(5000);
            System.out.println("created collection");

            makeItemTemplateAndItems(
                    getProcessor(session),
                    keXinJieDianName,
                    collectionAUUID,
                    itemTemplateAUUID,
                    commonLocationShuZiCangPinSchemaName,
                    itemTemplateACommonMetadata,
                    new ItemInTemplateDef[]{
                            new ItemInTemplateDef(itemAUUID, itemAImmutableMetadata),
                            new ItemInTemplateDef(itemBUUID, itemBImmutableMetadata),
                    }
            );
            Thread.sleep(5000);
            System.out.println("created items");

            Action mintAction = Action.fromSerializable(
                    "zsw.items",
                    "mint",
                    new Authorization[]{
                            new Authorization(keXinJieDianName, "active"),
                    },
                    new ZSWItemsMint(
                            keXinJieDianName,
                            userAName,
                            keXinJieDianName,
                            1,
                            new String[]{ZSWIdHelper.getZSW40BitIdFromUUID(itemAUUID),ZSWIdHelper.getZSW40BitIdFromUUID(itemBUUID)},
                            new String[]{"1","5"},
                            "mint你的数字藏品"
                    )
            );
            SendTx(session, Arrays.asList(
                    new Action[]{
                            mintAction,

                    }));

            System.out.println("waiting tx + 1 minute in legal compliance demo...");
            Thread.sleep(30000);
            System.out.println("60 seconds left before unfreezing...");

            Thread.sleep(30000);
            System.out.println("30 seconds left before unfreezing...");
            Thread.sleep(30000);


            Action transferAction = Action.fromSerializable(
                    "zsw.items",
                    "transfer",
                    new Authorization[]{
                            new Authorization(keXinJieDianName, "active"),
                    },
                    new ZSWItemsTransfer(
                            keXinJieDianName,
                            userAName,
                            keXinJieDianName,
                            userBName,
                            keXinJieDianName,
                            1,
                            false,
                            3,
                            new String[]{ZSWIdHelper.getZSW40BitIdFromUUID(itemBUUID)},
                            new String[]{"1"},
                            "给用户B一个数字藏品"
                    )
            );
            SendTx(session,Arrays.asList(
                    new Action[]{
                            transferAction,

                    }));

            Thread.sleep(5000);

            ZSWCollectionsTableResponse collectionsResponse  = new Gson().fromJson(rpcProvider.getTableRows(
                    new GetTableRowsRequest(
                            "zsw.items",
                            "zsw.items",
                            "collections",
                            1,
                            "",
                            "",
                            "",
                            "",
                            20
                    )
            ), ZSWCollectionsTableResponse.class);

            System.out.println(collectionsResponse.rows[0].issued_supply);


            ZSWItemTemplatesTableResponse templatesResponse  = new Gson().fromJson(rpcProvider.getTableRows(
                    new GetTableRowsRequest(
                            "zsw.items",
                            "zsw.items",
                            "itemtemplate",
                            1,
                            "",
                            "",
                            "",
                            "",
                            20
                    )
            ), ZSWItemTemplatesTableResponse.class);

            System.out.println(ZSWIdHelper.getUUIDFromUint128String(templatesResponse.rows[0].zsw_id));



            ZSWItemsTableResponse itemsResponse  = new Gson().fromJson(rpcProvider.getTableRows(
                    new GetTableRowsRequest(
                            "zsw.items",
                            "zsw.items",
                            "items",
                            1,
                            "",
                            "",
                            "",
                            "",
                            20
                    )
            ), ZSWItemsTableResponse.class);
            System.out.println(itemsResponse.rows[0].item_template_id);

            ZSWItemsTableResponse itemsExactQueryResponse  = new Gson().fromJson(rpcProvider.getTableRows(
                    new GetTableRowsRequest(
                            "zsw.items",
                            "zsw.items",
                            "items",
                            1,
                            "",
                            "",
                            ZSWIdHelper.getZSW40BitIdFromUUID(itemBUUID),
                            "",
                            1
                    )
            ), ZSWItemsTableResponse.class);
            System.out.println(itemsExactQueryResponse.rows[0].serialized_immutable_metadata[0]);







        }catch(Exception e){
            System.err.println("ERROR: "+e.toString());
        }

    }
    public static TransactionProcessor getProcessor(TransactionSession sessionClone){

        TransactionSession session = new TransactionSession(
                sessionClone.getSerializationProvider(),
                sessionClone.getRpcProvider(),
                sessionClone.getAbiProvider(),
                sessionClone.getSignatureProvider()
        );

        TransactionProcessor processor = session.getTransactionProcessor();

// Now the TransactionConfig can be altered, if desired
        TransactionConfig transactionConfig = processor.getTransactionConfig();

// Use blocksBehind (default 3) the current head block to calculate TAPOS
        transactionConfig.setUseLastIrreversible(false);
// Set the expiration time of transactions 600 seconds later than the timestamp
// of the block used to calculate TAPOS
        transactionConfig.setExpiresSeconds(600);

// Update the TransactionProcessor with the config changes
        processor.setTransactionConfig(transactionConfig);
        return processor;
    }
    public static SendTransactionResponse SendTx(TransactionSession sessionClone, List<Action> actions) throws TransactionPrepareError, TransactionSignAndBroadCastError {
        TransactionProcessor proc = getProcessor(sessionClone);
        proc.prepare(actions);
        return proc.signAndBroadcast();
    }
    public static void main(String[] args) {

        try {
            System.out.println("Hello world!");
            TestFull();
        }catch(Exception e){
            System.err.println("ERROR: "+e.toString());
        }
    }
}