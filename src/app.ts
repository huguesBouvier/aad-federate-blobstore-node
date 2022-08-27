const express = require("express");
var logHelper = require("./utils/loghelper");
import gcpCredential from "./auth/gcpcredential";
import k8sCredential from "./auth/k8scredential";
import spiffeCredential from "./auth/spiffecredential";

import BlobStore from "./blobstore/blobhelper";
var httpStatus = require('http-status-codes');
var jwt = require("jsonwebtoken");

import { DefaultAzureCredential, EnvironmentCredential } from "@azure/identity";

const logger = logHelper.logger;

var port = 3001;

var app = express();
//
// initialize the logger
//
logHelper.init(app);


app.use(express.json());
app.use(express.urlencoded({ extended: true }));

var whereRunning:any = 'spiffe';
var federatedCredential:any = null;
var credential:any = null;

var clientID:any = 'a556fd84-d997-4cae-bea4-4839d0148ba5';
var tenantID:any = '3e235bd6-f0f9-4960-9124-f6beb8b6c288';
var authority:any = '';

switch (whereRunning) {
    case 'Google':
        logger.info("using gcp creds");

        federatedCredential = credential = new gcpCredential(clientID,
                                                            tenantID,
                                                            authority);
        break;

    case 'k8sMSAL': 
        logger.info("using K8s creds via MSAL");

        federatedCredential = credential = new k8sCredential(clientID,
                                                            tenantID,
                                                            authority);
        break;

    case 'k8sAzureIdentity':
        logger.info("using DefaultAzure creds for k8sAzureIdentity");

        credential = new DefaultAzureCredential();
        break;

    case 'spiffe':
        logger.info("using spiffecredential");
        federatedCredential = credential = new spiffeCredential(clientID,
                                                                tenantID,
                                                                authority);
        break;
        
  
    case 'local':
        logger.info("using env creds for local");
        credential = new EnvironmentCredential();
        break;

    default:
        logger.info("error: no credentials for %o", whereRunning);
        break;

}
logger.info("initialize store with cred %o", credential);                                        
var blobAccount:any = 'spiffefederate';

var blob = new BlobStore(blobAccount, credential);

app.get('/:container/:name', (req:any, res:any) => {
    let blobName = req.params.name;
    let containerName = req.params.container;
    return blob.getEntity(containerName, blobName)
    .then(function(data:any) {
        res.send(data);
        logger.debug("get returned %o", data);
    })
    .catch(function(error:any) {
        logHelper.logger.error("app get error %o", error);
        res.status(httpStatus.INTERNAL_SERVER_ERROR).send(error);

    });
});

app.post('/:container/:name', (req:any, res:any) => {
    let blobName = req.params.name;
    let containerName = req.params.container;
    return blob.setEntity(containerName, blobName, req.body.value)
    .then(function(data:any) {
        res.send(data);
        logger.debug("post returned %o", data);
    })
    .catch(function(error:any) {
        logger.error("app post error %o", error);
        res.status(httpStatus.INTERNAL_SERVER_ERROR).send(error);

    });
});

app.get('/issued', (req:any, res:any) => {
    if (federatedCredential == null) {
        res.status(httpStatus.BAD_REQUEST).send("not federated credential");
        return;
    }
    federatedCredential.getFederatedToken()
    .then (function(response:any) {
        logger.info(response);
        var decoded = jwt.decode(response, {complete : true});
        logger.info("decoded issued %o", decoded);
        return (req.query.decode) ?  decoded:  response;
        return response;
    })
    .then(function(response:any) {
        res.json(response);
        return;
    })
    .catch(function(error:any) {
        logger.info(error);
        res.status(httpStatus.INTERNAL_SERVER_ERROR).send();
        return;
    })
})

app.get('/exchanged', (req:any, res:any) => {
    var scope = req.query.scope? req.query.scope : "https://vault.azure.net/.default";
    credential.getToken(scope)
    .then (function(response:any) {
        logger.info(response);
        var decoded = jwt.decode(response.token, {complete : true});
        logger.info("decoded exchanged %o", decoded);
        return (req.query.decode) ?  decoded:  response;
        return response;
    })
    .then (function(response:any) {
        res.json(response);
        return;
    })
    .catch(function(error:any) {
        logger.info(error);
        res.status(httpStatus.INTERNAL_SERVER_ERROR).send(error);
        return;
    })
})


app.listen(port);
logHelper.logger.info("express now running on poprt %d", port);

