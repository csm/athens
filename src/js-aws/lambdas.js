const AWS = require('aws-sdk');
const crypto = require('crypto');
const jws = require('jws');

var s3 = null;
var dynamo = null;
var ssm = null;

var publicKey = null;
var privateKey = null;

async function authenticate(event, context) {
    if (publicKey == null) {
        if (ssm === null) {
            ssm = new AWS.SSM();
        }
        let secretResult = await ssm.getParameter({Name: '/Athens/authPublicKey', WithDecryption: false}).promise();
        publicKey = secretResult.Parameter.Value;
    }
    var token = event.headers.authorization;
    if (token == null || !token.startsWith('Bearer ')) {
        return {isAuthorized: false};
    }
    token = token.substr(7);
    if (jws.verify(token, 'ES256', publicKey)) {
        let claims = jws.decode(token).payload;
        if (claims.exp == null || claims.exp < Date.now() / 1000 || claims.sub == null) {
            return {isAuthorized: false};
        } else {
            return {isAuthorized: true, context: {uuid: claims.sub}};
        }
    } else {
        return {isAuthorized: false};
    }
}

async function login(event, context) {
    let params = JSON.parse(event.body);
    if (params.email == null || params.password == null) {
        return {statusCode: 400, body: JSON.stringify({error: 'Invalid request'})};
    }
    let hash = crypto.createHash('sha256');
    hash.update(params.email.toLowerCase());
    let emailHash = hash.digest('hex').toLowerCase();
    if (dynamo == null) {
        dynamo = new AWS.DynamoDB.DocumentClient();
    }
    let queryResult = await dynamo.scan({
        TableName: process.env.USERS_DYNAMODB_TABLE,
        IndexName: 'emailHash-index',
        ExclusiveStartKey: emailHash,
    }).promise();
    if (queryResult.Items.length == 0) {
        return {statusCode: 401, body: JSON.stringify({error: 'Invalid credentials'})};
    }
    let userInfo = queryResult.items[0];
    let computedHash = crypto.scryptSync(params.password, userInfo.salt, 64);
    if (userInfo.passwordHash != computedHash.toString('hex')) {
        return {statusCode: 401, body: JSON.stringify({error: 'Invalid credentials'})};
    }
    if (userInfo.expires != null && userInfo.expires < Date.now()) {
        return {statusCode: 401, body: JSON.stringify({error: 'Account expired'})};
    }
    if (privateKey == null) {
        if (ssm == null) {
            ssm = new AWS.SSM();
        }
        let secretResult = await ssm.getParameter({Name: '/Athens/authPrivateKey', WithDecryption: true}).promise();
        privateKey = secretResult.Parameter.Value;
    }
    let expires = Date.now() / 1000 + (24 * 60 * 60);
    if (userInfo.expires != null && userInfo.expires / 1000 < expires) {
        expires = userInfo.expires / 1000;
    }
    let token = jws.sign({
        header: {
            alg: 'ES256',
        },
        payload: {
            sub: userInfo.uuid,
            exp: expires,
            iat: Date.now() / 1000,
        },
        privateKey: privateKey,
    });
    return {
        statusCode: 200,
        body: JSON.stringify({
            token: token,
            uuid: userInfo.uuid,
        })
    };
}

async function getSignedUrl(event, context) {
    let uuid = context.authorizer.uuid;
    if (uuid == null) {
        return {statusCode: 401, body: JSON.stringify({error: 'Unauthorized'})};
    }
    if (s3 == null) {
        s3 = new AWS.S3();
    }
}