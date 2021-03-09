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
        let claims = JSON.parse(jws.decode(token).payload);
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
    let queryResult = await dynamo.get({
        TableName: process.env.USERS_DYNAMODB_TABLE,
        Key: {emailHash},
    }).promise();
    if (queryResult.Item == null) {
        return {statusCode: 401, body: JSON.stringify({error: 'Invalid credentials'})};
    }
    let userInfo = queryResult.Item;
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

function getSignedUrl(s3client, op, args) {
    return new Promise((resolve, reject) => {
        s3client.getSignedUrl(op, args, (err, url) => {
            if (err != null) {
                reject(err);
            } else {
                resolve(url);
            }
        })
    })
}

async function getSignedUrls(event, context) {
    let uuid = event.requestContext.authorizer.lambda.uuid;
    if (uuid == null) {
        return {statusCode: 401, body: JSON.stringify({error: 'Unauthorized'})};
    }
    if (s3 == null) {
        s3 = new AWS.S3();
    }
    let getKeyUrl = await getSignedUrl(s3, 'getObject', {
        Bucket: process.env.S3_BUCKET,
        Key: `athens/${uuid}/.key`,
    });
    let putKeyUrl = await getSignedUrl(s3, 'putObject', {
        Bucket: process.env.S3_BUCKET,
        Key: `athens/${uuid}/.key`,
    });
    let getDataUrl = await getSignedUrl(s3, 'getObject', {
        Bucket: process.env.S3_BUCKET,
        Key: `athens/${uuid}/index.transit`,
    });
    let putDataUrl = await getSignedUrl(s3, 'putObject', {
        Bucket: process.env.S3_BUCKET,
        Key: `athens/${uuid}/index.transit`
    });
    return {
        statusCode: 200,
        headers: {"content-type": "application/json"},
        body: JSON.stringify({
            getKeyUrl,
            putKeyUrl,
            getDataUrl,
            putDataUrl,
        })
    };
}

module.exports.authenticate = authenticate;
module.exports.login = login;
module.exports.getSignedUrls = getSignedUrls;