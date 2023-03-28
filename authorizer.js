const { CognitoJwtVerifier } = require('aws-jwt-verify');

const COGNITO_USERPOOL_ID = process.env.COGNITO_USERPOOL_ID;
const COGNITO_WEB_CLIENT_ID = process.env.COGNITO_WEB_CLIENT_ID;

const jwtVerifier = CognitoJwtVerifier.create({
  userPoolId: COGNITO_USERPOOL_ID,
  tokenUse: 'id',
  clientId: COGNITO_WEB_CLIENT_ID,
});

var generatePolicy = function (principalId, effect, resource) {
  var authResponse = {};

  authResponse.principalId = principalId;
  if (effect && resource) {
    var policyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: effect,
          Resource: resource,
        },
      ],
    };
    authResponse.policyDocument = policyDocument;
  }

  // Optional output with custom properties of the String, Number or Boolean type.
  authResponse.context = {
    stringKey: 'stringval',
    numberKey: 123,
    booleanKey: true,
  };
  return authResponse;
};

exports.handler = async (event, context, callback) => {
  var token = event.authorizationToken;
  console.log(token);

  try {
    const payload = await jwtVerifier.verify(token);
    console.log(JSON.stringify(payload));
    callback(null, generatePolicy('user', 'Allow', event.methodArn));
  } catch (e) {
    // callback('Error: Invalid token');
    callback(null, generatePolicy('user', 'Deny', event.methodArn));
  }

  // switch (token) {
  //   case 'allow':
  //     callback(null, generatePolicy('user', 'Allow', event.methodArn));
  //     break;
  //   case 'deny':
  //     callback(null, generatePolicy('user', 'Deny', event.methodArn));
  //     break;
  //   case 'unauthorized':
  //     callback('Unauthorized'); // Return a 401 Unauthorized response
  //     break;
  //   default:
  //     callback('Error: Invalid token'); // Return a 500 Invalid token response
  // }
};
