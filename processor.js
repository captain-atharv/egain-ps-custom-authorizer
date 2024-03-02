const Logger = require('ps-chronicle');
const jsonwebtoken = require('jsonwebtoken');
const azureADHandler = require('./azure-ad/processor');
const { convertObjectKeysToLower } = require('./util');

// eslint-disable-next-line import/no-dynamic-require

const { getSecret } = require(process.env.AWS_LAMBDA_FUNCTION_NAME
  ? '/opt/nodejs/aws-client/secret-manager-client/secret-manager-client'
  : '../../../../../../global/common/nodejs/aws-client/secret-manager-client/secret-manager-client.js');

const logger = new Logger('processor.js', 'json', process.env.LogLevel);

const generatePolicyDocument = (effect, methodArn) => {
  if (!effect || !methodArn) return null;

  const policyDocument = {
    Version: '2012-10-17',
    Statement: [
      {
        Action: 'execute-api:Invoke',
        Effect: effect,
        Resource: methodArn,
      },
    ],
  };

  return policyDocument;
};

const generateAuthResponse = (principalId, effect, methodArn) => {
  const policyDocument = generatePolicyDocument(effect, methodArn);

  return {
    principalId,
    policyDocument,
  };
};

/* This method does authorization of the input event.Checks whether the valid jwt in the event
is present in the authorization header or not */
const authorizeEvent = async (event) => {
  let effect = 'Deny';
  try {
    const lowerCasedHeaders = convertObjectKeysToLower(event.headers);

    const secretString = await getSecret('YOUR_SECRET_NAME');
    logger.log('info', 'Secret fetched successfully');
    const secretVal = JSON.parse(secretString);

    const options = {};
    options.algorithms = ['RS256'];
    options.audience = secretVal.audience;
    options.issuer = secretVal.issuer;

    let { authorization } = lowerCasedHeaders;
    authorization = authorization.replace('Bearer ', '');

    const decodedToken = jsonwebtoken.decode(authorization, { complete: true });
    options.kid = decodedToken.header.kid;

    const isValidToken = await azureADHandler.verifyToken(
      authorization,
      options,
      secretVal.tenantId,
    );

    logger.log('info', ' is JWT valid -> ', isValidToken);

    effect = isValidToken ? 'Allow' : 'Deny';
  } catch (error) {
    logger.log('error', {
      tags: `unhandled error - >${error} `,
      stack: error.stack,
    });
  }
  return generateAuthResponse(
    'apigateway.amazonaws.com',
    effect,
    event.methodArn,
  );
};

module.exports = {
  authorizeEvent,
};
