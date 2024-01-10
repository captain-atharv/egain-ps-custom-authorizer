const Logger = require('ps-chronicle');
const azureADUtil = require('./util');

const logger = new Logger('azure-ad-processor.js', 'json', process.env.LogLevel);
let openIdConfig = '';
let certificates = '';

exports.verifyToken = async (jwtString, options, authorizedTenantId) => {
  let isValidToken = false;
  try {
    // const decodedToken = jsonwebtoken.decode(jwtString);

    // Call this method ONLY IF tenant ID is present in JWT
    // Store expected tenant ID in secret and pass it to method. Eg: authorizedTenantId
    // const isAuthorizedTenant = azureADUtil.isTokenIssuedForValidClaimTenantId(jwtString, authorizedTenantId);
    // if(!isAuthorizedTenant){
    //     logger.log('error', 'JWT not issued for valid tenant');
    //     return isValidToken;
    // }

    if (!openIdConfig) {
      const openIdConfigRes = await azureADUtil.requestOpenIdConfig(options);
      if (openIdConfigRes.isError) {
        return isValidToken;
      }
      openIdConfig = openIdConfigRes.data;
    }

    if (!certificates) {
      const certData = await azureADUtil.requestSigningCertificates(
        openIdConfig.jwks_uri,
        options,
      );
      if (certData.isError) {
        return isValidToken;
      }
      certificates = certData;
    }

    isValidToken = azureADUtil.verifyAll(jwtString, certificates, options);
  } catch (error) {
    logger.log('error', {
      tags: `unhandled error - >${error} `,
      stack: error.stack,
    });
  }
  return isValidToken;
};
