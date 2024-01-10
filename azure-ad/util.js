const Logger = require('ps-chronicle');
const jsonwebtoken = require('jsonwebtoken');

const logger = new Logger('azure-ad-util.js', 'json', process.env.LogLevel);
const axios = require('axios');
const getPem = require('rsa-pem-from-mod-exp');

const isTokenIssuedForValidClaimTenantId = (decodedToken, authorizedTenantId) => {
  let isValid = false;
  if (decodedToken) {
    if (decodedToken['http://egain.net/claims/identity/tenant'] === authorizedTenantId) {
      isValid = true;
    }
  }
  return isValid;
};

const isTokenExpired = (decodedToken) => {
  let isExpired = false;
  const { exp } = decodedToken.payload;
  const currentDate = new Date().getTime();

  if (currentDate < exp * 1000) {
    logger.log('debug', { tags: 'Token is not expired' });
  } else {
    logger.log('error', { tags: 'Token is expired', exp, currentDate });
    isExpired = true;
  }
  return isExpired;
};

const requestOpenIdConfig = async (options) => {
  // we need to load the tenant specific open id config
  // https://egainqeb2cgw2.b2clogin.com/tfp/c19f8e1f-0bba-45c2-a8f7-e33ce3d55ac8/b2c_1a_user_signin_oidc/v2.0/.well-known/openid-configuration
  const tenantOpenIdconfig = {
    url: `${options.issuer}.well-known/openid-configuration`,
    method: 'get',
  };
  const response = {
    isError: true,
    data: '',
  };

  try {
    const openIdConfigRes = await axios(tenantOpenIdconfig);
    logger.log('info', { tags: 'Open id config fetched successfully' });
    response.isError = false;
    response.data = openIdConfigRes.data;
  } catch (err) {
    logger.log('error', {
      tags: 'error while getting open id config',
      errorCode: err.response
        ? err.response.status
        : 'ERROR_STATUS_NOT_FOUND',
      errorMessage: err.response ? err.response.data : err.stack,
    });
  }

  return response;
};

const requestSigningCertificates = async (jwtSigningKeysLocation, options) => {
  const jwtSigningKeyRequestOptions = {
    url: jwtSigningKeysLocation,
    method: 'get',
  };

  const response = {
    isError: true,
    data: '',
  };

  try {
    const certRes = await axios(jwtSigningKeyRequestOptions);
    logger.log('info', { tags: 'Public key for certificate fetched successfully' });
    const certificates = [];
    const result = certRes.data;
    // Use KID to locate the public key and store the certificate chain.
    if (options && options.kid) {
      result.keys.find((publicKey) => {
        if (publicKey.kid === options.kid) {
          certificates.push(getPem(publicKey.n, publicKey.e));
        }
      });
    } else {
      result.keys.forEach((key) => {
        certificates.push(getPem(key.n, key.e));
      });
    }
    response.isError = false;
    response.data = certificates;
  } catch (err) {
    logger.log('error', {
      tags: 'error while getting certificates',
      errorCode: err.response
        ? err.response.status
        : 'ERROR_STATUS_NOT_FOUND',
      errorMessage: err.response ? err.response.data : err.stack,
    });
  }
  return response;
};

const verifyAll = (jwt, certificates, options) => {
  let errorDetails = '';
  const jwtParams = JSON.parse(JSON.stringify(options));
  delete jwtParams.audience;
  delete jwtParams.issuer;
  for (let i = 0; i < certificates.data.length; i += 1) {
    logger.log('debug', `Verifying for certificate number -> ${i}`);
    try {
      jsonwebtoken.verify(jwt, certificates.data[i], jwtParams);
      logger.log('info', { tags: 'Token authorized successfully' });
      return true;
    } catch (err) {
      errorDetails = {
        err,
        errorMessage: err.stack,
      };
    }
  }
  logger.log('error', {
    tags: 'error while authorizing token',
    errorDetails,
  });
  return false;
};

module.exports = {
  isTokenIssuedForValidClaimTenantId,
  isTokenExpired,
  requestOpenIdConfig,
  requestSigningCertificates,
  verifyAll,
};
