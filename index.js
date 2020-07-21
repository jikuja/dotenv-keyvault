'use strict';
// @ts-check

const request = require('request-promise');

const logger = console;

function log (message) {
    console.log(`[dotenv-keyvault][DEBUG] ${message}`)
  }

/**
 * @param {*} endpoint
 * @param {*} secret
 * @returns {string} the Active Directory Access token
 */
function getAADTokenFromMSI(endpoint, secret, resource) {
    const apiVersion = '2017-09-01';

    const options = {
        uri: `${endpoint}/?resource=${resource}&api-version=${apiVersion}`,
        headers: {
            Secret: secret,
        },
        json: true,
    };

    return request(options)
        .then((response) => response.access_token);
}

function getAadAccessToken(aadAccessToken, dotenvParsed) {
    if (!Object.values(dotenvParsed).find(x => x.startsWith('kv:'))) {
        // no values starting with 'kv:' => no data to fetch from KV => no need to fetch AAD Token
        return
    }

    let aadToken;
    if (!aadAccessToken) {
        // no token - get one using Managed Service Identity inside process.env
        const resource = 'https://vault.azure.net';
        aadToken = getAADTokenFromMSI(process.env.MSI_ENDPOINT, process.env.MSI_SECRET, resource);
    }
    else if (typeof aadAccessToken === 'function') {
        aadToken = aadAccessToken();
    }
    else if (typeof aadAccessToken === 'string') {
        aadToken = aadAccessToken;
    }
    return aadToken;
};

class UnableToPopulateKVBackedEnvVarError extends Error {
};

module.exports = {
    /**
     * @param {{aadAccessToken:*}} props
     */
    config(props = {}) {
        const { aadAccessToken } = props;

        return (dotenvConfig = {}) => {
            const dotenvParsed = dotenvConfig.parsed || {};
            const envWithKeyvault = Object.assign({}, dotenvParsed);
            const aadToken = getAadAccessToken(aadAccessToken, dotenvParsed);
            const debug = Boolean(props && props.debug)
            return Promise.resolve(aadToken).then((token) => {
                const fetches = Object.keys(dotenvParsed)
                    .filter((key) => dotenvParsed[key].match(/^kv:/))
                    .map((key) => {
                        // environment variable will have higher precedence than .env file value
                        const value = process.env[key] ? process.env[key] : dotenvParsed[key]
                        const uri = value.replace(/^kv:/, '') + '?api-version=2016-10-01';
                        return new Promise((resolve, reject) => {
                            return request({
                                method: 'GET',
                                json: true,
                                uri,
                                headers: {
                                    Authorization: `Bearer ${token}`,
                                },
                            }).then((secretResponse) => {
                                // overwrite the value because we are enriching data and dotenv does not know about kv: marked data
                                process.env[key] = secretResponse.value
                                envWithKeyvault[key] = secretResponse.value;
                                resolve();
                            }).catch((err) => {
                                logger.error('Problem fetching KeyVault secret for', key, err.message);
                                reject(err);
                            });
                        });
                    });
                return Promise.all(fetches)
                    .then(() => envWithKeyvault)
                    // TODO: collect errors for UnableToPopulateKVBackedEnvVarError
                    .catch((reason) => { throw new UnableToPopulateKVBackedEnvVarError(reason) });
            });
        };
    },
    UnableToPopulateKVBackedEnvVarError
};
