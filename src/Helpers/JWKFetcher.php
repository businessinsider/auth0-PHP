<?php

namespace Auth0\SDK\Helpers;

use Auth0\SDK\API\Helpers\RequestBuilder;
use Auth0\SDK\Helpers\Cache\CacheHandler;
use Auth0\SDK\Helpers\Cache\NoCacheHandler;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ClientException;

/**
 * Class JwksLocal
 */
class JwksLocal
{
    public $jwks;

    public function __construct()
    {
        $this->jwks = (object) [
            'keys' => array(
                (object) [
                'alg' => 'RS256',
                'kty' => 'RSA',
                'use' => 'sig',
                'n' => '3LTNxIFER3x-2E0vC1T_O8PWIWvQqcVrVOo7dV_x5EVmTz82ek6D0M0syYm4jI9zLSC0iV9C-d_vyTRnRc_IoTxIAulQmvZLysYqgmOFzPdAFwiUWkzSvANX-ywxYtS-hH_459nZwl75DIq9UFUYLJcC9f40aBc9buaUclaYJAqbgkSP_GM22zTddDmg4_YuT97UKhv-atoSFXhUkKON2aIyuiHEX74dHKOetmZGEe0lqADcFNbIKO4FDye0hpRvjCeUMSnnOfNX6-yYJmQk13YtN_tNi94F8trhSXyza2l4g3mmI4xZeyjx8R184RsPuMB5b1x3j8DAUKmqVUaKiQ',
                'e' => 'AQAB',
                'kid' => 'OTFGMDVFMTEyREIxOUFBNzQxRjVGQjZDM0FCMTc3NDdGNUFDMkM1Ng',
                'x5t' => 'OTFGMDVFMTEyREIxOUFBNzQxRjVGQjZDM0FCMTc3NDdGNUFDMkM1Ng',
                'x5c' => array('MIIDDTCCAfWgAwIBAgIJIaF0+xSPCe0dMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWJ1c2luZXNzaW5zaWRlci5hdXRoMC5jb20wHhcNMTcxMjE0MTcxNDUzWhcNMzEwODIzMTcxNDUzWjAkMSIwIAYDVQQDExlidXNpbmVzc2luc2lkZXIuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3LTNxIFER3x+2E0vC1T/O8PWIWvQqcVrVOo7dV/x5EVmTz82ek6D0M0syYm4jI9zLSC0iV9C+d/vyTRnRc/IoTxIAulQmvZLysYqgmOFzPdAFwiUWkzSvANX+ywxYtS+hH/459nZwl75DIq9UFUYLJcC9f40aBc9buaUclaYJAqbgkSP/GM22zTddDmg4/YuT97UKhv+atoSFXhUkKON2aIyuiHEX74dHKOetmZGEe0lqADcFNbIKO4FDye0hpRvjCeUMSnnOfNX6+yYJmQk13YtN/tNi94F8trhSXyza2l4g3mmI4xZeyjx8R184RsPuMB5b1x3j8DAUKmqVUaKiQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ5qq0glYDC4+Y2wQUkeJhjUaxvRjAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAA7IxzErSVa/ZaeVXM7loqb1AxAfJqHAxxCVnX6VNP44GZBEpi5Dnzt1B3vW0QqqTpCkP8eeKSbtwfwSYhwqCXCToQQjiT2l/6CnEy/d99bnbWDBFN+6mFBGGZhYXlCiiGgNFpN4D/ykPF5GU1uA6aMC6PXRUTKJDSfOlkTH7q8CubF3/dAWlLF/uHCM2mTEQwXQzdbxeYy9OPPct8SnBG9Cg7j93vImrjYkQ4JJXOEoE4+DuXNAusXB91pjd8HznEpcDYV5LdpBAmh2qBr4p1umtmm010Y8f+fu4yq4bYv8jHBYyZ+IYuXXNg3O2UDn7kvm6oZtPL+A8zZp4meQC14=')
                ],
                (object) [
                    'alg' => 'RS256',
                    'kty' => 'RSA',
                    'use' => 'sig',
                'n' => 'rDz1J1aLDL5GZQI2SenWZGo8GnYr1QbB6b-Xb7o9tO5klmqlmshh3_GsP_UB1jOt2iU3kht1kJ4E2UiwPdK3j21CLKTvJurdFeOKlWiunz1QmF3dw4HNHuzGBGs7PDy92186PLhhDNEfSVQ7ZfqRt_S4TY-cubWTMiHKcOdbvReNJLhvRPnwT9WIZlJXrhl3S2fIBFnmX1ORclFG8cGl4j907WuIyBzl4LqsZmC2zpOjBfQcG-mGrTkQrjl8RgxjGRNh52PTTF5dgxL4xG0yAnKd6-OY3ZiX-B6h61cl2e4cNz1lHXYfSg3ZLwtOI0XLHoh43Wud69VUliaMRN9_-Q',
                'e' => 'AQAB',
                'kid' => '3o1DyvhYcGQyNT5SYfZuM',
                'x5t' => 'ZkgeYZffaB3TF8JgIgf9mcNsqvQ',
                'x5c' => array('MIIDDTCCAfWgAwIBAgIJR3rF18ynqWXKMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWJ1c2luZXNzaW5zaWRlci5hdXRoMC5jb20wHhcNMjAwMzE3MjA1OTI4WhcNMzMxMTI0MjA1OTI4WjAkMSIwIAYDVQQDExlidXNpbmVzc2luc2lkZXIuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArDz1J1aLDL5GZQI2SenWZGo8GnYr1QbB6b+Xb7o9tO5klmqlmshh3/GsP/UB1jOt2iU3kht1kJ4E2UiwPdK3j21CLKTvJurdFeOKlWiunz1QmF3dw4HNHuzGBGs7PDy92186PLhhDNEfSVQ7ZfqRt/S4TY+cubWTMiHKcOdbvReNJLhvRPnwT9WIZlJXrhl3S2fIBFnmX1ORclFG8cGl4j907WuIyBzl4LqsZmC2zpOjBfQcG+mGrTkQrjl8RgxjGRNh52PTTF5dgxL4xG0yAnKd6+OY3ZiX+B6h61cl2e4cNz1lHXYfSg3ZLwtOI0XLHoh43Wud69VUliaMRN9/+QIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRM/Nv/VhKd96EENvA1HComYmCldTAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAIxZewBhq2pKjFLv585aFRQaAp1foLAFroCO+Twap33bqt8tgXR0JW+JWsCCS8n0q2uUIGcEjc1TLMKJZ0T3HzfuIc8CRaMeNKWBISHxmgOzZu4ZjlmSadcPzKSjC8Adus+ZlK8/jnqd4LlMD9/N3TEX6Esj8fwvXN5sB+hZSjllnXreB7DfmtgIO4ybBUPNx1oOLUqV6efvW2/8BBsaL7byDU20qCAUa7CJULJsiS0xGhXvvpwdsiYjmBSWGo5a30FZaygL9+jgPqbnjJmcS31mNo567cT+UdKh0Wk1nl+kHwhwobzP5atb+feQKvR9yLWUba1x6zn/VAbRyFIIf5E=')
                ]
            )
        ];
    }
}

/**
 * Class JWKFetcher.
 *
 * @package Auth0\SDK\Helpers
 */
class JWKFetcher
{

    /**
     * Cache handler or null for no caching.
     *
     * @var CacheHandler|null
     */
    private $cache;

    /**
     * Options for the Guzzle HTTP client.
     *
     * @var array
     */
    private $guzzleOptions;

    /**
     * JWKFetcher constructor.
     *
     * @param CacheHandler|null $cache         Cache handler or null for no caching.
     * @param array             $guzzleOptions Options for the Guzzle HTTP client.
     */
    public function __construct(CacheHandler $cache = null, array $guzzleOptions = [])
    {
        if ($cache === null) {
            $cache = new NoCacheHandler();
        }

        $this->cache         = $cache;
        $this->guzzleOptions = $guzzleOptions;
    }

    /**
     * Convert a certificate to PEM format.
     *
     * @param string $cert X509 certificate to convert to PEM format.
     *
     * @return string
     */
    protected function convertCertToPem($cert)
    {
        $output  = '-----BEGIN CERTIFICATE-----'.PHP_EOL;
        $output .= chunk_split($cert, 64, PHP_EOL);
        $output .= '-----END CERTIFICATE-----'.PHP_EOL;
        return $output;
    }

    /**
     * Gets an array of keys from the JWKS as kid => x5c.
     *
     * @param string $jwks_url Full URL to the JWKS.
     * @param boolean $static_well_known Whether to use local hardcoded jwks or not
     *
     * @return array
     */
    public function getKeys($jwks_url, $static_well_known = false)
    {
        $keys = $this->cache->get($jwks_url);
        if (is_array($keys) && ! empty($keys)) {
            return $keys;
        }

        //for testing
        //$static_well_known = false; 
        
        if ($static_well_known) {
            //$strJsonFileContents = file_get_contents("./jwks.json");
            //$jwks = json_decode($strJsonFileContents, true);
            $jwksLocal = new JwksLocal();
            $jwks = $jwksLocal->jwks;
        } else {
            $jwks = $this->requestJwks($jwks_url);
        }

        if (empty( $jwks ) || empty( $jwks['keys'] )) {
            return [];
        }

        $keys = [];
        foreach ($jwks['keys'] as $key) {
            if (empty( $key['kid'] ) || empty( $key['x5c'] ) || empty( $key['x5c'][0] )) {
                continue;
            }

            $keys[$key['kid']] = $this->convertCertToPem( $key['x5c'][0] );
        }

        $this->cache->set($jwks_url, $keys);
        return $keys;
    }

    /**
     * Fetch x509 cert for RS256 token decoding.
     *
     * @deprecated 5.6.0, use $this->getKeys().
     *
     * @param string      $jwks_url URL to the JWKS.
     * @param string|null $kid      Key ID to use; returns first JWK if $kid is null or empty.
     *
     * @return string|null - Null if an x5c key could not be found for a key ID or if the JWKS is empty/invalid.
     */
    public function requestJwkX5c($jwks_url, $kid = null)
    {
        $cache_key = $jwks_url.'|'.$kid;

        $x5c = $this->cache->get($cache_key);
        if (! is_null($x5c)) {
            return $x5c;
        }

        $jwks = $this->requestJwks($jwks_url);
        $jwk  = $this->findJwk($jwks, $kid);

        if ($this->subArrayHasEmptyFirstItem($jwk, 'x5c')) {
            return null;
        }

        $x5c = $this->convertCertToPem($jwk['x5c'][0]);
        $this->cache->set($cache_key, $x5c);
        return $x5c;
    }

    /**
     * Get a JWKS from a specific URL.
     *
     * @param string $jwks_url URL to the JWKS.
     *
     * @return mixed|string
     *
     * @throws RequestException If $jwks_url is empty or malformed.
     * @throws ClientException  If the JWKS cannot be retrieved.
     *
     * @codeCoverageIgnore
     */
    protected function requestJwks($jwks_url)
    {
        $request = new RequestBuilder([
            'domain' => $jwks_url,
            'method' => 'GET',
            'guzzleOptions' => $this->guzzleOptions
        ]);
        return $request->call();
    }

    /**
     * Get a JWK from a JWKS using a key ID, if provided.
     *
     * @deprecated 5.6.0, use $this->getKeys().
     *
     * @param array       $jwks JWKS to parse.
     * @param null|string $kid  Key ID to return; returns first JWK if $kid is null or empty.
     *
     * @return array|null Null if the keys array is empty or if the key ID is not found.
     *
     * @codeCoverageIgnore
     */
    private function findJwk(array $jwks, $kid = null)
    {
        if ($this->subArrayHasEmptyFirstItem($jwks, 'keys')) {
            return null;
        }

        if (! $kid) {
            return $jwks['keys'][0];
        }

        foreach ($jwks['keys'] as $key) {
            if (isset($key['kid']) && $key['kid'] === $kid) {
                return $key;
            }
        }

        return null;
    }

    /**
     * Check if an array within an array has a non-empty first item.
     *
     * @deprecated 5.6.0, not used.
     *
     * @param array|null $array Main array to check.
     * @param string     $key   Key pointing to a sub-array.
     *
     * @return boolean
     *
     * @codeCoverageIgnore
     */
    private function subArrayHasEmptyFirstItem($array, $key)
    {
        return empty($array) || ! is_array($array[$key]) || empty($array[$key][0]);
    }

    /*
     * Deprecated
     */

    // phpcs:disable
    /**
     * Appends the default JWKS path to a token issuer to return all keys from a JWKS.
     *
     * @deprecated 5.4.0, use requestJwkX5c instead.
     *
     * @param string $iss
     *
     * @return array|mixed|null
     *
     * @throws \Exception
     *
     * @codeCoverageIgnore
     */
    public function fetchKeys($iss)
    {
        $url = "{$iss}.well-known/jwks.json";

        if (($secret = $this->cache->get($url)) === null) {
            $secret = [];

            $request = new RequestBuilder([
                'domain' => $iss,
                'basePath' => '.well-known/jwks.json',
                'method' => 'GET',
                'guzzleOptions' => $this->guzzleOptions
            ]);
            $jwks    = $request->call();

            foreach ($jwks['keys'] as $key) {
                $secret[$key['kid']] = $this->convertCertToPem($key['x5c'][0]);
            }

            $this->cache->set($url, $secret);
        }

        return $secret;
    }
    // phpcs:enable
}
