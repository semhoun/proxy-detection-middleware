<?php
namespace RKA\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\UriInterface;

class ProxyDetection implements MiddlewareInterface
{
    /**
     * List of trusted proxy IP addresses
     *
     * If not empty, then one of these IP addresses must be in $_SERVER['REMOTE_ADDR']
     * in order for the proxy headers to be looked at.
     *
     * @var array
     */
    protected $trustedProxies;

    /**
     * Constructor
     *
     * @param array $trustedProxies   List of IP addresses of trusted proxies
     */
    public function __construct($trustedProxies = [])
    {
        $this->trustedProxies = $trustedProxies;
    }

    /**
     * Override the request URI's scheme, host and port as determined from the proxy headers
     *
     * @param  ServerRequestInterface  $request PSR-7 request
     * @param  RequestHandlerInterface $handler PSR-15 request handler
     *
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!empty($this->trustedProxies)) {
            // get IP address from REMOTE_ADDR
            $ipAddress = null;
            $serverParams = $request->getServerParams();
            if (isset($serverParams['REMOTE_ADDR']) && $this->isValidIpAddress($serverParams['REMOTE_ADDR'])) {
                $ipAddress = $serverParams['REMOTE_ADDR'];
            } else {
                return $handler->handle($request);
            }

            $allow = false;

            foreach ($this->trustedProxies as $proxy) {
                // If IP has / means CIDR notation
                if (strpos($proxy, '/') === false) {
                    // Check Single IP
                    if (inet_pton($ipAddress) == inet_pton($proxy)) {
                        $allow = true;
                        break;
                    }
                } else {
                    // Check IP range
                    list($subnet, $bits) = explode('/', $proxy);

                    // Convert subnet to binary string of $bits length
                    $subnet = unpack('H*', inet_pton($subnet)); // Subnet in Hex
                    foreach ($subnet as $i => $h) {
                        $subnet[$i] = base_convert($h, 16, 2); // Array of Binary
                    }
                    $subnet = substr(implode('', $subnet), 0, $bits); // Subnet in Binary, only network bits

                    // Convert remote IP to binary string of $bits length
                    $ip = unpack('H*', inet_pton($ipAddress)); // IP in Hex
                    foreach ($ip as $i => $h) {
                        $ip[$i] = base_convert($h, 16, 2); // Array of Binary
                    }
                    $ip = substr(implode('', $ip), 0, $bits); // IP in Binary, only network bits

                    // Check network bits match
                    if ($subnet == $ip) {
                        $allow = true;
                        break;
                    }
                }
            }
            if (!$allow) {
                return $handler->handle($request);
            }
        }

        $uri = $request->getUri();

        $uri = $this->processProtoHeader($request, $uri);
        $uri = $this->processPortHeader($request, $uri);
        $uri = $this->processHostHeader($request, $uri);

        $request = $request->withUri($uri);

        return $handler->handle($request);
    }

    /**
     * Check that a given string is a valid IP address
     *
     * @param  string  $ip
     * @return boolean
     */
    protected function isValidIpAddress($ip)
    {
        $flags = FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6;
        if (filter_var($ip, FILTER_VALIDATE_IP, $flags) === false) {
            return false;
        }
        return true;
    }

    protected function processProtoHeader(ServerRequestInterface $request, UriInterface $uri)
    {
        if ($request->hasHeader('X-Forwarded-Proto')) {
            $scheme = $request->getHeaderLine('X-Forwarded-Proto');

            if (in_array($scheme, ['http', 'https'])) {
                return $uri->withScheme($scheme);
            }
        }
        return $uri;
    }

    protected function processPortHeader(ServerRequestInterface $request, UriInterface $uri)
    {
        if ($request->hasHeader('X-Forwarded-Port')) {
            $port = trim(current(explode(',', $request->getHeaderLine('X-Forwarded-Port'))));

            if (preg_match('/^\d+\z/', $port)) {
                return $uri->withPort((int) $port);
            }
        }
        return $uri;
    }

    protected function processHostHeader(ServerRequestInterface $request, UriInterface $uri)
    {
        if ($request->hasHeader('X-Forwarded-Host')) {
            $host = trim(current(explode(',', $request->getHeaderLine('X-Forwarded-Host'))));

            $port = null;
            if (preg_match('/^(\[[a-fA-F0-9:.]+\])(:\d+)?\z/', $host, $matches)) {
                $host = $matches[1];
                if ($matches[2]) {
                    $port = (int) substr($matches[2], 1);
                }
            } else {
                $pos = strpos($host, ':');
                if ($pos !== false) {
                    $port = (int) substr($host, $pos + 1);
                    $host = strstr($host, ':', true);
                }
            }
            $uri = $uri->withHost($host);
            if ($port) {
                $uri = $uri->withPort($port);
            }
        }
        return $uri;
    }
}
