<?php
namespace RKA\Middleware\Test;

use RKA\Middleware\ProxyDetection;
use Middlewares\Utils\Dispatcher;
use Zend\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;

class ProxyDetectionTest extends TestCase
{
    private function doRequest($request, &$scheme, &$host, &$port, $proxies = [])
    {
        // To fix decoding by other PSR framework
        $uri = $request->getUri();
        $uri = $uri->withScheme('http');
        $uri = $uri->withPort(80);
        $uri = $uri->withHost('foo.com');
        $request = $request->withUri($uri);

        Dispatcher::run(
            [
                new ProxyDetection($proxies),
                function ($request, $next) use (&$scheme, &$host, &$port) {
                    $scheme = $request->getUri()->getScheme();
                    $host = $request->getUri()->getHost();
                    $port = $request->getUri()->getPort();

                    return $next->handle($request);
                }
            ],
            $request
        );
    }

    public function testSchemeAndHostAndPortWithPortInHostHeader()
    {
        $request = ServerRequestFactory::fromGlobals([
            'REMOTE_ADDR' => '192.168.0.1',
            'HTTP_HOST' => 'foo.com',
            'HTTP_X_FORWARDED_PROTO' => 'https',
            'HTTP_X_FORWARDED_HOST' => 'example.com:1234',
        ]);

        $this->doRequest($request, $scheme, $host, $port);

        $this->assertSame('https', $scheme);
        $this->assertSame('example.com', $host);
        $this->assertSame(1234, $port);
    }

    public function testSchemeAndHostAndPortWithPortInPortHeader()
    {
        $request = ServerRequestFactory::fromGlobals([
            'REMOTE_ADDR' => '192.168.0.1',
            'HTTP_HOST' => 'foo.com',
            'HTTP_X_FORWARDED_PROTO' => 'https',
            'HTTP_X_FORWARDED_HOST' => 'example.com',
            'HTTP_X_FORWARDED_PORT' => '1234',
        ]);

        $this->doRequest($request, $scheme, $host, $port);

        $this->assertSame('https', $scheme);
        $this->assertSame('example.com', $host);
        $this->assertSame(1234, $port);
    }

    public function testSchemeAndHostAndPortWithPortInHostAndPortHeader()
    {
        $request = ServerRequestFactory::fromGlobals([
            'REMOTE_ADDR' => '192.168.0.1',
            'HTTP_HOST' => 'foo.com',
            'HTTP_X_FORWARDED_PROTO' => 'https',
            'HTTP_X_FORWARDED_HOST' => 'example.com:1000',
            'HTTP_X_FORWARDED_PORT' => '2000',
        ]);

        $this->doRequest($request, $scheme, $host, $port);

        $this->assertSame('https', $scheme);
        $this->assertSame('example.com', $host);
        $this->assertSame(1000, $port);
    }

    public function testTrustedProxies()
    {
        $request = ServerRequestFactory::fromGlobals([
            'REMOTE_ADDR' => '192.168.0.1',
            'HTTP_HOST' => 'foo.com',
            'HTTP_X_FORWARDED_PROTO' => 'https',
            'HTTP_X_FORWARDED_HOST' => 'example.com:1234',
        ]);

        $this->doRequest($request, $scheme, $host, $port, ['192.168.0.1']);

        $this->assertSame('https', $scheme);
        $this->assertSame('example.com', $host);
        $this->assertSame(1234, $port);
    }

    public function testNonTrustedProxies()
    {
        $request = ServerRequestFactory::fromGlobals([
            'REMOTE_ADDR' => '10.0.0.1',
            'HTTP_HOST' => 'foo.com',
            'HTTP_X_FORWARDED_PROTO' => 'https',
            'HTTP_X_FORWARDED_HOST' => 'example.com:1234',
        ]);

        $scheme = $request->getUri()->getScheme();
        $host = $request->getUri()->getHost();
        $port = $request->getUri()->getPort();

        $this->doRequest($request, $scheme, $host, $port, ['192.168.0.1']);

        $this->assertSame('http', $scheme);
        $this->assertSame('foo.com', $host);
        $this->assertSame(null, $port);
    }

    public function testTrustedProxiesCIDR()
    {
        $request = ServerRequestFactory::fromGlobals([
            'REMOTE_ADDR' => '192.168.0.1',
            'HTTP_HOST' => 'foo.com',
            'HTTP_X_FORWARDED_PROTO' => 'https',
            'HTTP_X_FORWARDED_HOST' => 'example.com:1234',
        ]);

        $this->doRequest($request, $scheme, $host, $port, ['192.168.0.0/24']);

        $this->assertSame('https', $scheme);
        $this->assertSame('example.com', $host);
        $this->assertSame(1234, $port);
    }

    public function testNonTrustedProxiesCIDR()
    {
        $request = ServerRequestFactory::fromGlobals([
            'REMOTE_ADDR' => '10.0.0.1',
            'HTTP_HOST' => 'foo.com',
            'HTTP_X_FORWARDED_PROTO' => 'https',
            'HTTP_X_FORWARDED_HOST' => 'example.com:1234',
        ]);

        $scheme = $request->getUri()->getScheme();
        $host = $request->getUri()->getHost();
        $port = $request->getUri()->getPort();

        $this->doRequest($request, $scheme, $host, $port, ['192.168.0.0/24']);

        $this->assertSame('http', $scheme);
        $this->assertSame('foo.com', $host);
        $this->assertSame(null, $port);
    }
}
