# Proxy Scheme, Host and Port detection middleware

[![Build status][Master image]][Master]

PSR-7 Middleware that determines the scheme, host and port from the 'X-Forwarded-Proto', 'X-Forwarded-Host' and 'X-Forwarded-Port' headers and updates the Request's Uri object.

You can set a list of proxies that are trusted as the second constructor parameter. If this list is set, then the proxy headers will only be checked if the `REMOTE_ADDR` is in the trusted list.


## Installation

`composer require semhoun/proxy-detection-middleware`


## Usage

In Slim 4:

```php
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Slim\Factory\AppFactory;
use Slim\Psr7\Response;

require __DIR__ . '/../vendor/autoload.php';

$app = AppFactory::create();

$trustedProxies = ['10.0.0.1', '10.0.0.2', '192.168.0.0/24'];
$app->add(new RKA\Middleware\ProxyDetection($trustedProxies));

$app->get('/', function (Request $request, Response $response, $args) {
    $scheme = $request->getUri()->getScheme();
    $host = $request->getUri()->getHost();
    $port = $request->getUri()->getPort();

    $response->getBody()->write('Real URI is ' . $scheme . '://' . $host . ':' . $port);
    return $response;
});

$app->run();
```

## Testing

* Code coverage: ``$ vendor/bin/phpcs``
* Unit tests: ``$ vendor/bin/phpunit``


[Master]: https://travis-ci.org/semhoun/rka-content-type-renderer
[Master image]: https://secure.travis-ci.org/semhoun/rka-content-type-renderer.svg?branch=master
