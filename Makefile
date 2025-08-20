.PHONY: test

test:
	vendor/bin/phpunit --bootstrap vendor/autoload.php tests 

debug-test:
	php -dxdebug.mode=debug -dxdebug.start_with_request=yes  vendor/bin/phpunit --no-output --log-events-text php://stdout --bootstrap vendor/autoload.php tests