FROM php:7.2-apache

COPY ./src /var/www/html

RUN pecl install redis-5.3.7 \
	&& docker-php-ext-enable redis