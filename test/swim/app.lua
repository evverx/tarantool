#!/usr/bin/env tarantool
os = require('os')
box.cfg{}
swim = require('swim')
require('swim_utils')
listen_uri = os.getenv('LISTEN')
parsed_uri = require('uri').parse(listen_uri)
listen_port = parsed_uri.service
listen_host = parsed_uri.host
if listen_host == 'localhost' then
    listen_host = '127.0.0.1'
    listen_uri = listen_host..':'..listen_port
end
require('console').listen(os.getenv('ADMIN'))
test_run = require('test_run').new()
