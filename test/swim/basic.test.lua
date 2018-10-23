test_run:cmd("push filter ':"..listen_port.."' to ':listen_port'")
--
-- gh-3234: SWIM - Scalable Weakly-consistent Infection-style
-- Process Group Membership Protocol. Here are some basic tests on
-- cfg checking, binding to an existing address etc.
--

-- Info() and stop() on non-working server.
swim_info_sorted()
swim.stop()

-- Empty and multiple cfg is ok.
swim.cfg({})
swim.cfg({})
swim_info_sorted()
swim.stop()

-- Members without a server is ok.
members = {'192.168.0.1:3333', '192.168.0.2:3333', '192.168.0.3:3333'}
swim.cfg({members = members})
swim_info_sorted()
swim.stop()
swim_info_sorted()

swim.cfg({server = listen_uri, members = members})
swim_info_sorted()

swim.debug_round_step()
swim_info_sorted()
swim.stop()

-- Unix is not supported.
unix_uri = 'unix/:/tmp/anyfile'
swim.cfg({server = unix_uri})

-- Invalid server and member URI.
swim.cfg({server = 'bad uri'})
swim.cfg({members = {'bad uri'}})

-- Change server URI without stop.
swim.cfg({server = listen_uri})
swim.cfg({server = listen_uri})
swim.debug_round_step()
swim_info_sorted()
swim.stop()

-- It is ok to have server URI in members list.
table.insert(members, listen_uri)

-- Address in use.
socket = require('socket')
s = socket("AF_INET", "SOCK_DGRAM", "udp")
s:bind(listen_host, listen_port)
res, err = swim.cfg({server = listen_uri, members = members})
res
err:match('bind, called')
swim_info_sorted()
s:close()
swim.cfg({server = listen_uri, members = members})
swim_info_sorted()

swim.stop()
test_run:cmd("clear filter")
