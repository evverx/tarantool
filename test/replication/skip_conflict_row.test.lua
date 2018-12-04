env = require('test_run')
test_run = env.new()
test_run:cmd("restart server default with cleanup=1")
engine = test_run:get_cfg('engine')

box.schema.user.grant('guest', 'replication')

space = box.schema.space.create('test', {engine = engine});
index = box.space.test:create_index('primary')

test_run:cmd("create server replica with rpl_master=default, script='replication/replica.lua'")
test_run:cmd("start server replica")
test_run:cmd("switch replica")
box.cfg{replication_skip_conflict = true}
box.space.test:insert{1}

test_run:cmd("switch default")
space:insert{1, 1}
space:insert{2}
box.info.status

vclock = test_run:get_vclock('default')
_ = test_run:wait_vclock("replica", vclock)
test_run:cmd("switch replica")
box.info.replication[1].upstream.message
box.info.replication[1].upstream.status
box.space.test:select()

test_run:cmd("switch default")
box.info.status

-- test that if replication_skip_conflict is off vclock
-- is not advanced on errors.
test_run:cmd("restart server replica")
test_run:cmd("switch replica")
box.cfg{replication_skip_conflict=false}
box.space.test:insert{3}
box.info.vclock
test_run:cmd("switch default")
box.space.test:insert{3, 3}
box.space.test:insert{4}
box.info.vclock
test_run:cmd("switch replica")
box.info.vclock
box.info.replication[1].upstream.message
box.info.replication[1].upstream.status
box.space.test:select()
test_run:cmd("switch default")

-- cleanup
test_run:cmd("stop server replica")
test_run:cmd("cleanup server replica")
test_run:cmd("delete server replica")
test_run:cleanup_cluster()
box.space.test:drop()
box.schema.user.revoke('guest', 'replication')
