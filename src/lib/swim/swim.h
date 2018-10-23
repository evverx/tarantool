#ifndef TARANTOOL_SWIM_H_INCLUDED
#define TARANTOOL_SWIM_H_INCLUDED
/*
 * Copyright 2010-2018, Tarantool AUTHORS, please see AUTHORS file.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/socket.h>

#if defined(__cplusplus)
extern "C" {
#endif

struct info_handler;

/**
 * Virtual methods of SWIM protocol steps. Usual implementation -
 * just sendto/recvfrom for all methods. But for testing via this
 * interface errors could be simulated.
 */
struct swim_transport {
	/**
	 * Send regular round message containing dissemination,
	 * failure detection and anti-entropy sections. Parameters
	 * are like sendto().
	 */
	ssize_t
	(*send_round_msg)(int fd, const void *data, size_t size,
			  const struct sockaddr *addr, socklen_t addr_size);

	/**
	 * Receive a message. Not necessary round or failure
	 * detection. Before message is received, its type is
	 * unknown. Parameters are like recvfrom().
	 */
	ssize_t
	(*recv_msg)(int fd, void *buffer, size_t size, struct sockaddr *addr,
		    socklen_t *addr_size);
};

/** UDP sendto/recvfrom implementation of swim_transport. */
extern struct swim_transport swim_udp_transport;

/**
 * Configure or reconfigure the module.
 *
 * @param member_uris An array of member URIs in the format
 *        "ip:port".
 * @param member_uri_count Length of @member_uris.
 * @param server_uri A URI in the format "ip:port".
 * @param heartbeat_rate Rate of broadcasting messages. It does
 *        mean that each member will be checked each
 *        @heartbeat_rate seconds. It is rather the protocol
 *        speed. Protocol period depends on member count and
 *        broadcast batch.
 * @param new_transport Transport API to send/receive messages.
 *
 * @retval 0 Success.
 * @retval -1 Error.
 */
int
swim_cfg(const char **member_uris, int member_uri_count, const char *server_uri,
	 double heartbeat_rate, const struct swim_transport *new_transport);

/**
 * Stop listening and broadcasting messages, cleanup all internal
 * structures, free memory. Note, that swim_cfg/swim_stop
 * combination can be called many times.
 */
void
swim_stop(void);

void
swim_info(struct info_handler *info);

#ifndef NDEBUG

/** Trigger next round step right now. */
void
swim_debug_round_step(void);

#endif

#if defined(__cplusplus)
}
#endif

#endif /* TARANTOOL_SWIM_H_INCLUDED */
