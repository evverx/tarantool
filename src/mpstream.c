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

#include "mpstream.h"
#include <assert.h>
#include <stdint.h>
#include "msgpuck.h"
#include "vstream.h"
#include "port.h"

void
mpstream_reserve_slow(struct mpstream *stream, size_t size)
{
    stream->alloc(stream->ctx, stream->pos - stream->buf);
    stream->buf = (char *) stream->reserve(stream->ctx, &size);
    if (stream->buf == NULL) {
        diag_set(OutOfMemory, size, "mpstream", "reserve");
        stream->error(stream->error_ctx);
    }
    stream->pos = stream->buf;
    stream->end = stream->pos + size;
}

void
mpstream_reset(struct mpstream *stream)
{
    size_t size = 0;
    stream->buf = (char *) stream->reserve(stream->ctx, &size);
    if (stream->buf == NULL) {
        diag_set(OutOfMemory, size, "mpstream", "reset");
        stream->error(stream->error_ctx);
    }
    stream->pos = stream->buf;
    stream->end = stream->pos + size;
}

/**
 * A streaming API so that it's possible to encode to any output
 * stream.
 */
void
mpstream_init(struct mpstream *stream, void *ctx,
              mpstream_reserve_f reserve, mpstream_alloc_f alloc,
              mpstream_error_f error, void *error_ctx)
{
    stream->ctx = ctx;
    stream->reserve = reserve;
    stream->alloc = alloc;
    stream->error = error;
    stream->error_ctx = error_ctx;
    mpstream_reset(stream);
}

void
mpstream_encode_array(struct mpstream *stream, uint32_t size)
{
    assert(mp_sizeof_array(size) <= 5);
    char *data = mpstream_reserve(stream, 5);
    if (data == NULL)
        return;
    char *pos = mp_encode_array(data, size);
    mpstream_advance(stream, pos - data);
}

void
mpstream_encode_map(struct mpstream *stream, uint32_t size)
{
    assert(mp_sizeof_map(size) <= 5);
    char *data = mpstream_reserve(stream, 5);
    if (data == NULL)
        return;
    char *pos = mp_encode_map(data, size);
    mpstream_advance(stream, pos - data);
}

void
mpstream_encode_uint(struct mpstream *stream, uint64_t num)
{
    assert(mp_sizeof_uint(num) <= 9);
    char *data = mpstream_reserve(stream, 9);
    if (data == NULL)
        return;
    char *pos = mp_encode_uint(data, num);
    mpstream_advance(stream, pos - data);
}

void
mpstream_encode_int(struct mpstream *stream, int64_t num)
{
    assert(mp_sizeof_int(num) <= 9);
    char *data = mpstream_reserve(stream, 9);
    if (data == NULL)
        return;
    char *pos = mp_encode_int(data, num);
    mpstream_advance(stream, pos - data);
}

void
mpstream_encode_float(struct mpstream *stream, float num)
{
    assert(mp_sizeof_float(num) <= 5);
    char *data = mpstream_reserve(stream, 5);
    if (data == NULL)
        return;
    char *pos = mp_encode_float(data, num);
    mpstream_advance(stream, pos - data);
}

void
mpstream_encode_double(struct mpstream *stream, double num)
{
    assert(mp_sizeof_double(num) <= 9);
    char *data = mpstream_reserve(stream, 9);
    char *pos = mp_encode_double(data, num);
    if (data == NULL)
        return;
    mpstream_advance(stream, pos - data);
}

void
mpstream_encode_strn(struct mpstream *stream, const char *str, uint32_t len)
{
    assert(mp_sizeof_str(len) <= 5 + len);
    char *data = mpstream_reserve(stream, 5 + len);
    if (data == NULL)
        return;
    char *pos = mp_encode_str(data, str, len);
    mpstream_advance(stream, pos - data);
}

void
mpstream_encode_nil(struct mpstream *stream)
{
    assert(mp_sizeof_nil() <= 1);
    char *data = mpstream_reserve(stream, 1);
    if (data == NULL)
        return;
    char *pos = mp_encode_nil(data);
    mpstream_advance(stream, pos - data);
}

void
mpstream_encode_bool(struct mpstream *stream, bool val)
{
    assert(mp_sizeof_bool(val) <= 1);
    char *data = mpstream_reserve(stream, 1);
    if (data == NULL)
        return;
    char *pos = mp_encode_bool(data, val);
    mpstream_advance(stream, pos - data);
}

static int
mp_vstream_encode_port(struct vstream *stream, struct port *port)
{
	struct mpstream *mpstream = (struct mpstream *)stream;
	mpstream_flush(mpstream);
	if (port_dump_msgpack(port, mpstream->ctx) < 0) {
		/* Failed port dump destroyes the port. */
		return -1;
	}
	mpstream_reset(mpstream);
	return 0;
}

static void
mp_vstream_encode_enum(struct vstream *stream, int64_t num, const char *str)
{
	(void)str;
	if (num < 0)
		mpstream_encode_int((struct mpstream *)stream, num);
	else
		mpstream_encode_uint((struct mpstream *)stream, num);
}

static void
mp_vstream_noop(struct vstream *stream, ...)
{
	(void) stream;
}

static const struct vstream_vtab mp_vstream_vtab = {
	/** encode_array = */ (encode_array_f)mpstream_encode_array,
	/** encode_map = */ (encode_map_f)mpstream_encode_map,
	/** encode_uint = */ (encode_uint_f)mpstream_encode_uint,
	/** encode_int = */ (encode_int_f)mpstream_encode_int,
	/** encode_float = */ (encode_float_f)mpstream_encode_float,
	/** encode_double = */ (encode_double_f)mpstream_encode_double,
	/** encode_strn = */ (encode_strn_f)mpstream_encode_strn,
	/** encode_nil = */ (encode_nil_f)mpstream_encode_nil,
	/** encode_bool = */ (encode_bool_f)mpstream_encode_bool,
	/** encode_enum = */ mp_vstream_encode_enum,
	/** encode_port = */ mp_vstream_encode_port,
	/** encode_array_commit = */ (encode_array_commit_f)mp_vstream_noop,
	/** encode_map_commit = */ (encode_map_commit_f)mp_vstream_noop,
};

void
mpvstream_init(struct vstream *stream, void *ctx, mpstream_reserve_f reserve,
	       mpstream_alloc_f alloc, mpstream_error_f error, void *error_ctx)
{
	stream->vtab = &mp_vstream_vtab;
	assert(sizeof(stream->inheritance_padding) >= sizeof(struct mpstream));
	mpstream_init((struct mpstream *) stream, ctx, reserve, alloc, error,
		      error_ctx);
}
