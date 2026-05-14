
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Web Server LLC
 *
 * io_uring backend for file AIO. Compiled only when liburing is available.
 * Coexists with the legacy Linux native AIO (eventfd + io_submit) path; the
 * active backend is chosen at runtime via ngx_linux_aio_engine.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#if (NGX_HAVE_IO_URING)

#include <liburing.h>


/* engine state */
struct io_uring          ngx_io_uring;
struct io_uring_params   ngx_io_uring_params;
ngx_uint_t               ngx_io_uring_enabled;


static void ngx_linux_io_uring_event_handler(ngx_event_t *ev);


ngx_int_t
ngx_linux_io_uring_setup(ngx_log_t *log, ngx_uint_t entries)
{
    int  ret;

    ngx_memzero(&ngx_io_uring, sizeof(struct io_uring));
    ngx_memzero(&ngx_io_uring_params, sizeof(struct io_uring_params));

    if (entries == 0) {
        entries = 64;
    }

    ret = io_uring_queue_init_params((unsigned) entries, &ngx_io_uring,
                                     &ngx_io_uring_params);
    if (ret < 0) {
        ngx_log_error(NGX_LOG_EMERG, log, -ret,
                      "io_uring_queue_init_params() failed");
        return NGX_ERROR;
    }

    ngx_io_uring_enabled = 1;

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "io_uring enabled (entries:%ui features:0x%08xd)",
                  entries, ngx_io_uring_params.features);

    return NGX_OK;
}


void
ngx_linux_io_uring_done(void)
{
    if (!ngx_io_uring_enabled) {
        return;
    }

    io_uring_queue_exit(&ngx_io_uring);
    ngx_io_uring_enabled = 0;
}


int
ngx_linux_io_uring_fd(void)
{
    return ngx_io_uring.ring_fd;
}


void
ngx_linux_io_uring_handler(ngx_event_t *ev)
{
    unsigned              head;
    unsigned              cqe_count;
    ngx_event_t          *e;
    ngx_event_aio_t      *aio;
    struct io_uring_cqe  *cqe;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "io_uring handler");

    cqe_count = 0;

    io_uring_for_each_cqe(&ngx_io_uring, head, cqe) {

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "io_uring event: %p %d %ud",
                       io_uring_cqe_get_data(cqe), cqe->res, cqe->flags);

        e = (ngx_event_t *) io_uring_cqe_get_data(cqe);

        if (e != NULL) {
            e->complete = 1;
            e->active = 0;
            e->ready = 1;

            aio = e->data;
            aio->res = cqe->res;

            ngx_post_event(e, &ngx_posted_events);
        }

        cqe_count++;
    }

    io_uring_cq_advance(&ngx_io_uring, cqe_count);
}


ssize_t
ngx_linux_io_uring_read(ngx_file_t *file, u_char *buf, size_t size,
    off_t offset, ngx_pool_t *pool)
{
    ngx_err_t             err;
    ngx_event_t          *ev;
    ngx_event_aio_t      *aio;
    struct io_uring_sqe  *sqe;

    if (file->aio == NULL && ngx_file_aio_init(file, pool) != NGX_OK) {
        return NGX_ERROR;
    }

    aio = file->aio;
    ev = &aio->event;

    if (!ev->ready) {
        ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                      "second aio post for \"%V\"", &file->name);
        return NGX_AGAIN;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "aio complete:%d @%O:%uz %V",
                   ev->complete, offset, size, &file->name);

    if (ev->complete) {
        ev->active = 0;
        ev->complete = 0;

        if (aio->res >= 0) {
            ngx_set_errno(0);
            return aio->res;
        }

        ngx_set_errno(-aio->res);

        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "aio read \"%s\" failed", file->name.data);

        return NGX_ERROR;
    }

    sqe = io_uring_get_sqe(&ngx_io_uring);

    if (sqe == NULL) {
        ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                       "aio no sqe available:%d @%O:%uz %V",
                       ev->complete, offset, size, &file->name);
        return ngx_read_file(file, buf, size, offset);
    }

    if (ngx_io_uring_params.features & IORING_FEAT_CUR_PERSONALITY) {
        /*
         * io_uring_prep_read is faster than io_uring_prep_readv because the
         * kernel does not need to import iovecs.  IORING_FEAT_CUR_PERSONALITY
         * implies the non-vectored read op is available.
         */
        io_uring_prep_read(sqe, file->fd, buf, (unsigned) size, offset);

    } else {
        /*
         * Keep iov alive on the heap-allocated aio struct so the kernel can
         * still read it after submit when IORING_FEAT_SUBMIT_STABLE is absent.
         */
        aio->iov.iov_base = buf;
        aio->iov.iov_len = size;
        io_uring_prep_readv(sqe, file->fd, &aio->iov, 1, offset);
    }

    io_uring_sqe_set_data(sqe, ev);

    ev->handler = ngx_linux_io_uring_event_handler;

    if (io_uring_submit(&ngx_io_uring) >= 1) {
        ev->active = 1;
        ev->ready = 0;
        ev->complete = 0;

        return NGX_AGAIN;
    }

    err = ngx_errno;

    if (err == NGX_EAGAIN) {
        return ngx_read_file(file, buf, size, offset);
    }

    ngx_log_error(NGX_LOG_CRIT, file->log, err,
                  "io_uring_submit(\"%V\") failed", &file->name);

    return NGX_ERROR;
}


static void
ngx_linux_io_uring_event_handler(ngx_event_t *ev)
{
    ngx_event_aio_t  *aio;

    aio = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ev->log, 0,
                   "io_uring event handler fd:%d %V",
                   aio->fd, &aio->file->name);

    aio->handler(ev);
}


#endif /* NGX_HAVE_IO_URING */
