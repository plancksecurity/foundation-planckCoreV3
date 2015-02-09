#include "mime.h"

#include <libetpan/libetpan.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include "etpan_mime.h"

DYNAMIC_API PEP_STATUS mime_encode_text(
        const char *plaintext,
        const char *htmltext,
        bloblist_t *attachments,
        char **resulttext
    )
{
    struct mailmime * mime = NULL;
    struct mailmime * submime = NULL;
    int col;
    int r;
    int fd;
    FILE *file = NULL;
    size_t size;
    char *buf = NULL;
    PEP_STATUS error;

    assert(plaintext);
    assert(resulttext);

    *resulttext = NULL;

    if (htmltext) {
        mime = part_multiple_new("multipart/alternative", NULL);
        assert(mime);
        if (mime == NULL)
            goto enomem;

        submime = get_text_part("text/plain", plaintext, strlen(plaintext),
                MAILMIME_MECHANISM_QUOTED_PRINTABLE);
        assert(submime);
        if (submime == NULL)
            goto enomem;

        r = mailmime_smart_add_part(mime, submime);
        assert(r == MAILIMF_NO_ERROR);
        if (r == MAILIMF_ERROR_MEMORY) {
            goto enomem;
        }
        else {
            // mailmime_smart_add_part() takes ownership of submime
            submime = NULL;
        }

        submime = get_text_part("text/html", htmltext, strlen(htmltext),
                MAILMIME_MECHANISM_QUOTED_PRINTABLE);
        assert(submime);
        if (submime == NULL)
            goto enomem;

        r = mailmime_smart_add_part(mime, submime);
        assert(r == MAILIMF_NO_ERROR);
        if (r == MAILIMF_ERROR_MEMORY)
            goto enomem;
        else {
            // mailmime_smart_add_part() takes ownership of submime
            submime = NULL;
        }
    }
    else {
        mime = get_text_part("text/plain", plaintext, strlen(plaintext),
                MAILMIME_MECHANISM_QUOTED_PRINTABLE);
        assert(mime);
        if (mime == NULL)
            goto enomem;
    }

    if (attachments) {
        submime = mime;
        mime = part_multiple_new("multipart/mixed", NULL);
        assert(mime);
        if (mime == NULL)
            goto enomem;

        r = mailmime_smart_add_part(mime, submime);
        assert(r == MAILIMF_NO_ERROR);
        if (r == MAILIMF_ERROR_MEMORY) {
            goto enomem;
        }
        else {
            // mailmime_smart_add_part() takes ownership of submime
            submime = NULL;
        }

        bloblist_t *_a;
        for (_a = attachments; _a != NULL; _a = _a->next) {
            char * mime_type;

            assert(_a->data);
            assert(_a->size);

            if (_a->mime_type == NULL)
                mime_type = "application/octet-stream";
            else
                mime_type = _a->mime_type;

            submime = get_file_part(_a->file_name, mime_type, _a->data, _a->size);
            assert(submime);
            if (submime == NULL)
                goto enomem;

            r = mailmime_smart_add_part(mime, submime);
            assert(r == MAILIMF_NO_ERROR);
            if (r == MAILIMF_ERROR_MEMORY) {
                goto enomem;
            }
            else {
                // mailmime_smart_add_part() takes ownership of submime
                submime = NULL;
            }
        }
    }

    char *template = strdup("/tmp/pEp.XXXXXXXXXXXXXXXXXXXX");
    assert(template);
    if (template == NULL)
        goto enomem;

    do {
        fd = mkstemp(template);
    } while (fd == -1 && errno == EINTR);

    assert(fd != -1);
    if (fd == -1)
        goto err_file;

    r = unlink(template);
    assert(r == 0);
    if (r == -1)
        goto err_file;

    free(template);
    template = NULL;

    do {
        file = fdopen(fd, "w+");
    } while (file == NULL && errno == EINTR);

    assert(file);
    if (file == NULL) {
        switch (errno) {
            case ENOMEM:
                goto enomem;
            default:
                goto err_file;
        }
    }

    fd = -1;

    col = 0;
    r = mailmime_write_file(file, &col, mime);
    assert(r == MAILIMF_NO_ERROR);
    if (r == MAILIMF_ERROR_MEMORY)
        goto enomem;
    else if (r != MAILIMF_NO_ERROR)
        goto err_file;

    off_t len = ftello(file);
    assert(len != -1);
    if (len == -1 && errno == EOVERFLOW)
        goto err_file;

    if (len + 1 > SIZE_T_MAX)
        goto err_buffer;

    size = (size_t) len;

    errno = 0;
    rewind(file);
    assert(errno == 0);
    clearerr(file);

    buf = calloc(1, size + 1);
    assert(buf);
    if (buf == NULL)
        goto enomem;
    
    char *_buf = buf;
    size_t rest = size;
    for (size_t bytes_read = 0; rest > 0; rest -= bytes_read, _buf += rest) {
        assert(feof(file) == 0);
        if (feof(file))
            goto err_file;
        bytes_read = rest * fread(_buf, rest, 1, file);
        if (ferror(file))
            goto err_file;
    }

    fclose(file);
    mailmime_free(mime);
    *resulttext = buf;
    return PEP_STATUS_OK;

err_buffer:
    error = PEP_BUFFER_TOO_SMALL;
    goto release;

err_file:
    error = PEP_CANNOT_CREATE_TEMP_FILE;
    goto release;

enomem:
    error = PEP_OUT_OF_MEMORY;

release:
    free(buf);
    free(template);

    if (file)
        fclose(file);
    else if (fd != -1)
        close(fd);

    if (mime)
        mailmime_free(mime);
    if (submime)
        mailmime_free(submime);

    return error;
}
