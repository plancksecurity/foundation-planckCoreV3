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
        char **resulttext
    )
{
    struct mailmime * msg_mime = NULL;
	struct mailimf_fields * fields = NULL;
    struct mailmime * mime = NULL;
    struct mailmime * submime = NULL;
    int col;
    int r;
    int fd;
    FILE *file = NULL;
    size_t size;
    char *buf = NULL;
    PEP_STATUS error = PEP_OUT_OF_MEMORY;

    assert(plaintext);
    assert(resulttext);

    *resulttext = NULL;

    msg_mime = mailmime_new_message_data(NULL);
    assert(msg_mime);
    if (msg_mime == NULL)
        goto enomem;

    fields = mailimf_fields_new_empty();
    assert(fields);
    if (fields == NULL)
        goto enomem;

    mailmime_set_imf_fields(msg_mime, fields);

    mime = part_multiple_new("multipart/mixed", NULL);
    assert(mime);
    if (mime == NULL)
        goto enomem;

    submime = get_text_part("text/plain", plaintext, strlen(plaintext),
            MAILMIME_MECHANISM_QUOTED_PRINTABLE);
    assert(submime);
    if (submime == NULL) {
        mailmime_free(msg_mime);
        goto enomem;
    }

    r = mailmime_smart_add_part(mime, submime);
    assert(r == MAILIMF_NO_ERROR);
    if (r == MAILIMF_ERROR_MEMORY) {
        mailmime_free(msg_mime);
        goto enomem;
    }
    else {
        // mailmime_smart_add_part() takes ownership of submime
        submime = NULL;
    }

    r = mailmime_add_part(msg_mime, mime);
    assert(r == MAILIMF_NO_ERROR);
    if (r == MAILIMF_ERROR_MEMORY) {
        goto enomem;
    }
    // mailmime_add_part() takes ownership of mime

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
    mailmime_free(msg_mime);
    *resulttext = buf;
    return PEP_STATUS_OK;

err_buffer:
    error = PEP_BUFFER_TOO_SMALL;
    goto enomem;

err_file:
    error = PEP_CANNOT_CREATE_TEMP_FILE;

enomem:
    free(buf);
    free(template);

    if (file)
        fclose(file);
    else if (fd != -1)
        close(fd);

    if (msg_mime)
        mailmime_free(msg_mime);
    if (fields)
        mailimf_fields_free(fields);
    if (submime)
        mailmime_free(submime);

    return error;
}
