/* circpad_negotiation.c -- generated by Trunnel v1.5.1.
 * https://gitweb.torproject.org/trunnel.git
 * You probably shouldn't edit this file.
 */
#include <stdlib.h>
#include "trunnel-impl.h"

#include "circpad_negotiation.h"

#define TRUNNEL_SET_ERROR_CODE(obj) \
  do {                              \
    (obj)->trunnel_error_code_ = 1; \
  } while (0)

#if defined(__COVERITY__) || defined(__clang_analyzer__)
/* If we're runnning a static analysis tool, we don't want it to complain
 * that some of our remaining-bytes checks are dead-code. */
int circpadnegotiation_deadcode_dummy__ = 0;
#define OR_DEADCODE_DUMMY || circpadnegotiation_deadcode_dummy__
#else
#define OR_DEADCODE_DUMMY
#endif

#define CHECK_REMAINING(nbytes, label)                           \
  do {                                                           \
    if (remaining < (nbytes) OR_DEADCODE_DUMMY) {                \
      goto label;                                                \
    }                                                            \
  } while (0)

circpad_negotiate_t *
circpad_negotiate_new(void)
{
  circpad_negotiate_t *val = trunnel_calloc(1, sizeof(circpad_negotiate_t));
  if (NULL == val)
    return NULL;
  val->command = CIRCPAD_COMMAND_START;
  return val;
}

/** Release all storage held inside 'obj', but do not free 'obj'.
 */
static void
circpad_negotiate_clear(circpad_negotiate_t *obj)
{
  (void) obj;
}

void
circpad_negotiate_free(circpad_negotiate_t *obj)
{
  if (obj == NULL)
    return;
  circpad_negotiate_clear(obj);
  trunnel_memwipe(obj, sizeof(circpad_negotiate_t));
  trunnel_free_(obj);
}

uint8_t
circpad_negotiate_get_version(const circpad_negotiate_t *inp)
{
  return inp->version;
}
int
circpad_negotiate_set_version(circpad_negotiate_t *inp, uint8_t val)
{
  if (! ((val == 0))) {
     TRUNNEL_SET_ERROR_CODE(inp);
     return -1;
  }
  inp->version = val;
  return 0;
}
uint8_t
circpad_negotiate_get_command(const circpad_negotiate_t *inp)
{
  return inp->command;
}
int
circpad_negotiate_set_command(circpad_negotiate_t *inp, uint8_t val)
{
  if (! ((val == CIRCPAD_COMMAND_START || val == CIRCPAD_COMMAND_STOP))) {
     TRUNNEL_SET_ERROR_CODE(inp);
     return -1;
  }
  inp->command = val;
  return 0;
}
uint8_t
circpad_negotiate_get_machine_type(const circpad_negotiate_t *inp)
{
  return inp->machine_type;
}
int
circpad_negotiate_set_machine_type(circpad_negotiate_t *inp, uint8_t val)
{
  inp->machine_type = val;
  return 0;
}
uint8_t
circpad_negotiate_get_echo_request(const circpad_negotiate_t *inp)
{
  return inp->echo_request;
}
int
circpad_negotiate_set_echo_request(circpad_negotiate_t *inp, uint8_t val)
{
  if (! ((val == 0 || val == 1))) {
     TRUNNEL_SET_ERROR_CODE(inp);
     return -1;
  }
  inp->echo_request = val;
  return 0;
}
const char *
circpad_negotiate_check(const circpad_negotiate_t *obj)
{
  if (obj == NULL)
    return "Object was NULL";
  if (obj->trunnel_error_code_)
    return "A set function failed on this object";
  if (! (obj->version == 0))
    return "Integer out of bounds";
  if (! (obj->command == CIRCPAD_COMMAND_START || obj->command == CIRCPAD_COMMAND_STOP))
    return "Integer out of bounds";
  if (! (obj->echo_request == 0 || obj->echo_request == 1))
    return "Integer out of bounds";
  return NULL;
}

ssize_t
circpad_negotiate_encoded_len(const circpad_negotiate_t *obj)
{
  ssize_t result = 0;

  if (NULL != circpad_negotiate_check(obj))
     return -1;


  /* Length of u8 version IN [0] */
  result += 1;

  /* Length of u8 command IN [CIRCPAD_COMMAND_START, CIRCPAD_COMMAND_STOP] */
  result += 1;

  /* Length of u8 machine_type */
  result += 1;

  /* Length of u8 echo_request IN [0, 1] */
  result += 1;
  return result;
}
int
circpad_negotiate_clear_errors(circpad_negotiate_t *obj)
{
  int r = obj->trunnel_error_code_;
  obj->trunnel_error_code_ = 0;
  return r;
}
ssize_t
circpad_negotiate_encode(uint8_t *output, const size_t avail, const circpad_negotiate_t *obj)
{
  ssize_t result = 0;
  size_t written = 0;
  uint8_t *ptr = output;
  const char *msg;
#ifdef TRUNNEL_CHECK_ENCODED_LEN
  const ssize_t encoded_len = circpad_negotiate_encoded_len(obj);
#endif

  if (NULL != (msg = circpad_negotiate_check(obj)))
    goto check_failed;

#ifdef TRUNNEL_CHECK_ENCODED_LEN
  trunnel_assert(encoded_len >= 0);
#endif

  /* Encode u8 version IN [0] */
  trunnel_assert(written <= avail);
  if (avail - written < 1)
    goto truncated;
  trunnel_set_uint8(ptr, (obj->version));
  written += 1; ptr += 1;

  /* Encode u8 command IN [CIRCPAD_COMMAND_START, CIRCPAD_COMMAND_STOP] */
  trunnel_assert(written <= avail);
  if (avail - written < 1)
    goto truncated;
  trunnel_set_uint8(ptr, (obj->command));
  written += 1; ptr += 1;

  /* Encode u8 machine_type */
  trunnel_assert(written <= avail);
  if (avail - written < 1)
    goto truncated;
  trunnel_set_uint8(ptr, (obj->machine_type));
  written += 1; ptr += 1;

  /* Encode u8 echo_request IN [0, 1] */
  trunnel_assert(written <= avail);
  if (avail - written < 1)
    goto truncated;
  trunnel_set_uint8(ptr, (obj->echo_request));
  written += 1; ptr += 1;


  trunnel_assert(ptr == output + written);
#ifdef TRUNNEL_CHECK_ENCODED_LEN
  {
    trunnel_assert(encoded_len >= 0);
    trunnel_assert((size_t)encoded_len == written);
  }

#endif

  return written;

 truncated:
  result = -2;
  goto fail;
 check_failed:
  (void)msg;
  result = -1;
  goto fail;
 fail:
  trunnel_assert(result < 0);
  return result;
}

/** As circpad_negotiate_parse(), but do not allocate the output
 * object.
 */
static ssize_t
circpad_negotiate_parse_into(circpad_negotiate_t *obj, const uint8_t *input, const size_t len_in)
{
  const uint8_t *ptr = input;
  size_t remaining = len_in;
  ssize_t result = 0;
  (void)result;

  /* Parse u8 version IN [0] */
  CHECK_REMAINING(1, truncated);
  obj->version = (trunnel_get_uint8(ptr));
  remaining -= 1; ptr += 1;
  if (! (obj->version == 0))
    goto fail;

  /* Parse u8 command IN [CIRCPAD_COMMAND_START, CIRCPAD_COMMAND_STOP] */
  CHECK_REMAINING(1, truncated);
  obj->command = (trunnel_get_uint8(ptr));
  remaining -= 1; ptr += 1;
  if (! (obj->command == CIRCPAD_COMMAND_START || obj->command == CIRCPAD_COMMAND_STOP))
    goto fail;

  /* Parse u8 machine_type */
  CHECK_REMAINING(1, truncated);
  obj->machine_type = (trunnel_get_uint8(ptr));
  remaining -= 1; ptr += 1;

  /* Parse u8 echo_request IN [0, 1] */
  CHECK_REMAINING(1, truncated);
  obj->echo_request = (trunnel_get_uint8(ptr));
  remaining -= 1; ptr += 1;
  if (! (obj->echo_request == 0 || obj->echo_request == 1))
    goto fail;
  trunnel_assert(ptr + remaining == input + len_in);
  return len_in - remaining;

 truncated:
  return -2;
 fail:
  result = -1;
  return result;
}

ssize_t
circpad_negotiate_parse(circpad_negotiate_t **output, const uint8_t *input, const size_t len_in)
{
  ssize_t result;
  *output = circpad_negotiate_new();
  if (NULL == *output)
    return -1;
  result = circpad_negotiate_parse_into(*output, input, len_in);
  if (result < 0) {
    circpad_negotiate_free(*output);
    *output = NULL;
  }
  return result;
}
