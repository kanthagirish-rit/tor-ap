/* circpad_negotiation.h -- generated by by Trunnel v1.5.1.
 * https://gitweb.torproject.org/trunnel.git
 * You probably shouldn't edit this file.
 */
#ifndef TRUNNEL_CIRCPAD_NEGOTIATION_H
#define TRUNNEL_CIRCPAD_NEGOTIATION_H

#include <stdint.h>
#include "trunnel.h"

#define CIRCPAD_COMMAND_STOP 1
#define CIRCPAD_COMMAND_START 2
#define CIRCPAD_MACHINE_CIRC_SETUP 1
#define CIRCPAD_MACHINE_HS_CLIENT_INTRO 2
#define CIRCPAD_MACHINE_HS_SERVICE_INTRO 3
#define CIRCPAD_MACHINE_HS_SERVICE_REND 4
#define CIRCPAD_MACHINE_WTF_PAD 5
#if !defined(TRUNNEL_OPAQUE) && !defined(TRUNNEL_OPAQUE_CIRCPAD_NEGOTIATE)
struct circpad_negotiate_st {
  uint8_t version;
  uint8_t command;
  uint8_t machine_type;
  uint8_t echo_request;
  uint8_t trunnel_error_code_;
};
#endif
typedef struct circpad_negotiate_st circpad_negotiate_t;
/** Return a newly allocated circpad_negotiate with all elements set
 * to zero.
 */
circpad_negotiate_t *circpad_negotiate_new(void);
/** Release all storage held by the circpad_negotiate in 'victim'. (Do
 * nothing if 'victim' is NULL.)
 */
void circpad_negotiate_free(circpad_negotiate_t *victim);
/** Try to parse a circpad_negotiate from the buffer in 'input', using
 * up to 'len_in' bytes from the input buffer. On success, return the
 * number of bytes consumed and set *output to the newly allocated
 * circpad_negotiate_t. On failure, return -2 if the input appears
 * truncated, and -1 if the input is otherwise invalid.
 */
ssize_t circpad_negotiate_parse(circpad_negotiate_t **output, const uint8_t *input, const size_t len_in);
/** Return the number of bytes we expect to need to encode the
 * circpad_negotiate in 'obj'. On failure, return a negative value.
 * Note that this value may be an overestimate, and can even be an
 * underestimate for certain unencodeable objects.
 */
ssize_t circpad_negotiate_encoded_len(const circpad_negotiate_t *obj);
/** Try to encode the circpad_negotiate from 'input' into the buffer
 * at 'output', using up to 'avail' bytes of the output buffer. On
 * success, return the number of bytes used. On failure, return -2 if
 * the buffer was not long enough, and -1 if the input was invalid.
 */
ssize_t circpad_negotiate_encode(uint8_t *output, size_t avail, const circpad_negotiate_t *input);
/** Check whether the internal state of the circpad_negotiate in 'obj'
 * is consistent. Return NULL if it is, and a short message if it is
 * not.
 */
const char *circpad_negotiate_check(const circpad_negotiate_t *obj);
/** Clear any errors that were set on the object 'obj' by its setter
 * functions. Return true iff errors were cleared.
 */
int circpad_negotiate_clear_errors(circpad_negotiate_t *obj);
/** Return the value of the version field of the circpad_negotiate_t
 * in 'inp'
 */
uint8_t circpad_negotiate_get_version(const circpad_negotiate_t *inp);
/** Set the value of the version field of the circpad_negotiate_t in
 * 'inp' to 'val'. Return 0 on success; return -1 and set the error
 * code on 'inp' on failure.
 */
int circpad_negotiate_set_version(circpad_negotiate_t *inp, uint8_t val);
/** Return the value of the command field of the circpad_negotiate_t
 * in 'inp'
 */
uint8_t circpad_negotiate_get_command(const circpad_negotiate_t *inp);
/** Set the value of the command field of the circpad_negotiate_t in
 * 'inp' to 'val'. Return 0 on success; return -1 and set the error
 * code on 'inp' on failure.
 */
int circpad_negotiate_set_command(circpad_negotiate_t *inp, uint8_t val);
/** Return the value of the machine_type field of the
 * circpad_negotiate_t in 'inp'
 */
uint8_t circpad_negotiate_get_machine_type(const circpad_negotiate_t *inp);
/** Set the value of the machine_type field of the circpad_negotiate_t
 * in 'inp' to 'val'. Return 0 on success; return -1 and set the error
 * code on 'inp' on failure.
 */
int circpad_negotiate_set_machine_type(circpad_negotiate_t *inp, uint8_t val);
/** Return the value of the echo_request field of the
 * circpad_negotiate_t in 'inp'
 */
uint8_t circpad_negotiate_get_echo_request(const circpad_negotiate_t *inp);
/** Set the value of the echo_request field of the circpad_negotiate_t
 * in 'inp' to 'val'. Return 0 on success; return -1 and set the error
 * code on 'inp' on failure.
 */
int circpad_negotiate_set_echo_request(circpad_negotiate_t *inp, uint8_t val);


#endif
