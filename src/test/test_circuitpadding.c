#define TOR_CHANNEL_INTERNAL_
#include "or.h"
#include "test.h"
#include "testsupport.h"
#include "connection.h"
#include "connection_or.h"
#include "channel.h"
#include "channeltls.h"
#include "channelpadding.h"
#include "compat_libevent.h"
#include "config.h"
#include <event.h>
#include "compat_time.h"
#include "relay.h"
#include "circuitlist.h"
#include "circuitbuild.h"

extern smartlist_t *connection_array;
extern networkstatus_t *current_ns_consensus;
extern networkstatus_t *current_md_consensus;

circid_t get_unique_circ_id_by_chan(channel_t *chan);

static or_circuit_t * new_fake_orcirc(channel_t *nchan, channel_t *pchan);
channel_t *new_fake_channel(void);

void test_circuitpadding_circuitsetup_machine(void *arg);

static or_circuit_t *
new_fake_orcirc(channel_t *nchan, channel_t *pchan)
{
  or_circuit_t *orcirc = NULL;
  circuit_t *circ = NULL;
  crypt_path_t tmp_cpath;
  char whatevs_key[CPATH_KEY_MATERIAL_LEN];

  // XXX: Hack to get cmux
  nchan->cmux = circuitmux_alloc();
  pchan->cmux = circuitmux_alloc();

  orcirc = tor_malloc_zero(sizeof(*orcirc));
  circ = &(orcirc->base_);
  circ->magic = OR_CIRCUIT_MAGIC;

  //circ->n_chan = nchan;
  circ->n_circ_id = get_unique_circ_id_by_chan(nchan);
  circ->n_mux = NULL; /* ?? */
  cell_queue_init(&(circ->n_chan_cells));
  circ->n_hop = NULL;
  circ->streams_blocked_on_n_chan = 0;
  circ->streams_blocked_on_p_chan = 0;
  circ->n_delete_pending = 0;
  circ->p_delete_pending = 0;
  circ->received_destroy = 0;
  circ->state = CIRCUIT_STATE_OPEN;
  circ->purpose = CIRCUIT_PURPOSE_OR;
  circ->package_window = CIRCWINDOW_START_MAX;
  circ->deliver_window = CIRCWINDOW_START_MAX;
  circ->n_chan_create_cell = NULL;

  //orcirc->p_chan = pchan;
  orcirc->p_circ_id = get_unique_circ_id_by_chan(pchan);
  cell_queue_init(&(orcirc->p_chan_cells));

  circuit_set_p_circid_chan(orcirc, orcirc->p_circ_id, pchan);
  circuit_set_n_circid_chan(circ, circ->n_circ_id, nchan);

  memset(&tmp_cpath, 0, sizeof(tmp_cpath));
  if (circuit_init_cpath_crypto(&tmp_cpath, whatevs_key, 0)<0) {
    log_warn(LD_BUG,"Circuit initialization failed");
    return NULL;
  }
  orcirc->n_digest = tmp_cpath.f_digest;
  orcirc->n_crypto = tmp_cpath.f_crypto;
  orcirc->p_digest = tmp_cpath.b_digest;
  orcirc->p_crypto = tmp_cpath.b_crypto;

  return orcirc;
}

void dummy_nop_timer(void);

//static int dont_stop_libevent = 0;

static circuit_t *client_side;
static circuit_t *relay_side;

static int n_client_cells = 0;
static int n_relay_cells = 0;

static int
circuit_package_relay_cell_mock(cell_t *cell, circuit_t *circ,
                           cell_direction_t cell_direction,
                           crypt_path_t *layer_hint, streamid_t on_stream,
                           const char *filename, int lineno);

static int
cpath_get_len(crypt_path_t *cpath_orig)
{
  crypt_path_t *cpath, *cpath_next = NULL;
  int n = 0;
  for (cpath = cpath_orig; cpath_next != cpath_orig; cpath = cpath_next) {
    cpath_next = cpath->next;
    ++n;
  }
  return n;
}

static int
circuit_package_relay_cell_mock(cell_t *cell, circuit_t *circ,
                           cell_direction_t cell_direction,
                           crypt_path_t *layer_hint, streamid_t on_stream,
                           const char *filename, int lineno) {
  (void)cell; (void)on_stream; (void)filename; (void)lineno;

  if (circ == client_side) {
    tt_int_op(cell_direction, OP_EQ, CELL_DIRECTION_OUT);
    tt_ptr_op(layer_hint, OP_NE, TO_ORIGIN_CIRCUIT(circ)->cpath->prev);
    tt_int_op(cpath_get_len(layer_hint), OP_EQ, 2);

    fprintf(stderr, "Client padded\n");
    // Pretend a padding cell was sent
    circpad_event_padding_sent(client_side);

    // Receive padding cell at middle 
    circpad_event_padding_received(relay_side);
    n_client_cells++;
  } else if (circ == relay_side) {
    tt_int_op(cell_direction, OP_EQ, CELL_DIRECTION_IN);

    fprintf(stderr, "Relay padded\n");
    // Pretend a padding cell was sent
    circpad_event_padding_sent(relay_side);

    // Receive padding cell at client
    circpad_event_padding_received(client_side);
    n_relay_cells++;
  }

 done:
  event_base_loopbreak(tor_libevent_get_base());
  return 0;
}

// XXX: test negotiation (write it first)

static void
simulate_single_hop_extend(circuit_t *client, circuit_t *mid_relay)
{
  char whatevs_key[CPATH_KEY_MATERIAL_LEN];

  // Pretend a non-padding cell was sent
  circpad_event_nonpadding_sent((circuit_t*)client);

  // Receive extend cell at middle 
  circpad_event_nonpadding_received((circuit_t*)mid_relay);

  // Sleep a tiny bit so we can calculate an RTT
  tor_sleep_msec(10);

  // Receive extended cell at middle
  circpad_event_nonpadding_sent((circuit_t*)mid_relay);

  // Receive extended cell at first hop
  circpad_event_nonpadding_received((circuit_t*)client);

  // Add a hop to cpath
  crypt_path_t *hop = tor_malloc_zero(sizeof(crypt_path_t));
  onion_append_to_cpath(&TO_ORIGIN_CIRCUIT(client)->cpath, hop);

  hop->magic = CRYPT_PATH_MAGIC;
  hop->state = CPATH_STATE_OPEN;

  // XXX: we need to free this..
  circuit_init_cpath_crypto(hop, whatevs_key, 0);

  hop->package_window = circuit_initial_package_window();
  hop->deliver_window = CIRCWINDOW_START;
}

void
test_circuitpadding_circuitsetup_machine(void *arg)
{
  /**
   * Test case plan:
   * 
   * 1. Simulate a normal circuit setup pattern
   * 2. Simulate a cannibalized circuit hop addition
   * 3. Simulate a hs intro setup pattern
   *    - On-demand
   *    - Via cannibalize
   * 4. Simulate a hs rend setup pattern
   *    - On-demand
   *    - Via cannibalize
   */
  (void)arg;
  client_side = (circuit_t *)origin_circuit_new();
  // XXX: free these channels
  relay_side = (circuit_t *)new_fake_orcirc(new_fake_channel(), new_fake_channel());

  relay_side->purpose = CIRCUIT_PURPOSE_OR;
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;

  monotime_init();
  timers_initialize();

  circpad_circ_responder_machine_setup(relay_side);
  circpad_circ_client_machine_setup(client_side);

  MOCK(circuit_package_relay_cell,
       circuit_package_relay_cell_mock);

  /* Test case #1: Build a 3 hop circuit, then wait and let pad */
  for (int i = 0; i < 3; i++) {
    simulate_single_hop_extend(client_side, relay_side);

    tt_int_op(client_side->padding_info[0]->current_state, OP_EQ,
              CIRCPAD_STATE_BURST);
    tt_int_op(relay_side->padding_info[0]->current_state, OP_EQ,
              CIRCPAD_STATE_BURST);
  }

  tt_int_op(client_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_NE, 0);
  tt_int_op(relay_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_EQ, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 1);
  tt_int_op(n_relay_cells, OP_EQ, 0);

  tt_int_op(relay_side->padding_info[0]->current_state, OP_EQ,
              CIRCPAD_STATE_GAP);

  fprintf(stderr, "Wait loop\n");
  tt_int_op(client_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_NE, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 1);
  tt_int_op(n_relay_cells, OP_EQ, 1);

  fprintf(stderr, "Wait loop\n");
  tt_int_op(client_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_NE, 0);
  tt_int_op(relay_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_EQ, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 2);
  tt_int_op(n_relay_cells, OP_EQ, 1);

  fprintf(stderr, "Wait loop\n");
  tt_int_op(client_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_NE, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 2);
  tt_int_op(n_relay_cells, OP_EQ, 2);

  fprintf(stderr, "Wait loop\n");
  tt_int_op(client_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_NE, 0);
  tt_int_op(relay_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_EQ, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 3);
  tt_int_op(n_relay_cells, OP_EQ, 2);

  fprintf(stderr, "Wait loop\n");
  tt_int_op(client_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_NE, 0);
  event_base_loop(tor_libevent_get_base(), 0);
  tt_int_op(n_client_cells, OP_EQ, 3);
  tt_int_op(n_relay_cells, OP_EQ, 3);

  tt_int_op(client_side->padding_info[0]->current_state,
            OP_EQ, CIRCPAD_STATE_END);
  tt_int_op(client_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->current_state,
            OP_EQ, CIRCPAD_STATE_GAP);
  tt_int_op(relay_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_EQ, 0);

  /* Simulate application traffic */
  circpad_event_nonpadding_sent((circuit_t*)client_side);
  circpad_event_nonpadding_received((circuit_t*)relay_side);
  circpad_event_nonpadding_sent((circuit_t*)relay_side);
  circpad_event_nonpadding_received((circuit_t*)client_side);

  tt_int_op(client_side->padding_info[0]->current_state,
            OP_EQ, CIRCPAD_STATE_END);
  tt_int_op(client_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_EQ, 0);
  tt_int_op(relay_side->padding_info[0]->current_state,
            OP_EQ, CIRCPAD_STATE_END);
  tt_int_op(relay_side->padding_info[0]->padding_was_scheduled_at_us,
            OP_EQ, 0);

  fprintf(stderr, "Client %d, relay: %d\n", n_client_cells, n_relay_cells);

 done:
  timers_shutdown();
  UNMOCK(circuit_package_relay_cell);

  return;
}

#define TEST_CIRCUITPADDING(name, flags) \
    { #name, test_##name, (flags), NULL, NULL }

struct testcase_t circuitpadding_tests[] = {
  //TEST_CHANNELPADDING(channelpadding_decide_to_pad_channel, 0),
  TEST_CIRCUITPADDING(circuitpadding_circuitsetup_machine, 0),
  END_OF_TESTCASES
};

