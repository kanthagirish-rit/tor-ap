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
#include "protover.h"
#include "nodelist.h"

extern smartlist_t *connection_array;
extern networkstatus_t *current_ns_consensus;
extern networkstatus_t *current_md_consensus;

circid_t get_unique_circ_id_by_chan(channel_t *chan);
uint32_t circpad_histogram_bin_us(circpad_machineinfo_t *mi, int bin);

static or_circuit_t * new_fake_orcirc(channel_t *nchan, channel_t *pchan);
channel_t *new_fake_channel(void);
void test_circuitpadding_negotiation(void *arg);

void test_circuitpadding_serialize(void *arg);
void test_circuitpadding_rtt(void *arg);
void test_circuitpadding_circuitsetup_machine(void *arg);

static void
simulate_single_hop_extend(circuit_t *client, circuit_t *mid_relay, int padding);
void free_fake_orcirc(circuit_t *circ);
void free_fake_origin_circuit(origin_circuit_t *circ);

static node_t padding_node;
static node_t non_padding_node;

static channel_t dummy_channel;

static void
nodes_init(void)
{
  padding_node.ri = tor_malloc_zero(sizeof(routerinfo_t));
  padding_node.ri->protocol_list = tor_strdup(protover_get_supported_protocols());

  non_padding_node.ri = tor_malloc_zero(sizeof(routerinfo_t));
  non_padding_node.ri->protocol_list = tor_strdup("Cons=1-2 Desc=1-2 "
                                                   "DirCache=1 HSDir=1-2 "
                                                   "HSIntro=3-4 HSRend=1-2 "
                                                   "Link=1-4 LinkAuth=1,3 "
                                                   "Microdesc=1-2 Relay=1-2");
}

static void
nodes_free(void)
{
  tor_free(padding_node.ri->protocol_list);
  tor_free(padding_node.ri);

  tor_free(non_padding_node.ri->protocol_list);
  tor_free(non_padding_node.ri);
}

static const node_t *
node_get_by_id_mock(const char *identity_digest)
{
  if (identity_digest[0] == 1) {
    return &padding_node;
  } else if (identity_digest[0] == 0) {
    return &non_padding_node;
  }

  return NULL;
}

static or_circuit_t *
new_fake_orcirc(channel_t *nchan, channel_t *pchan)
{
  or_circuit_t *orcirc = NULL;
  circuit_t *circ = NULL;
  crypt_path_t tmp_cpath;
  char whatevs_key[CPATH_KEY_MATERIAL_LEN];

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

void
free_fake_orcirc(circuit_t *circ)
{
  or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
  crypto_digest_free(orcirc->n_digest);
  crypto_digest_free(orcirc->p_digest);

  crypto_cipher_free(orcirc->n_crypto);
  crypto_cipher_free(orcirc->p_crypto);

  circpad_machines_free(circ);
  tor_free(circ);
}

void
free_fake_origin_circuit(origin_circuit_t *circ)
{
  circpad_machines_free(TO_CIRCUIT(circ));
  circuit_clear_cpath(circ);
  tor_free(circ);
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

    if (cell->payload[0] == RELAY_COMMAND_PADDING_NEGOTIATE) {
      fprintf(stderr, "Client sent padding negotiate\n");
      // Deliver to relay
      circpad_event_padding_negotiate(relay_side, cell);
    }

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

// Test reading and writing padding to strings (or options_t + consensus)
void
test_circuitpadding_serialize(void *arg)
{
  (void)arg;
}

void
test_circuitpadding_rtt(void *arg)
{
  /* Test Plan:
   *
   * 1. Test RTT measurement server side
   *    a. test usage of measured RTT
   * 2. Test termination of RTT measurement
   *    a. test non-update of RTT
   * 3. Test client side circuit and non-application of RTT..
   */
  uint32_t rtt_estimate;
  (void)arg;

  dummy_channel.cmux = circuitmux_alloc();
  relay_side = (circuit_t *)new_fake_orcirc(&dummy_channel,
                                            &dummy_channel);
  relay_side->purpose = CIRCUIT_PURPOSE_OR;

  monotime_init();
  timers_initialize();

  MOCK(circuit_package_relay_cell,
       circuit_package_relay_cell_mock);
  circpad_circ_responder_machine_setup(relay_side);

  /* Test 1: Test measuring RTT */
  circpad_event_nonpadding_received((circuit_t*)relay_side);
  tt_int_op(relay_side->padding_info[0]->last_rtt_packet_time_us, OP_NE, 0);

  tor_sleep_msec(2);
  circpad_event_nonpadding_sent((circuit_t*)relay_side);
  tt_int_op(relay_side->padding_info[0]->last_rtt_packet_time_us, OP_EQ, 0);


  tt_int_op(relay_side->padding_info[0]->rtt_estimate, OP_GE, 1900);
  tt_int_op(relay_side->padding_info[0]->rtt_estimate, OP_LE, 3000);
  tt_int_op(circpad_histogram_bin_us(relay_side->padding_info[0], 0),
            OP_EQ, relay_side->padding_info[0]->rtt_estimate);

  circpad_event_nonpadding_received((circuit_t*)relay_side);
  tt_int_op(relay_side->padding_info[0]->last_rtt_packet_time_us, OP_NE, 0);
  tor_sleep_msec(4);
  circpad_event_nonpadding_sent((circuit_t*)relay_side);
  tt_int_op(relay_side->padding_info[0]->last_rtt_packet_time_us, OP_EQ, 0);

  tt_int_op(relay_side->padding_info[0]->rtt_estimate, OP_GE, 2900);
  tt_int_op(relay_side->padding_info[0]->rtt_estimate, OP_LE, 5000);
  tt_int_op(circpad_histogram_bin_us(relay_side->padding_info[0], 0),
            OP_EQ, relay_side->padding_info[0]->rtt_estimate);

  /* Test 2: Termination of RTT measurement */
  rtt_estimate = relay_side->padding_info[0]->rtt_estimate;

  circpad_event_nonpadding_received((circuit_t*)relay_side);
  circpad_event_nonpadding_received((circuit_t*)relay_side);
  tor_sleep_msec(4);
  circpad_event_nonpadding_sent((circuit_t*)relay_side);
  circpad_event_nonpadding_sent((circuit_t*)relay_side);

  tt_int_op(relay_side->padding_info[0]->rtt_estimate, OP_EQ, rtt_estimate);
  tt_int_op(relay_side->padding_info[0]->last_rtt_packet_time_us, OP_EQ,
            CIRCPAD_STOP_ESTIMATING_RTT);
  tt_int_op(circpad_histogram_bin_us(relay_side->padding_info[0], 0),
            OP_EQ, relay_side->padding_info[0]->rtt_estimate);


done:

  free_fake_orcirc(relay_side);
  circuitmux_detach_all_circuits(dummy_channel.cmux, NULL);
  circuitmux_free(dummy_channel.cmux);
  timers_shutdown();
  UNMOCK(circuit_package_relay_cell);

  return;
}

void
test_circuitpadding_negotiation(void *arg)
{
  /**
   * Test plan:
   * 1. Test circuit where padding is supported by middle
   *    a. Make sure padding negotiation is sent
   *    b. Test padding negotiation delivery and parsing
   * FIXME:
   * 2. Test circuit where padding is unsupported by middle
   *    a. Make sure padding negotiation is not sent
   */
  (void)arg;
  client_side = (circuit_t *)origin_circuit_new();
  dummy_channel.cmux = circuitmux_alloc();
  relay_side = (circuit_t *)new_fake_orcirc(&dummy_channel,
                                            &dummy_channel);

  relay_side->purpose = CIRCUIT_PURPOSE_OR;
  client_side->purpose = CIRCUIT_PURPOSE_C_GENERAL;
  nodes_init();
  monotime_init();
  timers_initialize();

  MOCK(node_get_by_id,
       node_get_by_id_mock);

  MOCK(circuit_package_relay_cell,
       circuit_package_relay_cell_mock);


  /* Build two hops */
  simulate_single_hop_extend(client_side, relay_side, 1);
  simulate_single_hop_extend(client_side, relay_side, 1);

  /* Verify no padding yet */
  tt_ptr_op(relay_side->padding_machine[0], OP_EQ, NULL);
  tt_int_op(n_relay_cells, OP_EQ, 0);
  tt_int_op(n_client_cells, OP_EQ, 0);

  /* Try to negotiate padding */
  circpad_negotiate_padding(TO_ORIGIN_CIRCUIT(client_side),
                            CIRCPAD_MACHINE_CIRC_SETUP, 1);

  /* verify padding was negotiated */
  tt_ptr_op(relay_side->padding_machine[0], OP_NE, NULL);

  /* verify echo was sent */
  tt_int_op(n_relay_cells, OP_EQ, 1);
  tt_int_op(n_client_cells, OP_EQ, 1);

  /* Finish circuit */
  simulate_single_hop_extend(client_side, relay_side, 1);

done:

  free_fake_origin_circuit(TO_ORIGIN_CIRCUIT(client_side));
  free_fake_orcirc(relay_side);
  circuitmux_detach_all_circuits(dummy_channel.cmux, NULL);
  circuitmux_free(dummy_channel.cmux);
  UNMOCK(node_get_by_id);
  UNMOCK(circuit_package_relay_cell);
  nodes_free();
}

static void
simulate_single_hop_extend(circuit_t *client, circuit_t *mid_relay, int padding)
{
  char whatevs_key[CPATH_KEY_MATERIAL_LEN];
  char digest[DIGEST_LEN];
  tor_addr_t addr;

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

  // add an extend info to indicate if this node supports padding or not.
  // (set the first byte of the digest for our mocked node_get_by_id)
  digest[0] = padding;

  // XXX: Free this..
  hop->extend_info = extend_info_new(
          padding ? "padding" : "non-padding",
          digest, NULL, NULL, NULL,
          &addr, padding);

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
   *    a. Application traffic
   *
   * FIXME: This should focus more on exercising the machine
   * features rather than actual traffic patterns. For example,
   * test cancellation and bins empty/refill
   */
  (void)arg;
  dummy_channel.cmux = circuitmux_alloc();
  client_side = (circuit_t *)origin_circuit_new();
  relay_side = (circuit_t *)new_fake_orcirc(&dummy_channel, &dummy_channel);

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
    simulate_single_hop_extend(client_side, relay_side, 1);

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

  // FIXME: Test refill
  // FIXME: Test timer cancellation

 done:
  free_fake_origin_circuit(TO_ORIGIN_CIRCUIT(client_side));
  free_fake_orcirc(relay_side);

  circuitmux_detach_all_circuits(dummy_channel.cmux, NULL);
  circuitmux_free(dummy_channel.cmux);
  timers_shutdown();
  UNMOCK(circuit_package_relay_cell);

  return;
}

#define TEST_CIRCUITPADDING(name, flags) \
    { #name, test_##name, (flags), NULL, NULL }

struct testcase_t circuitpadding_tests[] = {
  //TEST_CIRCUITPADDING(circuitpadding_circuitsetup_machine, 0),
  TEST_CIRCUITPADDING(circuitpadding_negotiation, TT_FORK),
  TEST_CIRCUITPADDING(circuitpadding_circuitsetup_machine, TT_FORK),
  TEST_CIRCUITPADDING(circuitpadding_rtt, TT_FORK),
  END_OF_TESTCASES
};

