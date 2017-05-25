/* Copyright (c) 2017 The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "channel.h"
#include "or.h"
#include "circuitpadding.h"
#include "circuitlist.h"
#include "relay.h"
#include "compat_time.h"
#include "util.h"
#include "relay.h"
#include "protover.h"
#include "nodelist.h"

HANDLE_IMPL(circpad_machineinfo, circpad_machineinfo_t,);

#define USEC_PER_SEC (1000000)

void circpad_machine_remove_closest_token(circpad_machineinfo_t *mi);
void circpad_send_padding_cell_for_callback(circpad_machineinfo_t *mi);
circpad_decision_t circpad_machine_schedule_padding(circpad_machineinfo_t *mi);
circpad_decision_t circpad_machine_transition(circpad_machineinfo_t *mi,
                                              circpad_transition_t event);
circpad_machineinfo_t *circpad_machineinfo_new(circuit_t *on_circ, int machine_index);
STATIC uint32_t circpad_histogram_bin_us(circpad_machineinfo_t *mi, int bin);
STATIC const circpad_state_t *circpad_machine_current_state(
                                      circpad_machineinfo_t *machine);

/* Histogram helpers */
STATIC const circpad_state_t *
circpad_machine_current_state(circpad_machineinfo_t *machine)
{
  switch (machine->current_state) {
    case CIRCPAD_STATE_START:
    case CIRCPAD_STATE_END:
      return NULL;

    case CIRCPAD_STATE_BURST:
      return &CIRCPAD_GET_MACHINE(machine)->burst;

    case CIRCPAD_STATE_GAP:
      return &CIRCPAD_GET_MACHINE(machine)->gap;
  }

  log_fn(LOG_WARN,LD_CIRC,
         "Invalid circuit padding state %d",
         machine->current_state);
  //tor_fragile_assert();

  return NULL;
}

/**
 * Calculate the lower bound of a histogram bin. The upper bound
 * is obtained by calling this function with bin+1, and subtracting 1.
 */
STATIC uint32_t
circpad_histogram_bin_us(circpad_machineinfo_t *mi, int bin)
{
  const circpad_state_t *state = circpad_machine_current_state(mi);
  uint32_t start_usec;

  if (state->use_rtt_estimate)
    start_usec = mi->rtt_estimate;
  else
    start_usec = state->start_usec;

  if (bin == 0)
    return start_usec;

  return start_usec
      + (state->range_sec*USEC_PER_SEC)/(1<<(state->histogram_len-bin));
}

/**
 * This function frees any token bins allocated from a previous state
 *
 * Called after a state transition, or if the bins are empty.
 */
static void
circpad_machine_setup_tokens(circpad_machineinfo_t *mi)
{
  const circpad_state_t *state = circpad_machine_current_state(mi);

  /* If this state doesn't exist, or doesn't have token removal,
   * free any previous state's histogram, and bail */
  if (!state || !state->remove_tokens) {
    if (mi->histogram) {
      tor_free(mi->histogram);
      mi->histogram = NULL;
      mi->histogram_len = 0;
    }
    return;
  }

  /* Try to avoid re-mallocing if we don't really need to */
  if (!mi->histogram || (mi->histogram
          && mi->histogram_len != state->histogram_len)) {
    tor_free(mi->histogram); // null ok
    mi->histogram = tor_malloc_zero(sizeof(uint16_t)*state->histogram_len);
  }
  mi->histogram_len = state->histogram_len;

  memcpy(mi->histogram, state->histogram, sizeof(uint16_t)*state->histogram_len);
}

static uint32_t
circpad_machine_sample_delay(circpad_machineinfo_t *mi)
{
  const circpad_state_t *state = circpad_machine_current_state(mi);
  const uint16_t *histogram = NULL;
  int i = 0;
  uint32_t curr_weight = 0;
  uint32_t histogram_total = 0;
  uint32_t bin_choice;
  uint32_t bin_start, bin_end;

  tor_assert(state);

  if (state->remove_tokens) {
    tor_assert(mi->histogram && mi->histogram_len == state->histogram_len);

    histogram = mi->histogram;
    for (int b = 0; b < state->histogram_len; b++)
      histogram_total += histogram[b];
  } else {
    histogram = state->histogram;
    histogram_total = state->histogram_total;
  }

  bin_choice = crypto_rand_int(histogram_total);

  /* Skip all the initial zero bins */
  while (!histogram[i]) {
    i++;
  }
  curr_weight = histogram[i];

  // TODO: This is not constant-time. Pretty sure we don't
  // really need it to be, though.
  while (curr_weight < bin_choice) {
    i++;
    tor_assert(i < state->histogram_len);
    curr_weight += histogram[i];
  }

  tor_assert(i < state->histogram_len);
  tor_assert(histogram[i] > 0);

  // Store this index to remove the token upon callback.
  if (state->remove_tokens) {
    mi->chosen_bin = i;
  }

  if (i == state->histogram_len-1) {
    if (state->remove_tokens) {
      tor_assert(mi->histogram[i] > 0);
      mi->histogram[i]--;
    }

    return CIRCPAD_DELAY_INFINITE; // Infinity: Don't send a padding packet
  }

  tor_assert(i < state->histogram_len - 1);

  bin_start = circpad_histogram_bin_us(mi, i);
  bin_end = circpad_histogram_bin_us(mi, i+1);

  // Sample uniformly between histogram[i] to histogram[i+1]-1
  return bin_start + crypto_rand_int(bin_end - bin_start);
}

/* Remove a token from the bin corresponding to the delta since
 * last packet, or the next greater bin */
// TODO-MP-AP: remove from lower bin? lowest bin? closest bin?
// FIXME-MP-AP: Hidden service circuit machine may need both...
void
circpad_machine_remove_closest_token(circpad_machineinfo_t *mi)
{
  uint64_t current_time = monotime_absolute_usec();
  const circpad_state_t *state = circpad_machine_current_state(mi);
  uint64_t target_bin_us;
  uint32_t histogram_total = 0;

  if (!mi->padding_was_scheduled_at_us) {
    return;
  }

  target_bin_us = current_time - mi->padding_was_scheduled_at_us;

  // Cancel the padding, as this packet is counting instead.
  mi->padding_was_scheduled_at_us = 0;
  timer_disable(mi->padding_timer);

  if (!state || !state->remove_tokens)
    return;

  tor_assert(mi->histogram && mi->histogram_len == state->histogram_len);

  /* First, check if we came before bin 0. In which case, decrement it. */
  if (circpad_histogram_bin_us(mi, 0) > target_bin_us) {
    mi->histogram[0]--;
    fprintf(stderr, "Token removal: %p %d\n", mi, mi->histogram[0]);
  } else {
    /* Otherwise, we need to remove the token from the first bin
     * whose upper bound is greater than the target, and that
     * has tokens remaining. */
    int i;
    for (i = 1; i <= mi->histogram_len; i++) {
      if (circpad_histogram_bin_us(mi, i) > target_bin_us) {
        if (mi->histogram[i-1]) {
          mi->histogram[i-1]--;
          fprintf(stderr, "Token removal: %p %d\n", mi, mi->histogram[i-1]);
          break;
        }
      }
    }

    // FIXME-MP-AP: Hrmm... What to do here? Remove lower, refill, or ignore?
    if (i > mi->histogram_len) {
      fprintf(stderr, "No more upper tokens: %p\n", mi);
    }
  }

  /* Check if bins empty. Right now, we're operating under the assumption
   * that this loop is better than the extra space for maintaining a
   * running total in machineinfo */
  for (int b = 0; b < state->histogram_len; b++)
    histogram_total += mi->histogram[b];

  if (histogram_total == 0) {
    circpad_event_bins_empty(mi);
  }
}

static crypt_path_t *
cpath_clone_shallow(crypt_path_t *cpath, int hops)
{
  crypt_path_t *new_head = NULL;
  crypt_path_t *new_prev = NULL;
  crypt_path_t *new_curr = NULL;
  crypt_path_t *orig_iter = cpath;
  int i;

  for (i = 0; i < hops; i++) {
    new_curr = tor_malloc_zero(sizeof(crypt_path_t));
    new_curr->magic = CRYPT_PATH_MAGIC;

    memcpy(new_curr, orig_iter, sizeof(crypt_path_t));
    new_curr->prev = new_prev;

    if (new_prev) {
      new_prev->next = new_curr;
    } else {
      /* head is null */
      new_head = new_curr;
    }

    new_prev = new_curr;
    orig_iter = orig_iter->next;

    // Did we wrap around?
    if (orig_iter == cpath)
      break;
  }

  new_curr->next = new_head;
  new_head->prev = new_curr;

  if (orig_iter == cpath && i == 0) {
    log_fn(LOG_WARN,LD_CIRC,
           "Trying to do padding on short (one-hop) circuit!");
    BUG(i == 0);
  }

  return new_head;
}

static void
cpath_free_shallow(crypt_path_t *cpath)
{
  crypt_path_t *iter = cpath;
  crypt_path_t *next;

  if (!cpath) return;

  do {
    next = iter->next;
    tor_free(iter);
    iter = next;
  } while(iter != cpath);

}

static int
circpad_send_command_to_hop(origin_circuit_t *circ, int hopnum,
                            uint8_t relay_command, const uint8_t *payload,
                            ssize_t payload_len)
{
  crypt_path_t *new_cpath;
  int ret;

  // Check that we have at least a 2 hop circuit
  if (circuit_get_cpath_len(circ) < hopnum) {
    log_fn(LOG_WARN,LD_CIRC,
           "Circuit %u has %d hops, not %d",
           circ->global_identifier,
           circuit_get_cpath_len(circ), hopnum);
    return -1;
  }

  /* Prepare a cpath to get us to the middle hop */
  new_cpath = cpath_clone_shallow(circ->cpath, hopnum);

  // Ensure that our cpath is not short, and we have both hops are open
  // FIXME-MP-AP: move this check into clone? But then it needs to generalize
  // to more than 2 hops..
  if (!new_cpath || new_cpath == new_cpath->next ||
      new_cpath->state != CPATH_STATE_OPEN ||
      new_cpath->next->state != CPATH_STATE_OPEN) {
    log_fn(LOG_WARN,LD_CIRC,
           "Padding callback on circuit %u without two opened hops.",
           circ->global_identifier);
    cpath_free_shallow(new_cpath);
    return -1;
  }

  /* Send the drop command to the second hop */
  ret = relay_send_command_from_edge(0, TO_CIRCUIT(circ), relay_command,
                                     (const char*)payload, payload_len,
                                     new_cpath);

  cpath_free_shallow(new_cpath);

  return ret;
}

void
circpad_send_padding_cell_for_callback(circpad_machineinfo_t *mi)
{
  mi->padding_was_scheduled_at_us = 0;

  // Make sure circuit didn't close on us
  if (mi->on_circ->marked_for_close) {
    log_fn(LOG_INFO,LD_CIRC,
           "Padding callback on a circuit marked for close. Ignoring.");
    return;
  }

  if (mi->histogram && mi->histogram_len) {
    tor_assert(mi->chosen_bin < mi->histogram_len);
    tor_assert(mi->histogram[mi->chosen_bin] > 0);
    mi->histogram[mi->chosen_bin]--;
  }

  if (CIRCUIT_IS_ORIGIN(mi->on_circ)) {
    circpad_send_command_to_hop(TO_ORIGIN_CIRCUIT(mi->on_circ), 2,
                                RELAY_COMMAND_DROP, NULL, 0);
  } else {
    // If we're a non-origin circ, we can just send from here as if we're the
    // edge.
    relay_send_command_from_edge(0, mi->on_circ, RELAY_COMMAND_DROP, NULL, 0, NULL);
  }

  /* Check if bins empty. Right now, we're operating under the assumption
   * that this loop is better than the extra space for maintaining a
   * running total in machineinfo */
  if (mi->histogram && mi->histogram_len) {
    uint32_t histogram_total = 0;

    for (int b = 0; b < mi->histogram_len; b++)
      histogram_total += mi->histogram[b];

    if (histogram_total == 0) {
      circpad_event_bins_empty(mi);
    }
  }
}

static void
circpad_send_padding_callback(tor_timer_t *timer, void *args,
                              const struct monotime_t *time)
{
  circpad_machineinfo_t *mi =
      circpad_machineinfo_handle_get((struct circpad_machineinfo_handle_t*)args);
  (void)timer; (void)time;

  if (mi && mi->on_circ) {
    assert_circuit_ok(mi->on_circ);
    circpad_send_padding_cell_for_callback(mi);
  } else {
    // This shouldn't happen (represents a handle leak)
    log_fn(LOG_WARN,LD_CIRC,
            "Circuit closed while waiting for padding timer.");
    tor_fragile_assert();
  }

  // TODO-MP-AP: Unify this counter with channelpadding somehow for rephist stats
  //total_timers_pending--;
}

circpad_decision_t
circpad_machine_schedule_padding(circpad_machineinfo_t *mi)
{
  uint32_t in_us = 0;
  struct timeval timeout;
  tor_assert(mi);

  fprintf(stderr, "Scheduling padding?\n");
  // Don't pad in either state start or end (but
  // also don't cancel any previously scheduled padding
  // either).
  if (mi->current_state == CIRCPAD_STATE_START ||
      mi->current_state == CIRCPAD_STATE_END) {
    fprintf(stderr, "End state\n");
    return CIRCPAD_NONPADDING_STATE;
  }

  if (mi->padding_was_scheduled_at_us) {
    /* Cancel current timer (if any) */
    timer_disable(mi->padding_timer);
    mi->padding_was_scheduled_at_us = 0;
  }

  in_us = circpad_machine_sample_delay(mi);

  fprintf(stderr, "Padding in %u usec\n", in_us);

  if (in_us <= 0) {
    mi->padding_was_scheduled_at_us = monotime_absolute_usec();
    circpad_send_padding_cell_for_callback(mi);
    return CIRCPAD_PADDING_SENT;
  }

  // Don't schedule if we have infinite delay.
  if (in_us == CIRCPAD_DELAY_INFINITE) {
    // XXX-MP-AP: Return differently if we transition or not?
    circpad_event_infinity(mi);
    return CIRCPAD_WONTPAD_INFINITY;
  }

  timeout.tv_sec = in_us/USEC_PER_SEC;
  timeout.tv_usec = (in_us%USEC_PER_SEC);

  fprintf(stderr, "Padding in %u sec, %u usec\n",
          (unsigned)timeout.tv_sec, (unsigned)timeout.tv_usec);

  if (!mi->on_circ->padding_handles[mi->machine_index]) {
    mi->on_circ->padding_handles[mi->machine_index] =
        circpad_machineinfo_handle_new(mi);
  }

  if (mi->padding_timer) {
    timer_set_cb(mi->padding_timer,
                 circpad_send_padding_callback,
                 mi->on_circ->padding_handles[mi->machine_index]);
  } else {
    mi->padding_timer =
        timer_new(circpad_send_padding_callback,
                  mi->on_circ->padding_handles[mi->machine_index]);
  }
  timer_schedule(mi->padding_timer, &timeout);

  // TODO-MP-AP: Unify with channelpadding counter
  //rep_hist_padding_count_timers(++total_timers_pending);

  mi->padding_was_scheduled_at_us = monotime_absolute_usec();

  return CIRCPAD_PADDING_SCHEDULED;
}

circpad_decision_t
circpad_machine_transition(circpad_machineinfo_t *mi,
                           circpad_transition_t event)
{
  const circpad_state_t *state =
      circpad_machine_current_state(mi);

  if (!state) {
    if (mi->current_state == CIRCPAD_STATE_START &&
        CIRCPAD_GET_MACHINE(mi)->transition_burst_events & event) {
      mi->current_state = CIRCPAD_STATE_BURST;

      circpad_machine_setup_tokens(mi);
      return circpad_machine_schedule_padding(mi);
    }
    return CIRCPAD_WONTPAD_EVENT;
  }

  if (state->transition_prev_events & event) {
    mi->current_state = state->prev_state;

    circpad_machine_setup_tokens(mi);
    return circpad_machine_schedule_padding(mi);
  }

  if (state->transition_reschedule_events & event) {
    return circpad_machine_schedule_padding(mi);
  }

  if (state->transition_cancel_events & event) {
    if (mi->padding_was_scheduled_at_us) {
      /* Cancel current timer (if any) */
      timer_disable(mi->padding_timer);
      mi->padding_was_scheduled_at_us = 0;
      return CIRCPAD_WONTPAD_CANCELED;
    }
    return CIRCPAD_WONTPAD_EVENT;
  }

  if (state->transition_next_events & event) {
    mi->current_state = state->next_state;

    fprintf(stderr, "State transition\n");
    circpad_machine_setup_tokens(mi);
    return circpad_machine_schedule_padding(mi);
  }

  return CIRCPAD_WONTPAD_EVENT;
}

void
circpad_event_nonpadding_sent(circuit_t *on_circ)
{
  for (int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
       i++) {

    circpad_machine_remove_closest_token(on_circ->padding_info[i]);

    circpad_machine_transition(on_circ->padding_info[i],
                               CIRCPAD_TRANSITION_ON_NONPADDING_SENT);

    /* Round trip time estimate (only valid for relay-side machines) */
    if (on_circ->padding_info[i]->last_rtt_packet_time_us &&
        on_circ->padding_info[i]->last_rtt_packet_time_us !=
        CIRCPAD_STOP_ESTIMATING_RTT) {
      uint64_t rtt_time = monotime_absolute_usec() -
          on_circ->padding_info[i]->last_rtt_packet_time_us;

      /* Reset the last RTT packet time, so we can tell if two
       * arrive back to back */
      on_circ->padding_info[i]->last_rtt_packet_time_us = 0;

      /* Use INT32_MAX to ensure the addition doesn't overflow */
      if (rtt_time >= INT32_MAX) {
        log_fn(LOG_WARN,LD_CIRC,
               "Circuit RTT estimate overflowed: "U64_FORMAT
               " vs "U64_FORMAT, U64_PRINTF_ARG(monotime_absolute_usec()),
               U64_PRINTF_ARG(
                 on_circ->padding_info[i]->last_rtt_packet_time_us));
        continue;
      }

      /* Cheap EWMA */
      if (on_circ->padding_info[i]->rtt_estimate) {
        on_circ->padding_info[i]->rtt_estimate += (uint32_t)rtt_time;
        on_circ->padding_info[i]->rtt_estimate /= 2;
      } else {
        on_circ->padding_info[i]->rtt_estimate = (uint32_t)rtt_time;
      }
    }
  }
}

void
circpad_event_nonpadding_received(circuit_t *on_circ)
{
  for (int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
      i++) {
    circpad_machine_transition(on_circ->padding_info[i],
                               CIRCPAD_TRANSITION_ON_NONPADDING_RECV);


    /* If we already have a last RTT packet time, that means we
     * did not get a response before this packet. The RTT estimate
     * only makes sense if we do not have multiple packets on the
     * wire, so stop estimating if this is the second packet
     * back to back. */
    // XXX: Optimistic data may cause this to cut off before
    // the connection to the exit is made.. Maybe we set a flag
    // when this happens so that we know to stop *after* we get
    // the first response packet?
    if (on_circ->padding_info[i]->last_rtt_packet_time_us &&
        on_circ->padding_info[i]->last_rtt_packet_time_us !=
        CIRCPAD_STOP_ESTIMATING_RTT) {
      // FIXME: Safelog?
      log_fn(LOG_INFO, LD_CIRC,
             "Stopping RTT estimation on circuit ("U64_FORMAT", %d) after "
             "two back to back packets. Current RTT: %d",
             U64_PRINTF_ARG(on_circ->n_chan->global_identifier),
             on_circ->n_circ_id, on_circ->padding_info[i]->rtt_estimate);
      on_circ->padding_info[i]->last_rtt_packet_time_us
          = CIRCPAD_STOP_ESTIMATING_RTT;
    } else {
      on_circ->padding_info[i]->last_rtt_packet_time_us
          = monotime_absolute_usec();
    }
  }
}

void
circpad_event_padding_sent(circuit_t *on_circ)
{
  for (int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
       i++) {
    circpad_machine_transition(on_circ->padding_info[i],
                             CIRCPAD_TRANSITION_ON_PADDING_SENT);
  }
}

void
circpad_event_padding_received(circuit_t *on_circ)
{
  for(int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
      i++) {
    circpad_machine_transition(on_circ->padding_info[i],
                              CIRCPAD_TRANSITION_ON_PADDING_RECV);
  }
}

void
circpad_event_infinity(circpad_machineinfo_t *mi)
{
  circpad_machine_transition(mi, CIRCPAD_TRANSITION_ON_INFINITY);
}

void
circpad_event_bins_empty(circpad_machineinfo_t *mi)
{
  if (!circpad_machine_transition(mi, CIRCPAD_TRANSITION_ON_BINS_EMPTY)) {
    circpad_machine_setup_tokens(mi);
  }
}

void
circpad_event_padding_negotiate(circuit_t *circ, cell_t *cell)
{
  circpad_negotiate_t *negotiate;

  if (circpad_negotiate_parse(&negotiate, cell->payload+RELAY_HEADER_SIZE,
                               CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE) < 0) {
    log_fn(LOG_WARN, LD_CIRC,
          "Received malformed PADDING_NEGOTIATE cell; "
          "dropping.");

    return;
  }

  if (negotiate->command == CIRCPAD_COMMAND_STOP) {
    circpad_machines_free(circ);
  } else if (negotiate->command == CIRCPAD_COMMAND_START) {
    // TODO-MP-AP: Support the other machine types..

    switch (negotiate->machine_type) {
      case CIRCPAD_MACHINE_CIRC_SETUP:
        circpad_circ_responder_machine_setup(circ);
        break;
      case CIRCPAD_MACHINE_HS_CLIENT_INTRO:
        break;
      case CIRCPAD_MACHINE_HS_SERVICE_INTRO:
        break;
      case CIRCPAD_MACHINE_HS_SERVICE_REND:
        break;
      case CIRCPAD_MACHINE_WTF_PAD:
        break;
      default:
        break;
    }
  }

  /* If the other end requested an echo, send one. */
  /* FIXME-MP-AP: We could instead/additionally just transition
   * immediately into the burst state...
   */
  if (negotiate->echo_request) {
    relay_send_command_from_edge(0, circ, RELAY_COMMAND_DROP, NULL, 0, NULL);
  }

  circpad_negotiate_free(negotiate);
}

void
circpad_machines_free(circuit_t *circ)
{
  for (int i = 0; i < CIRCPAD_MAX_MACHINES; i++) {
    circpad_machineinfo_handle_free(circ->padding_handles[i]);

    if (circ->padding_info[i]) {
      circpad_machineinfo_handles_clear(circ->padding_info[i]);
      tor_free(circ->padding_info[i]->histogram);
      timer_free(circ->padding_info[i]->padding_timer);
      tor_free(circ->padding_info[i]);
    }
  }
}

circpad_machineinfo_t *
circpad_machineinfo_new(circuit_t *on_circ, int machine_index)
{
  circpad_machineinfo_t *mi = tor_malloc_zero(sizeof(circpad_machineinfo_t));
  mi->machine_index = machine_index;
  mi->on_circ = on_circ;

  return mi;
}

/* Machines for various usecases */
static circpad_machine_t circ_client_machine;
void
circpad_circ_client_machine_setup(circuit_t *on_circ)
{
  /* Free the old machines (if any) */
  circpad_machines_free(on_circ);

  on_circ->padding_machine[0] = &circ_client_machine;
  on_circ->padding_info[0] = circpad_machineinfo_new(on_circ, 0);

  if (circ_client_machine.is_initialized)
    return;

  circ_client_machine.transition_burst_events =
    CIRCPAD_TRANSITION_ON_NONPADDING_RECV;

  circ_client_machine.burst.transition_reschedule_events =
    CIRCPAD_TRANSITION_ON_PADDING_RECV |
    CIRCPAD_TRANSITION_ON_NONPADDING_RECV;

  circ_client_machine.burst.transition_cancel_events =
    CIRCPAD_TRANSITION_ON_NONPADDING_SENT;

  circ_client_machine.burst.transition_next_events =
    CIRCPAD_TRANSITION_ON_BINS_EMPTY;

  circ_client_machine.burst.next_state =
    CIRCPAD_STATE_END;

  circ_client_machine.burst.remove_tokens = 1;

  // FIXME: Tune this histogram
  circ_client_machine.burst.histogram_len = 5;
  circ_client_machine.burst.start_usec = 500;
  circ_client_machine.burst.range_sec = 1;
  circ_client_machine.burst.histogram[0] = 5;
  circ_client_machine.burst.histogram_total = 5;

  circ_client_machine.is_initialized = 1;

  return;
}

static circpad_machine_t circ_responder_machine;
void
circpad_circ_responder_machine_setup(circuit_t *on_circ)
{
  /* Free the old machines (if any) */
  circpad_machines_free(on_circ);

  on_circ->padding_machine[0] = &circ_responder_machine;
  on_circ->padding_info[0] = circpad_machineinfo_new(on_circ, 0);

  if (circ_responder_machine.is_initialized)
    return;

  circ_responder_machine.transition_burst_events =
    CIRCPAD_TRANSITION_ON_PADDING_RECV |
    CIRCPAD_TRANSITION_ON_NONPADDING_RECV;

  circ_responder_machine.burst.transition_reschedule_events =
    CIRCPAD_TRANSITION_ON_NONPADDING_SENT;

  circ_responder_machine.burst.transition_next_events =
    CIRCPAD_TRANSITION_ON_PADDING_RECV;

  circ_responder_machine.burst.next_state =
    CIRCPAD_STATE_GAP;

  circ_responder_machine.burst.use_rtt_estimate = 1;
  circ_responder_machine.burst.histogram_len = 1;
  circ_responder_machine.burst.start_usec = 5000;
  circ_responder_machine.burst.range_sec = 10;
  circ_responder_machine.burst.histogram[0] = 1; // Only infinity for this state
  circ_responder_machine.burst.histogram_total = 1;

  circ_responder_machine.gap.transition_reschedule_events =
    CIRCPAD_TRANSITION_ON_PADDING_RECV |
    CIRCPAD_TRANSITION_ON_NONPADDING_RECV;

  circ_responder_machine.gap.transition_next_events =
    CIRCPAD_TRANSITION_ON_BINS_EMPTY |
    CIRCPAD_TRANSITION_ON_NONPADDING_SENT;

  circ_responder_machine.gap.next_state =
    CIRCPAD_STATE_END;

  // FIXME: Tune this histogram
  circ_responder_machine.gap.use_rtt_estimate = 1;
  circ_responder_machine.gap.histogram_len = 6;
  circ_responder_machine.gap.start_usec = 5000;
  circ_responder_machine.gap.range_sec = 10;
  circ_responder_machine.gap.histogram[0] = 0;
  circ_responder_machine.gap.histogram[1] = 1;
  circ_responder_machine.gap.histogram[2] = 2;
  circ_responder_machine.gap.histogram[3] = 2;
  circ_responder_machine.gap.histogram[4] = 1;
  circ_responder_machine.gap.histogram_total = 6;

  circ_responder_machine.is_initialized = 1;

  return;
}

static int
circpad_node_supports_padding(const node_t *node)
{
  if (node->ri) {
    const char *protos = node->ri->protocol_list;
    if (protos == NULL)
      return 0;
    return protocol_list_supports_protocol(protos, PRT_PADDING, 1);
  }

  return 0;
}

static const node_t *
circuit_get_nth_hop(origin_circuit_t *circ, int hop)
{
  crypt_path_t *iter = circ->cpath;
  int i;

  for (i = 1; i < hop; i++) {
    iter = iter->next;

    // Did we wrap around?
    if (iter == circ->cpath)
      return NULL;
  }

  return node_get_by_id(iter->extend_info->identity_digest);
}

static int
circpad_circuit_supports_padding(origin_circuit_t *circ)
{
  const node_t *hop;

  if (!(hop = circuit_get_nth_hop(circ, 2))) {
    return 0;
  }

  return circpad_node_supports_padding(hop);
}

/**
 * Try to negotiate padding.
 *
 * Returns 1 if successful (or already set up), 0 otherwise.
 */
int
circpad_negotiate_padding(origin_circuit_t *circ, circpad_machine_num_t machine,
                          int echo)
{
  circpad_negotiate_t type;
  cell_t cell;
  ssize_t len;

  // If we have a padding machine, we already did this.
  if (TO_CIRCUIT(circ)->padding_machine[0]) {
    return 1;
  }

  if (!circpad_circuit_supports_padding(circ)) {
    return 0;
  }

  memset(&cell, 0, sizeof(cell_t));
  memset(&type, 0, sizeof(circpad_negotiate_t));
  // This gets reset to RELAY_EARLY appropriately by
  // relay_send_command_from_edge_. At least, it looks that way.
  // QQQ-MP-AP: Verify that.
  cell.command = CELL_RELAY;

  circpad_negotiate_set_command(&type, CIRCPAD_COMMAND_START);
  circpad_negotiate_set_version(&type, 0);
  circpad_negotiate_set_machine_type(&type, machine);
  circpad_negotiate_set_echo_request(&type, echo);

  if ((len = circpad_negotiate_encode(cell.payload, CELL_PAYLOAD_SIZE,
        &type)) < 0)
    return -1;

  /* Set up our own machine before telling the other side */
  switch (machine) {
    case CIRCPAD_MACHINE_CIRC_SETUP:
      circpad_circ_client_machine_setup(TO_CIRCUIT(circ));
      break;
    case CIRCPAD_MACHINE_HS_CLIENT_INTRO:
      break;
    case CIRCPAD_MACHINE_HS_SERVICE_INTRO:
      break;
    case CIRCPAD_MACHINE_HS_SERVICE_REND:
      break;
    case CIRCPAD_MACHINE_WTF_PAD:
      break;
    default:
      break;
  }

  return circpad_send_command_to_hop(circ, 2, RELAY_COMMAND_PADDING_NEGOTIATE,
                                     cell.payload, len) == 0;
}

/* Serialization */
// TODO: Should we use keyword=value here? Are there helpers for that?
static void
circpad_state_serialize(const circpad_state_t *state,
                        smartlist_t *chunks)
{
  smartlist_add_asprintf(chunks, " %u", state->histogram[0]);
  for (int i = 1; i < state->histogram_len; i++) {
    smartlist_add_asprintf(chunks, ",%u",
                           state->histogram[i]);
  }

  smartlist_add_asprintf(chunks, " %u %u 0x%x %u 0x%x 0x%x %u %u",
                         state->start_usec, state->range_sec,
                         state->transition_prev_events, state->prev_state,
                         state->transition_reschedule_events,
                         state->transition_next_events, state->next_state,
                         state->remove_tokens);
}

char *
circpad_machine_to_string(const circpad_machine_t *machine)
{
  smartlist_t *chunks = smartlist_new();
  char *out;

  smartlist_add_asprintf(chunks,
                         "0x%x",
                         machine->transition_burst_events);

  circpad_state_serialize(&machine->gap, chunks);
  circpad_state_serialize(&machine->burst, chunks);

  out = smartlist_join_strings(chunks, "", 0, NULL);

  SMARTLIST_FOREACH(chunks, char *, cp, tor_free(cp));
  smartlist_free(chunks);
  return out;
}

// XXX: Writeme
const circpad_machine_t *
circpad_string_to_machine(const char *str)
{
  (void)str;
  return NULL;
}
