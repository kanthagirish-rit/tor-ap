/* Copyright (c) 2017 The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "compat_time.h"

HANDLE_IMPL(circpad_machineinfo, circpad_machineinfo_t,);

/* Histogram helpers */

/**
 * Calculate the lower bound of a histogram bin. The upper bound
 * is obtained by calling this function with bin+1, and subtracting 1.
 */
inline static uint32_t circpad_histogram_bin_us(circpad_state_t *state,
                                                int bin)
{
  if (bin == 0)
    return state->start_usec;

  return state->start_usec
      + (state->range_sec*USEC_PER_SEC)/(1<<(state->histogram_len-bin));
}

inline static const circpad_state_t *circpad_machine_current_state(
                                      circpad_machineinfo_t *machine)
{
  switch (machine->current_state) {
    case CIRCPAD_STATE_START:
      return NULL;

    case CIRCPAD_STATE_BURST:
      return &CIRCPAD_GET_MACHINE(machine)->burst;

    case CIRCPAD_STATE_GAP:
      return &CIRCPAD_GET_MACHINE(machine)->gap;

  }

  // XXX: tor_bug?
  tor_assert(0);
}

/**
 * This function frees any token bins allocated from a previous state
 *
 * Called after a state transition, or if the bins are empty.
 */
static void circpad_machine_setup_tokens(circpad_machineinfo_t *mi)
{
  circpad_state_t *state = circpad_machine_current_state(mi);

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

inline static uint32_t circpad_machine_sample_delay(circpad_machineinfo_t *mi,
                                                    int *empty_hint)
{
  circpad_state_t *state = circpad_machine_current_state(mi);
  const uint16_t *histogram = NULL;
  int i = 0;
  uint32_t curr_weight;
  uint32_t histogram_total = 0;
  uint32_t bin_choice; 
  uint16_t bin_start, bin_end;

  tor_assert(state);
  tor_assert(empty_hint);

  if (state->remove_tokens) {
    tor_assert(mi->histogram && mi->histogram_len == state->histogram_len);

    histogram = mi->histogram;
    for (int b = 0; i < state->histogram_len; b++)
      histogram_total += histogram[b];
  } else {
    histogram = state->histogram;
    histogram_total = state->histogram_total;
  }

  bin_choice = crypto_rand_int(histogram_total);
  curr_weight = histogram[0];

  // TODO: This is not constant-time. Pretty sure we don't
  // really need it to be, though.
  while (curr_weight < bin_choice) {
    tor_assert(i < state->histogram_len);
    curr_weight += histogram[i];
    i++;
  }

  tor_assert(curr_weight);
  tor_assert(i < state->histogram_len);

  if (state->remove_tokens) {
    tor_assert(mi->histogram[i] > 0);
    mi->histogram[i]--;
  }

  if (curr_weight == total_weight) {
    *empty_hint = 1;
  } else {
    *empty_hint = 0;
  }

  if (i == state->histogram_len-1)
    return CIRCPAD_DELAY_INFINITE; // Infinity: Don't send a padding packet

  tor_assert(i < state->histogram_len - 1);

  bin_start = circpad_histogram_bin_ms(state, i);
  bin_end = circpad_histogram_bin_ms(state, i+1);

  // Sample uniformly between histogram[i] to histogram[i+1]-1
  return bin_start + crypto_rand_int(bin_end - bin_start);
}

/* Remove a token from the bin corresponding to the delta since
 * last packet, or the next greater bin */
void circpad_machine_remove_closest_token(circpad_machineinfo_t *mi)
{
  uint64_t current_time = monotime_absolute_usec();
  circpad_state_t *state = circpad_machine_current_state(mi);
  uint64_t target_bin_us;
  uint32_t histogram_total = 0;

  target_bin_us = current_time - mi->last_send_packet_time_us;

  mi->last_send_packet_time_us = current_time;

  if (!state->remove_tokens)
    return;

  tor_assert(mi->histogram && mi->histogram_len == state->histogram_len);

  /* First, check if we came before bin 0. In which case, decrement it. */
  if (circpad_histogram_bin_us(mi, 0) > target_bin_us) {
    mi->histogram[0]--;
  } else {
    /* Otherwise, we need to remove the token from the bin
     * whose upper bound is greater than the target */ 
    for (int i = 1; i <= mi->histogram_len; i++) {
      if (circpad_histogram_bin_us(mi, i) > target_bin_us) {
        if (mi->histogram[i-1]) {
          mi->histogram[i-1]--;
          break;
        }
      }
    }
  }

  /* Check if bins empty. Right now, we're operating under the assumption
   * that this loop is better than the extra space for maintaining a
   * running total in machineinfo */
  for (int b = 0; i < state->histogram_len; b++)
    histogram_total += histogram[b];

  if (histogram_total == 0) {
    circpad_event_bins_empty(mi);
  }
}

static crypt_path_t *cpath_clone_shallow(crypt_path_t *cpath, int hops)
{
  crypt_path_t *new_head = NULL;
  crypt_path_t *new_prev = NULL;
  crypt_path_t *new_curr = NULL;
  crypt_path_t *orig_iter = cpath;

  for (int i = 0; i < hops && orig_iter != cpath; i++) {
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
  }

  new_curr->next = new_head;
  new_head->prev = new_curr;

  if (old_iter == cpath) {
    // XXX: tor_bug log (short cpath)
  }

  return new_head;
}

static void cpath_free_shallow(crypt_path_t *cpath)
{
  crypt_path_t *iter = cpath;
  crypt_path_t *next;
  crypt_path_t *last;

  if (!cpath) return;
 
  last = cpath->prev;

  while(iter != last) {
    next = iter->next;
    tor_free(iter);
    iter = next;
  }
}

// XXX: We should make sure that this doesn't mess up circ SENDME windows
// on the client.. exit should be fine, and the middle shouldn't have a
// window (though that may cause the code to get confused).
int circpad_send_padding_cell_for_callback(circpad_machineinfo_t *mi,
                                           const struct monotime_t *now)
{
  mi->is_padding_scheduled = 0;
 
  // Make sure circuit didn't close on us
  if (mi->on_circ->marked_for_close) {
    // XXX: tor_log at info?
    return;
  }

  // TODO: Should we write a utility function to use now instead?
  mi->last_packet_send_time_us = monotime_absolute_usec(); 

  if (CIRCUIT_IS_ORIGIN(mi->on_circ)) {
    crypt_path_t *new_cpath;

    // Check that we have at least a 2 hop circuit
    if (circuit_get_cpath_len(TO_ORIGIN_CIRC(mi->on_circ)) < 2) {
      // XXX: tor_log
      return;
    }

    /* Prepare a cpath to get us to the middle hop */
    new_cpath = cpath_clone_shallow(TO_ORIGIN_CIRC(mi->on_circ)->cpath, 2);

    // Ensure that our cpath is not short, and we have both hops are open
    if (!new_cpath || new_cpath == new_cpath->next ||
        new_cpath->state != CPATH_STATE_OPEN ||
        new_cpath->next->state != CPATH_STATE_OPEN) {
      // XXX: tor_log.. 
      cpath_free_shallow(new_cpath);
      return;
    }

    /* Send the drop command to the second hop */
    relay_send_command_from_edge(0, mi->on_circ, RELAY_DROP, NULL, 0, new_cpath);

    cpath_free_shallow(new_cpath);
  } else {
    // If we're a non-origin circ, we can just send from here as if we're the
    // edge.
    relay_send_command_from_edge(0, mi->on_circ, RELAY_DROP, NULL, 0, NULL);
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
    circpad_send_padding_cell_for_callback(mi, time);
  } else {
    // XXX: This shouldn't happen (represents a handle leak)
    log_fn(LOG_INFO,LD_OR,
            "Circuit closed while waiting for timer.");
  }

  total_timers_pending--;
}

// XXX: return decision?
int circpad_machine_schedule_padding(circuit_machineinfo_t *mi)
{
  uint32_t in_us = 0;
  uint64_t now_us = 0;
  int bins_empty = 0;
  tor_assert(mi);

  // Don't pad in either state start or end.
  if (mi->current_state == CIRCPAD_STATE_START ||
      mi->current_state == CIRCPAD_STATE_END) {
    // XXX: return decision
    return;
  }

  if (mi->is_padding_scheduled) {
    /* Cancel current timer (if any) */
    timer_disable(mi->padding_timer);
    mi->is_padding_scheduled = 0;
  }

  in_us = circpad_machine_sample_delay(mi, &bins_empty);

  if (in_us <= 0) {
    mi->is_padding_scheduled = 1;
    circpad_send_padding_cell_for_callback(on_circ);
    // XXX: decision enum?
    return CIRCPAD_PADDING_SENT;
  }

  // Don't schedule if we have infinite delay.
  if (in_us == CIRCPAD_DELAY_INFINITE) {
    // XXX: Return differently if we transition or not
    circpad_event_infinity(mi);
    return;
  }

  timeout.tv_sec = in_us/USEC_PER_SEC;
  timeout.tv_usec = (in_us%USEC_PER_SEC);

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

  rep_hist_padding_count_timers(++total_timers_pending);

  mi->is_padding_scheduled = 1;

  if (bins_empty) {
    // XXX: Return differently if we transition or not here
    circpad_event_bins_empty(mi);
    return;
  }

  return CIRCPAD_PADDING_SCHEDULED;
}

// XXX: return indicating transition
int circpad_machine_transition(circpad_machineinfo_t *mi,
                               circpad_transition_t event)
{
  circpad_state_t *state =
      circpad_machine_current_state(mi);

  if (!state) {
    if (CIRCPAD_GET_MACHINE(mi)->transition_burst_events & event) {
      mi->current_state = CIRCPAD_STATE_BURST;

      circpad_machine_setup_tokens(mi);
      circpad_machine_schedule_padding(mi);
      return 1;
    }
    return 0;
  }

  if (state->transition_prev_events & event) {
    mi->current_state = state->prev_state;

    circpad_machine_setup_tokens(mi);
    circpad_machine_schedule_padding(mi);
    return 1;
  }

  if (state->transition_reschedule_events & event) {
    circpad_machine_schedule_padding(mi);
    return 1;
  }
 
  if (state->transition_next_events & event) {
    mi->current_state = state->next_state;
    
    circpad_machine_setup_tokens(mi);
    circpad_machine_schedule_padding(mi);
    return 1;
  }

  return 0;
}

int circpad_event_nonpadding_sent(circuit_t *on_circ)
{
  for (int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
       i++) {
    circpad_machine_remove_closest_token(mi);

    circpad_machine_transition(on_circ->padding_info[i],
                               CIRCPAD_TRANSITION_ON_NONPADDING_SENT); 
  }
}

int circpad_event_nonpadding_recieved(circuit_t *on_circ)
{
  for (int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
      i++) {
    circpad_machine_transition(on_circ->padding_info[i],
                             CIRCPAD_TRANSITION_ON_NONPADDING_RECV); 
  }
}

int circpad_event_padding_sent(circuit_t *on_circ)
{
  for (int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
       i++) {
    circpad_machine_transition(on_circ->padding_info[i],
                             CIRCPAD_TRANSITION_ON_PADDING_SENT); 
  }
}

int circpad_event_padding_recieved(circuit_t *on_circ)
{
  for(int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
      i++) {
    circpad_machine_transition(on_circ->padding_info[i],
                              CIRCPAD_TRANSITION_ON_PADDING_RECV); 
  }
}

int circpad_event_infinity(cirpad_machineinfo_t *mi)
{
  circpad_machine_transition(mi, CIRCPAD_TRANSITION_ON_INFINITY);
}

int circpad_event_bins_empty(circpad_machineinfo_t *mi)
{
  if (!circpad_machine_transition(mi, CIRCPAD_TRANSITION_ON_BINS_EMPTY)) {
    circpad_machine_setup_tokens(mi);
  }
}

int circpad_machines_free(circuit_t *circ)
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

circpad_machineinfo_t *circpad_machineinfo_new(int machine_index)
{
  circpad_machineinfo_t *mi = tor_malloc_zero(sizeof(circpad_machineinfo_t));

  mi->machine_index = machine_index;

  return mi;
}

/* Machines for various usecases */
static circpad_machine_t circ_client_machine;
const circpad_machine_t *circpad_circ_client_machine_new()
{
  if (circ_client_machine.is_initialized)
    return &circ_client_machine;

  circ_client_machine.transition_burst_events =
    CIRCPAD_TRANSITION_ON_NONPADDING_RECV;

  circ_client_machine.burst.transition_reschedule_events =
    CIRCPAD_TRANSITION_ON_PADDING_RECV |
    CIRCPAD_TRANSITION_ON_NONPADDING_RECV;

  circ_client_machine.burst.transition_next_events =
      CIRCPAD_TRANSITION_ON_BINS_EMPTY;

  circ_client_machine.burst.next_state =
      CIRCPAD_STATE_END;

  circ_client_machine.burst.remove_tokens = 1;

  // XXX: histograms
}

static circpad_machine_t circ_responder_machine;
const circpad_machine_t *circpad_circ_responder_machine_new()
{
  if (circ_responder_machine.is_initialized)
    return &circ_responder_machine;

  circ_responder_machine.transition_burst_events =
    CIRCPAD_TRANSITION_ON_PADDING_RECV;

  circ_responder_machine.burst.transition_reschedule_events =
    CIRCPAD_TRANSITION_ON_PADDING_RECV;

  circ_client_machine.burst.transition_next_events =
      CIRCPAD_TRANSITION_ON_BINS_EMPTY;

  circ_client_machine.burst.next_state =
      CIRCPAD_STATE_END;

  circ_client_machine.burst.remove_tokens = 1;

  // XXX: Histograms
}

static circpad_machine_t circ_hs_service_intro_machine;
const circpad_machine_t *circpad_hs_service_intro_machine_new();

static circpad_machine_t circ_hs_client_intro_machine;
const circpad_machine_t *circpad_hs_client_intro_machine_new();

static circpad_machine_t circ_wtf_machine;
const circpad_machine_t *circpad_wtf_machine_new();

static circpad_machine_t circ_hs_service_rend_machine;
const circpad_machine_t *circpad_hs_serv_rend_machine_new();

/* Serialization */
// TODO: Should we use keyword=value here? Are there helpers for that?
static void circpad_state_serialize(const circpad_state_t *state,
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

char *circpad_machine_to_string(const circpad_machine_t *machine)
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
const circpad_machine_t *circpad_string_to_machine(const char *string)
{
  
}


