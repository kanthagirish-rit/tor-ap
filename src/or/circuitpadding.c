/* Copyright (c) 2017 The Tor Project, Inc. */
/* See LICENSE for licensing information */

HANDLE_IMPL(circpad_machineinfo, circpad_machineinfo_t,);

/* Histogram helpers */
inline static uint32_t circpad_histogram_bin_ms(circpad_state_t *state,
                                                int bin)
{
  if (bin == 0)
    return state->start_usec;

  return state->start_usec
      + state->max_sec*USEC_PER_SEC/(1<<(state->histogram_len-bin));
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

static void circpad_machine_fill_tokens(circpad_machineinfo_t *mi)
{
  circpad_state_t *state = circpad_machine_current_state(mi);

  if (!state->remove_tokens) {
    if (mi->histogram) {
      tor_free(mi->histogram);
      mi->histogram = NULL;
      mi->histogram_len = 0;
    }
    return;
  }

  if (!mi->histogram) {
    mi->histogram = tor_malloc_zero(sizeof(uint16_t)*state->histogram_len);
    mi->histogram_len = state->histogram_len;
  }

  tor_assert(state->histogram_len == mi->histogram_len);
  memcpy(mi->histogram, state->histogram, sizeof(uint16_t)*state->histogram_len);
}

// TODO: support token removal and the empty event..
inline static uint32_t circpad_machine_sample_delay(circpad_machineinfo_t *mi)
{
  circpad_state_t *state = circpad_machine_current_state(mi);
  int i = 0;
  tor_assert(state);
  const uint16_t *histogram = NULL;

  uint32_t curr_weight;
  uint32_t histogram_total = 0;
  uint32_t bin_choice; 
  uint16_t bin_start, bin_end;

  if (state->remove_tokens) {
    tor_assert(mi->histogram && mi->histogram_len == state->histogram_len);

    histogram = mi->histogram;
    for (int i = 0; i < state->histogram_len; i++)
      histogram_total += histogram[i];
  } else {
    histogram = state->histogram;
    histogram_total = state->histogram_total;
  }

  bin_choice = crypto_rand_int(histogram_total);
  curr_weight = state->histogram[0];

  while (curr_weight < bin_choice) {
    curr_weight += histogram[i];
    i++;
  }

  if (i == state->histogram_len-1)
    return CIRCPAD_DELAY_INFINITE; // Infinity: Don't send a padding packet

  tor_assert(i < state->histogram_len - 1);

  // XXX: verify this is right (including i=0)
  bin_start = circpad_histogram_bin_ms(state, i);
  bin_end = circpad_histogram_bin_ms(state, i+1);

  // Sample uniformly between a[i] and b[i]
  send_padding_packet_at = bin_start + crypto_rand_int(bin_end - bin_start);
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
  crypt_path_t *last = cpath->prev;

  while(iter != last) {
    next = iter->next;
    tor_free(iter);
    iter = next;
  }
}

int circpad_send_padding_cell_for_callback(circpad_machineinfo_t *mi)
{
  mi->is_padding_scheduled = 0;
 
  // XXX: check circuit marks (marked for close, marked unusable, etc)

  if (CIRCUIT_IS_ORIGIN(mi->on_circ)) {
    crypt_path_t *new_cpath;

    // Check that we have at least a 2 hop circuit
    if (circuit_get_cpath_len(TO_ORIGIN_CIRC(mi->on_circ)) < 2) {
      // XXX: tor_log
      return;
    }

    /* Prepare a cpath to get us to the middle hop */
    cpath = cpath_clone_shallow(TO_ORIGIN_CIRC(mi->on_circ)->cpath, 2);

    // Ensure that both hops are open
    if (new_cpath->state != CPATH_STATE_OPEN ||
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
    circpad_send_padding_cell_for_callback(mi);
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
  tor_assert(mi);
  tor_assert(mi->current_state != CIRCPAD_STATE_START);
  tor_assert(!mi->is_padding_scheduled);

  // TODO: Remove token for this interval since the last time..

  in_us = circpad_machine_sample_delay(mi);

  if (in_us <= 0) {
    mi->is_padding_scheduled = 1;
    circpad_send_padding_cell_for_callback(on_circ);
    // XXX: decision enum?
    return CIRCPAD_PADDING_SENT;
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

      circpad_machine_fill_tokens(mi);
  
      circpad_machine_schedule_padding(mi);
      return 1;
    }
    return 0;
  }

  if (state->transition_prev_events & event) {
    mi->current_state = state->prev_state;

    /* Cancel current timer (if any) */
    timer_disable(mi->padding_timer);
    mi->is_padding_scheduled = 0;

    circpad_machine_fill_tokens(mi);

    circpad_machine_schedule_padding(mi);
    return 1;
  }

  if (state->transition_reschedule_events & event) {
    /* Stay in this state, but cancel current timer (if any) */
    timer_disable(mi->padding_timer);
    mi->is_padding_scheduled = 0;

    circpad_machine_schedule_padding(mi);
    return 1;
  }
 
  if (state->transition_next_events & event) {
    mi->current_state = state->next_state;
    
    /* Cancel current timer (if any) */
    timer_disable(mi->padding_timer);
    mi->is_padding_scheduled = 0;
    
    circpad_machine_fill_tokens(mi);
    
    circpad_machine_schedule_padding(mi);
    return 1;
  }

  return 0;
}

int circpad_event_nonpadding_sent(circuit_t *on_circ)
{
  for(int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
      i++) {
    circpad_machine_transition(on_circ->padding_info[i],
                               CIRCPAD_TRANSITION_ON_NONPADDING_SENT); 
  }
}

int circpad_event_nonpadding_recieved(circuit_t *on_circ)
{
  for(int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
      i++) {
    circpad_machine_transition(on_circ->padding_info[i],
                             CIRCPAD_TRANSITION_ON_NONPADDING_RECV); 
  }
}

int circpad_event_padding_sent(circuit_t *on_circ)
{
  for(int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
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

int circpad_event_infinity(circuit_t *on_circ)
{
  for(int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
      i++) {
    circpad_machine_transition(on_circ->padding_info[i],
                               CIRCPAD_TRANSITION_ON_INFINITY);
  }
}

// TODO: This event is never emitted/called (because we don't remove tokens yet)
int circpad_event_bins_empty(circuit_t *on_circ)
{
  for (int i = 0; i < CIRCPAD_MAX_MACHINES && on_circ->padding_info[i];
       i++) {
    if (!circpad_machine_transition(on_circ->padding_info[i],
                               CIRCPAD_TRANSITION_ON_BINS_EMPTY)) {
      circpad_machine_fill_tokens(on_circ->padding_info[i]);
    }
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

/* Serialization: TODO Writeme */
char *circpad_machine_to_string(const circpad_machine_t *machine);
const circpad_machine_t *circpad_string_to_machine(const char *string);


