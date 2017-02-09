/* 
 * Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitpadding.h
 * \brief Header file for circuitpadding.c.
 **/
#ifndef TOR_CIRCUITPADDING_H
#define TOR_CIRCUITPADDING_H

#include "circpad_negotiation.h"
#include "handles.h"
#include "timers.h"


struct circuit_t;
typedef struct circuit_t circuit_t;

typedef enum {
  CIRCPAD_STATE_START = 0,
  CIRCPAD_STATE_BURST,
  CIRCPAD_STATE_GAP,
  CIRCPAD_STATE_END
} circpad_statenum_t; 

/**
 * These constants form a bitfield to specify the types of events
 * that can cause transitions between state machine states.
 *
 * Note that SENT and RECV are relative to this endpoint. For
 * relays, SENT means packets destined towards the client and
 * RECV means packets destined towards the relay. On the client,
 * SENT means packets destined towards the relay, where as RECV
 * means packets destined towards the client.
 */
typedef enum {
  CIRCPAD_TRANSITION_ON_NONPADDING_RECV = 1<<0,
  CIRCPAD_TRANSITION_ON_NONPADDING_SENT = 1<<1,
  CIRCPAD_TRANSITION_ON_PADDING_SENT = 1<<2,
  CIRCPAD_TRANSITION_ON_PADDING_RECV = 1<<3,
  CIRCPAD_TRANSITION_ON_INFINITY = 1<<4,
  CIRCPAD_TRANSITION_ON_BINS_EMPTY = 1<<5
} circpad_transition_t;

#define CIRCPAD_DELAY_INFINITE  (UINT32_MAX)

// XXX: 100 bytes is probably pretty close to the
// "malloc overhead makes it not worth it"
#define CIRCPAD_MAX_HISTOGRAM_LEN 50
typedef struct {
  uint8_t histogram_len;
  uint16_t histogram[CIRCPAD_MAX_HISTOGRAM_LEN];
  uint32_t histogram_total;
  uint32_t start_usec;
  uint16_t range_sec;

  /* This is a bitfield that specifies which direction and types
   * of traffic that cause us to abort our scheduled packet and
   * return to waiting for another event from transition_burst_events.
   */ 
  circpad_transition_t transition_prev_events;
  circpad_statenum_t prev_state;

  /* This is a bitfield that specifies which direction and types
   * of traffic that cause us to remain in the current state: Cancel the
   * pending padding packet (if any), and schedule another padding
   * packet from our histogram.
   */
  circpad_transition_t transition_reschedule_events;

  /* This is a bitfield that specifies which direction and types
   * of traffic that cause us to remain in the current state. Cancel the
   * pending padding packet (if any), and then await the next event.
   */
  circpad_transition_t transition_cancel_events;

  /* This is a bitfield that specifies which direction and types
   * of traffic that cause us to transition to the Gap (or burst)
   * state. */
  circpad_transition_t transition_next_events;
  circpad_statenum_t next_state;

  /* If true, estimate the RTT and use that for the histogram base instead of
   * start_usec.
   *
   * XXX: Right now this is only supported for relay-side state machines. 
   */
  uint8_t use_rtt_estimate;

  /* If true, remove tokens from the histogram upon padding and
   * non-padding activity. */
  // XXX: Different removal types? (before, after, lowest, highest?)
  uint8_t remove_tokens;
} circpad_state_t;

/**
 * This structure contains mutable information about a padding
 * machine. The mutable information must be kept separate because
 * it exists per-circuit, where as the machines themselves are global.
 * This separation is done to conserve space in the circuit structure.
 */
typedef struct circpad_machineinfo_t {
  HANDLE_ENTRY(circpad_machineinfo, circpad_machineinfo_t);

  /** The callback pointer for the padding callbacks */
  tor_timer_t *padding_timer;

  /** The circuit for this machine */
  circuit_t *on_circ;

  /* The last time we sent a padding or non-padding packet.
   * Monotonic time in microseconds since system start.
   */
  uint64_t last_sent_packet_time_us;

  /* The last time we got an event relevant to estimating
   * the RTT. Monotonic time in microseconds since system
   * start.
   */
  uint64_t last_rtt_packet_time_us;

  uint32_t rtt_estimate;

  /* A copy of the histogram for the current state. NULL if
   * remove_tokens is false for that state */
  uint16_t *histogram;
  uint8_t histogram_len;

  /** What state is this machine in? */
  circpad_statenum_t current_state;

#define CIRCPAD_MAX_MACHINES    (2)
  /** Which padding machine index was this for.
   * (make sure changes to the bitwidth can support the
   * CIRCPAD_MAX_MACHINES define). */
  uint8_t machine_index : 1;

  /** Is a padding packet scheduled? */
  uint8_t is_padding_scheduled : 1;

} circpad_machineinfo_t;

HANDLE_DECL(circpad_machineinfo, circpad_machineinfo_t,);

#define CIRCPAD_GET_MACHINE(machineinfo) \
    ((machineinfo)->on_circ->padding_machine[(machineinfo)->machine_index])

typedef struct {
  circpad_transition_t transition_burst_events;

  circpad_state_t burst;
  circpad_state_t gap;

  uint8_t is_initialized : 1;
} circpad_machine_t;

typedef enum {
  CIRCPAD_WONTPAD_EVENT = 0, 
  CIRCPAD_WONTPAD_CANCELED, 
  CIRCPAD_NONPADDING_STATE,
  CIRCPAD_WONTPAD_INFINITY,
  CIRCPAD_PADDING_SCHEDULED,
  CIRCPAD_PADDING_SENT
} circpad_decision_t;

void circpad_event_nonpadding_sent(circuit_t *on_circ);
void circpad_event_nonpadding_recieved(circuit_t *on_circ);

void circpad_event_padding_sent(circuit_t *on_circ);
void circpad_event_padding_recieved(circuit_t *on_circ);

void circpad_event_infinity(circpad_machineinfo_t *mi);
void circpad_event_bins_empty(circpad_machineinfo_t *mi);

/* Machines for various usecases */
const circpad_machine_t *circpad_circ_client_machine_new(void);
const circpad_machine_t *circpad_circ_server_machine_new(void);

const circpad_machine_t *circpad_hs_serv_intro_machine_new(void);
const circpad_machine_t *circpad_hs_client_intro_machine_new(void);

const circpad_machine_t *circpad_adaptive_padding_machine_new(void);
const circpad_machine_t *circpad_hs_serv_rend_machine_new(void);

#endif
