/*
 *  Copyright (C) 2014-2015 - Vito Caputo - <vcaputo@gnugeneration.com>
 *
 *  This program is free software: you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License version 3 as published
 *  by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* 12/31/2014: started on an experimental gpg-centric ncurses-based splode chat
 * client
 * There are few better ways to spend new years eve.
 */

#define _GNU_SOURCE
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <ncurses.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <gpgme.h>

#include "list.h"

#ifndef INFTIM
#define INFTIM -1
#endif

#define DECODER_THREADS	20
#define SPLODE_PORT	31337

#define VERSION "0.0.1"

/* raw splode message */
typedef struct _msg_t {
	uint16_t	len;
	uint8_t		bytes[64 * 1024];
} __attribute__ ((__packed__)) msg_t;

typedef struct _times_t {
	time_t			epoch_stamp;
	time_t			start_stamp;
	time_t			end_stamp;
} times_t;

/* received messages are read into .raw then decoded into .decrypted */
typedef struct _decode_t {
	list_head_t		decoded_msgs;
	times_t			times;
	uint64_t		seqnum;

	msg_t			raw;		/* raw message from the wire */

	gpgme_error_t		decrypt_err;	/* errcode of decryption */
	gpgme_decrypt_result_t	decrypt_res;	/* valid if !decrypt_err */
	gpgme_verify_result_t	verify_res;	/* valid if !decrypt_err */
	gpgme_data_t		plain;		/* valid if !decrypt_err */

	gpgme_key_t		*recipient_keys;
	gpgme_key_t		*signature_keys;

	const char		*msg;
	int			msg_len;
} decode_t;

/* entered messages are split into this according to a simple syntax */
typedef struct _parse_t {
	const char		*buf;		/* indexed raw input or NULL*/
	int			buf_len;

	const char		**recipients;
	int			n_recipients;

	const char		**signatures;
	int			n_signatures;
	int			sign:1;

	const char		*msg;
	const char		*cmd;
} parse_t;

/* messages go from .input to .plain then encoded into .encrypted to send() */
typedef struct _encode_t {
	list_head_t		encoded_msgs;
	times_t			times;

	parse_t			input;		/* parsed/indexed input */

	gpgme_data_t		plain;		/* plaintext input message */
	gpgme_key_t		*recipients;	/* array of recipients */
	int			sign;		/* signature desired? */

	gpgme_error_t		encrypt_err;	/* errcode of encryption */
	gpgme_data_t		encrypt_data;	/* usable if !encrypt_err */
	msg_t			encrypted;	/* usable if !encrypt_err */
} encode_t;

/* queues */
#define q_declare(_q)							\
		static LIST_HEAD(_q);					\
		static pthread_mutex_t	_q ## _mutex =			\
					PTHREAD_MUTEX_INITIALIZER;	\
		static pthread_cond_t	_q ## _cond =			\
					PTHREAD_COND_INITIALIZER;	\
		static int		_q ## _depth;

#define q_get(_q, _what_type, _what, _node)				\
		pthread_mutex_lock(&_q ## _mutex);			\
		while(list_empty(&_q)) {				\
			pthread_cond_wait(&_q ## _cond,	&_q ## _mutex);	\
		}							\
		_what = list_entry((&_q)->next, _what_type, _node);	\
		list_del(&_what->_node);				\
		_q ## _depth--;						\
		pthread_mutex_unlock(&_q ## _mutex);

#define q_put(_q, _what, _node)						\
		pthread_mutex_lock(&_q ##_mutex);			\
		list_add_tail(&_what->_node, &_q);			\
		_q ## _depth++;						\
		pthread_mutex_unlock(&_q ## _mutex);			\
		pthread_cond_signal(&_q ## _cond);

#define nelems(_a) (sizeof(_a)/sizeof(_a[0]))

/* some globals */
q_declare(encoded_msgs);
q_declare(received_msgs);
q_declare(decoded_msgs);
q_declare(plain_msgs);

static int		sockfd = -2; /* start sockfd @ -2 to trigger initial connect */
static int		sock_users = 0;
static pthread_cond_t	sock_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t	sock_mutex = PTHREAD_MUTEX_INITIALIZER;
static const char	*splode_addr = NULL;
static int		scry, scrx;


/* basic socket-handling stuff */

/* enter sockfd-using critical section, blocks until sockfd is usable */
static inline void get_sock(void)
{
	pthread_mutex_lock(&sock_mutex);
	while(sockfd == -1)
		pthread_cond_wait(&sock_cond, &sock_mutex);
	sock_users++;
	pthread_mutex_unlock(&sock_mutex);
}

/* leave sockfd-using critical section */
static inline void put_sock(void)
{
	pthread_mutex_lock(&sock_mutex);
	sock_users--;
	pthread_mutex_unlock(&sock_mutex);
	pthread_cond_signal(&sock_cond);
}

/* simple blocking connect to the configured splode address and port */
static int splode_connect(const char *addr)
{
	int			sock;
	struct protoent		*proto;
	struct sockaddr_in	inaddr;

	inaddr.sin_family = AF_INET;
	inaddr.sin_port = htons(SPLODE_PORT);
	inet_aton(addr, (struct in_addr *)&inaddr.sin_addr);

        proto = getprotobyname("tcp");
        if(-1 == (sock = socket(AF_INET, SOCK_STREAM, proto ? proto->p_proto : 0)))
		return -1;

	if(-1 == connect(sock, (struct sockaddr *)&inaddr, sizeof(inaddr))) {
		close(sock);
		return -1;
	}

	return sock;
}

/* repair sockfd in response to a failed recv/send */
static inline void repair_sock(void)
{
	int fd;

	pthread_mutex_lock(&sock_mutex);
	while(sock_users != 1)
		pthread_cond_wait(&sock_cond, &sock_mutex);
	fd = sockfd;
	sockfd = -1;
	pthread_mutex_unlock(&sock_mutex);

	if(fd != -1) {
		/* only one of us gets to repair the socket */
		close(fd);

		/* (re)connect the socket */
		while(-1 == (fd = splode_connect(splode_addr))) {
			/* TODO: UI needs to show something about being connected */
			struct timespec delay = { 0, 500000000 };
			nanosleep(&delay, NULL);
		}

		/* tell everyone it's fixed */
		pthread_mutex_lock(&sock_mutex);
		sockfd = fd;
		pthread_mutex_unlock(&sock_mutex);
		pthread_cond_signal(&sock_cond);
	}
}


/* encode / send messages */

/* allocate an encode message instance */
static encode_t * encode_alloc(void)
{
	return calloc(1, sizeof(encode_t));
}

/* free an encode message instance */
static void encode_free(encode_t *e)
{
	if(e->recipients) {
		int i;
		for(i = 0; e->recipients[i]; i++)
			gpgme_key_unref(e->recipients[i]);
		free(e->recipients);
	}

	if(e->input.buf) {
		free((void *)e->input.buf);
	} else {
		/* if input.buf is NULL,
			input.msg and input.recipients should be freed */
		free((void *)e->input.msg);
		int i;
		for(i = 0; i < e->input.n_recipients; i++)
			free((void *)e->input.recipients[i]);
	}
	gpgme_data_release(e->plain);
	gpgme_data_release(e->encrypt_data);
	free(e);
}

/* send an encoded message */
static void encode_send(encode_t *m)
{
	int len = m->encrypted.len;

	/* just convert the length to network order for the duration of the send */
	m->encrypted.len = htons(m->encrypted.len);

	get_sock();
retry:
	if(send(sockfd, &m->encrypted, len + sizeof(m->encrypted.len), MSG_NOSIGNAL) == -1) {
		repair_sock();
		goto retry;
	}

	put_sock();

	m->encrypted.len = ntohs(len);
}

/* take e->input and produce e->encrypt_data and e->encrypted for xmitter... */
static void encode(gpgme_ctx_t *ctx, encode_t *e)
{
	gpgme_error_t		err;
	int			i;
	gpgme_encrypt_flags_t	flags = (GPGME_ENCRYPT_NO_ENCRYPT_TO |
					 GPGME_ENCRYPT_ALWAYS_TRUST);

	/* XXX TODO: investigate ramifications and necessity of GPGME_ENCRYPT_ALWAYS_TRUST */

	/* go from parsed e->input to the gpgme stuff */
	e->recipients = calloc(e->input.n_recipients + 1, sizeof(*e->recipients));
	for(i = 0; i < e->input.n_recipients; i++) {
		gpgme_get_key(*ctx, e->input.recipients[i],
			      &e->recipients[i], 0);
	}

	if(e->input.msg) {
		gpgme_data_new_from_mem(&e->plain, e->input.msg,
					strlen(e->input.msg), 1);
	} else if(e->input.cmd) {
		char	cmd_buf[256];
		char	*cmd = (char *) &cmd_buf;

		snprintf(cmd,255,"\001%s",e->input.cmd);
		gpgme_data_new_from_mem(&e->plain, cmd, strlen(cmd), 1);
	}
	gpgme_data_new(&e->encrypt_data);

	/* TODO: map the specified signatures to the gpgme context */
	/* XXX: for now it's only honoring signed vs. unsigned,
	 * only supporting the default signing key */
	if(e->input.sign) {
		err = gpgme_op_encrypt_sign(*ctx, e->recipients, flags,
					    e->plain, e->encrypt_data);
	} else {
		err = gpgme_op_encrypt(*ctx, e->recipients, flags,
				       e->plain, e->encrypt_data);
	}

	if(!err) {
		ssize_t	len;

		/* TODO: use gpgme_data_release_and_get_mem() instead of copying
		 * pass the encrypted buffer as encrypted.bytes */
		gpgme_data_seek(e->encrypt_data, 0, SEEK_SET);
		len = gpgme_data_read(e->encrypt_data, e->encrypted.bytes,
				      sizeof(e->encrypted.bytes));
		if(len < 0) {
			err = gpgme_error_from_errno(errno);
		} else {
			e->encrypted.len = len;
		}
	}

	e->encrypt_err = err;
}

/* consume plaintext from UI and encode into messages for xmitter */
static void encoder(void *foo)
{
	gpgme_ctx_t ctx;
	gpgme_new(&ctx);

	for(;;) {
		encode_t *e;

		q_get(plain_msgs, encode_t, e, encoded_msgs);
		encode(&ctx, e);
		q_put(encoded_msgs, e, encoded_msgs);
	}
}

/* consume messages from encoder and send them using simple blocking sends */
static void xmitter(void *foo)
{
	for(;;) {
		encode_t *e;

		q_get(encoded_msgs, encode_t, e, encoded_msgs);
		if(!e->encrypt_err)
			encode_send(e);
		/* TODO: queue back to the UI for status update etc */
		encode_free(e);
	}
}


/* decode / receive messages */

/* allocate a decode message instance */
static decode_t * decode_alloc(void)
{
	return calloc(1, sizeof(decode_t));
}

/* free a decode message instance */
static void decode_free(decode_t *d)
{
	gpgme_recipient_t	rcp;
	gpgme_signature_t	sig;
	int			n;

#define putkeys(_a, _i, _h, _t)					\
	if(_a) {						\
		for(_i = 0, _t = _h; _t; _t = _t->next, _i++)	\
			gpgme_key_unref(_a[_i]);		\
		free(_a);					\
	}
	putkeys(d->recipient_keys, n, d->decrypt_res->recipients, rcp);
	putkeys(d->signature_keys, n, d->verify_res->signatures, sig);

	gpgme_result_unref(d->decrypt_res);
	gpgme_result_unref(d->verify_res);
	gpgme_data_release(d->plain);
	if(d->msg)
		free((void *)d->msg);

	free(d);
}

/* receive a message into m->raw for decoding */
static void decode_recv(decode_t *m)
{
	static uint64_t	seqnum = 1;

	m->seqnum = seqnum++;

	get_sock();

retry_len:
	if(recv(sockfd, &m->raw.len, sizeof(m->raw.len), 0) <= 0) {
		repair_sock();
		goto retry_len;
	}
	m->raw.len = ntohs(m->raw.len);

retry_bytes:
	if(recv(sockfd, &m->raw.bytes, m->raw.len, 0) <= 0) {
		repair_sock();
		goto retry_bytes;
	}
	put_sock();
}

/* consume messages from the network and place on a decoder queue */
static void receiver(void *foo)
{
	for(;;) {
		decode_t *d;

		d = decode_alloc();
		decode_recv(d);
		q_put(received_msgs, d, decoded_msgs);
	}
}

/* decode a message using the provided gpg context */
static void decode(gpgme_ctx_t *ctx, decode_t *d)
{
	gpgme_data_t	cipher;
	gpgme_error_t	err;
	off_t		len;
	char		*out;

        gpgme_data_new_from_mem(&cipher, (const char *)d->raw.bytes,
				d->raw.len, 1);
        gpgme_data_seek(cipher, 0, SEEK_SET);
        gpgme_data_new(&d->plain);

        err = gpgme_op_decrypt_verify(*ctx, cipher, d->plain);
	if(!err) {
		int			i;
		gpgme_recipient_t	rcp;
		gpgme_signature_t	sig;

		d->decrypt_res = gpgme_op_decrypt_result(*ctx);
		gpgme_result_ref(d->decrypt_res);
		d->verify_res = gpgme_op_verify_result(*ctx);
		gpgme_result_ref(d->verify_res);

		len = gpgme_data_seek(d->plain, 0, SEEK_CUR);
		gpgme_data_seek(d->plain, 0, SEEK_SET);

		/* TODO: use gpgme_data_release_and_get_mem() instead of
		 * allocating space for and copying out the decrypted buffer.
		 */
		out = calloc(len, sizeof(char));
		gpgme_data_read(d->plain, out, len);

		d->msg = out;
		d->msg_len = len;

		/* fetch the keys for all recipients and signatures */
#define getkeys(_a, _i, _h, _t, _id)					\
		for(_i = 0, _t = _h; _t; _t = _t->next, _i++);		\
		_a = calloc(_i, sizeof(gpgme_key_t));			\
		for(_i = 0, _t = _h; _t; _t = _t->next, _i++)		\
			gpgme_get_key(*ctx, _t->_id, &_a[_i], 0);

		getkeys(d->recipient_keys, i,
			d->decrypt_res->recipients, rcp, keyid);
		getkeys(d->signature_keys, i,
			d->verify_res->signatures, sig, fpr);
	}
	gpgme_data_release(cipher);

	d->decrypt_err = err;
}

/* get from receiver queue, try decode, put on decoded queue */
static void decoder(int *uipc)
{
	gpgme_ctx_t ctx;
	gpgme_new(&ctx);
        gpgme_set_armor(ctx, 1);

	for(;;) {
		decode_t *d;

		q_get(received_msgs, decode_t, d, decoded_msgs);
		decode(&ctx, d);
		q_put(decoded_msgs, d, decoded_msgs);
		write(*uipc, "", 1);
	}
}

/* helper for growing the signature and recipient arrays */
static int input_append(const char *str, const char ***arr, int *arr_len)
{
	const char **new = realloc(*arr, sizeof(*new) * (*arr_len + 1));
	if(!new)
		return 0;
	new[*arr_len] = str;
	*arr = new;
	(*arr_len)++;
	return 1;
}

static void ctcp_pong(char *keyid, char *arg)
{
	char		msg[255];
	encode_t 	*e = NULL;

	if(!(e = encode_alloc())) {
		return;
	}

	e->input.buf=NULL;
	e->input.sign=1;

	input_append(strdup(keyid),
		&e->input.recipients,
		&e->input.n_recipients);

	if(*arg) {
		snprintf(msg, sizeof(msg), "\001PONG %s", arg);
	} else {
		snprintf(msg, sizeof(msg), "\001PONG");
	}
	e->input.msg=strdup(msg);
	q_put(plain_msgs, e, encoded_msgs);
}

static void ctcp_version(char *keyid)
{
	char		msg[255];
	encode_t 	*e = NULL;

	if(!(e = encode_alloc())) {
		return;
	}

	e->input.buf=NULL;
	e->input.sign=1;

	input_append(strdup(keyid),
		&e->input.recipients,
		&e->input.n_recipients);

	snprintf(msg, sizeof(msg), "\001VERSION %s", VERSION);

	e->input.msg=strdup(msg);
	q_put(plain_msgs, e, encoded_msgs);
}


/* user input stuff */

/* some states for the input parser below */
typedef enum _infsm_t {
	IN_NONE	= 0,
	IN_RECIPIENT,
	IN_SIGNATURE_MAYBE,
	IN_SIGNATURE,
	IN_NIL_SIGNATURE,
	IN_CTCP,
	IN_CTCP_COMMAND,
	IN_MESSAGE
} infsm_t;

/* rudimentary parser for input strings */
/* take str of input, produce structured output in *e or errors in *errmsg */
static int input_parse(const char *str, int len, parse_t *e, const char **errmsg)
{
	/* parse str according to these rules:
	 * one or more @key specifiers, which forms the recipients list
	 * a ! indicating no signature should be included, or just a space.
	 * the message to send
	 * ex: "@fd25ef92! Hi, unsigned message."
	 *     "@fd25ef92$ Hi, signed message using default signature."
	 *     "@fd25ef92$ae13920b Hi, signed message using explicit signature."
	 *     "@aaaaaaaa@bbbbbbbb$ Hi, multiple recipients, signed message"
	 *
	 * Eventually local aliases for gpg key ids will be supported like:
	 *     "@linux$ Hi guys."
	 *     "@ops$ego Hola"
	 *
	 * CTCP Commands:
	 *     "@fd25ef92# VERSION"
	 *     "@fd25ef92# PING 1458456098"
	 *
	 */
	infsm_t	state = IN_NONE;
	int	i;
	char	*istr, c, *this_start;
	int	istr_len, recipients = 0, signatures = 0;

	if(!len || !str) {
		*errmsg = "empty input";
		goto _fail;
	}

	if(!(e->buf = istr = strndup(str, len))) {
		*errmsg = "alloc failure";
		goto _fail;
	}
	e->buf_len = istr_len = strlen(istr);

	for(this_start = istr, state = IN_NONE, i = 0; i < istr_len; i++) {
		c = istr[i];

		switch(state) {
			/* TODO: start with an IN_RECIPIENT_MAYBE to support a
			 * plain message which gets a default added to it? */
		case IN_NONE:
			if(c == ' ')
				continue;
			if(c != '@') {
				*errmsg = "missing leading @";
				goto _fail;
			}
			state = IN_RECIPIENT;
			this_start = &istr[i + 1];
			break;

		case IN_RECIPIENT:
			if(c == '@' || c == '$' || c == '!' || c == '#') {
				if(this_start == &istr[i]) {
					*errmsg = "empty recipient";
					goto _fail;
				}
				recipients++;
				istr[i] = '\0';
				input_append(this_start,
					     &e->recipients,
					     &e->n_recipients);
				if(c == '$') {
					state = IN_SIGNATURE_MAYBE;
					signatures++;
				} else if(c == '!') {
					signatures = -1;
					state = IN_NIL_SIGNATURE;
				} else if(c == '#') {
					state = IN_CTCP;
					signatures++;
				}
				this_start = &istr[i + 1];
			}
			/* TODO: valid recipient characters only */
			break;

		case IN_SIGNATURE_MAYBE:
			if(c == ' ') {
				state = IN_MESSAGE;
				this_start = &istr[i + 1];
				break;
			} /* fall-through to IN_SIGNATURE */

		case IN_SIGNATURE:
			if(c == '$' || c == ' ') {
				istr[i] = '\0';
				input_append(this_start,
					     &e->signatures,
					     &e->n_signatures);
				if(c == ' ')
					state = IN_MESSAGE;
			} else if(c == '!') {
				*errmsg = "signature contradiction";
				goto _fail;
			}
			break;

		case IN_NIL_SIGNATURE:
			if(c != ' ') {
				*errmsg = "space required after ! signature key";
				goto _fail;
			}
			state = IN_MESSAGE;
			this_start = &istr[i + 1];
			break;

		case IN_CTCP:
			if(c != ' ') {
				*errmsg = "space required after # command key";
				goto _fail;
			}
			state = IN_CTCP_COMMAND;
			this_start = &istr[i + 1];
			break;

		case IN_CTCP_COMMAND:
			break;

		case IN_MESSAGE:
			/* TODO: restrict message chars? */
			break;
				
		default:
			break;
		}
	}

	if(state == IN_MESSAGE) {
		e->msg = this_start;
	} else if (state == IN_CTCP_COMMAND) {
		e->msg = NULL;
		e->cmd = this_start;
	}

	if(!signatures) {
		*errmsg = "trailing signature key required (!=unsigned | $=signed | $key=signed using key)";
		goto _fail;
	} else if(signatures > 0) {
		e->sign = 1;
	}

	return 1;

_fail:
	return 0;
}

/* take the input string and return an encode instance */
static encode_t * input_to_encode(const char *str, int len, const char **errmsg)
{
	encode_t *e = NULL;

	if(!(e = encode_alloc())) {
		*errmsg = "allocation failure";
		goto _fail;
	}

	if(!input_parse(str, len, &e->input, errmsg)) {
		goto _fail;
	}

	if(!e->input.n_recipients) {
		*errmsg = "no recipients";
		goto _fail;
	}

	if(!(e->input.msg || e->input.cmd)) {
		*errmsg = "no message or command";
		goto _fail;
	}
	/* TODO: support using cached recipient/signature settings with plain
	 * input which doesn't begin with an @... */
	return e;

_fail:
	encode_free(e);
	return NULL;
}

void handle_ctcp( decode_t *d )
{
	int			i;
	char			arg[129];
	char			ctcp_command[17];
	char			*uid;
	gpgme_ctx_t		ctx;
	gpgme_signature_t	s;
	gpgme_key_t		key;
	gpgme_error_t		err;

	if(!d->verify_res) return;

	if (sscanf(d->msg, "\001%16s", (char *)&ctcp_command) != 1)
		return;

	gpgme_new(&ctx);

	for(i = 0, s = d->verify_res->signatures; s; s = s->next, i++) {

		err = gpgme_op_keylist_start (ctx, s->fpr, 0);
		if (err) continue;
		err = gpgme_op_keylist_next(ctx, &key);
		if (err) continue;
		uid = key->subkeys->keyid;

		/* TODO: verify uid is someone we want to CTCP with */

		if (strncmp((char *)&ctcp_command, "PING",16) == 0) {

			if (sscanf(d->msg, "\001PING %128s", (char *)&arg) != 1) {
				arg[0]='\0';
			}
			ctcp_pong(uid, (char *)&arg);

		} else if (strncmp((char *)&ctcp_command, "VERSION",7) == 0) {

			if (strlen(d->msg) == 8)
				ctcp_version(uid);

		}
	}

	gpgme_release (ctx);

	return;
}

/* show the decoded message */
static void display_decoded(decode_t *d, WINDOW *outwin, WINDOW *statwin)
{
	char			*uid;
	char			*msg;
	gpgme_recipient_t	r;
	gpgme_signature_t	s;
	int			i;
	static int		g;
	static const char	fun[] = {'-','\\','|','/'};

	/* activity animation in status line */
	g++;
	g %= sizeof(fun);

	mvwprintw(statwin, 0, 0, "%c %i/%i/%i/%i", fun[g], received_msgs_depth, encoded_msgs_depth, decoded_msgs_depth, plain_msgs_depth);
	wclrtoeol(statwin);

	/* TODO: for now just throwing the messages into a scrollok ncurses window, no scrollback or anything */
	/* I want scrollback and potentially threaded/filtered views, probably put them into a linked list and perhaps
	 * maintain some indexes, unsure about persistent logging of the decoded stuff, I'm leaning towards persistent
	 * logging of the encoded messages which requires re-decoding with the appropriate keys to access them... */

	if(!d->decrypt_res || !d->msg) {
		if(d->decrypt_err &&
		   gpgme_err_code(d->decrypt_err) != GPG_ERR_NO_DATA &&
		   gpgme_err_code(d->decrypt_err) != GPG_ERR_BAD_DATA &&
		   gpgme_err_code(d->decrypt_err) != GPG_ERR_DECRYPT_FAILED &&
		   gpgme_err_code(d->decrypt_err) != GPG_ERR_INV_DATA) {
			mvwprintw(statwin, 0, 20, "decrypt error: %s (%u)", gpgme_strerror(d->decrypt_err), d->decrypt_err);
			wclrtoeol(statwin);
		}
		/* TODO: display useful error information for non-expected normal noise decode errors */
		return;
	}

	wprintw(outwin, "<");
	if(d->verify_res) {
		for(i = 0, s = d->verify_res->signatures; s; s = s->next, i++) {
			int attrs = 0;

			// color fingerprint according to s->status
			if(d->signature_keys &&
			   d->signature_keys[i] &&
			   d->signature_keys[i]->uids &&
			   d->signature_keys[i]->uids->name) {
				uid = d->signature_keys[i]->uids->name;
			} else {
				uid = s->fpr;
			}

			if((s->summary & GPGME_SIGSUM_GREEN)) {
				attrs = COLOR_PAIR(COLOR_GREEN);
			} else if((s->summary & GPGME_SIGSUM_KEY_MISSING)) {
				attrs = COLOR_PAIR(COLOR_BLUE);
			} else if(!(s->summary & GPGME_SIGSUM_VALID)) {
				attrs = COLOR_PAIR(COLOR_RED);
			}

			if(attrs)
				wattron(outwin, attrs);

			wprintw(outwin, "%s", uid);

			if(attrs)
				wattroff(outwin, attrs);

			if(i)
				wprintw(outwin, "%s", ", ");
		}
	}
	wprintw(outwin, "> ");

	for(i = 0, r = d->decrypt_res->recipients; r; r = r->next, i++) {
		if(d->recipient_keys &&
		   d->recipient_keys[i] &&
		   d->recipient_keys[i]->uids &&
		   d->recipient_keys[i]->uids->name) {
			uid = d->recipient_keys[i]->uids->name;
		} else {
			uid = r->keyid;
		}
		wprintw(outwin, "%s%s", i ? ", " : "", uid);
	}

	if ((int)d->msg[0] == '\001') {
		/* handle ctcp */
		handle_ctcp(d);
		wprintw(outwin, "#(ctcp)");
		msg=(char *)&d->msg[1];
	} else {
		msg=(char *)d->msg;
	}

	wprintw(outwin, ": %s%s", msg, msg[strlen(msg) - 1] == '\n' ? "" : "\n");
	wrefresh(outwin);
}

/* list local gpg keys */
/* this is temporarily just writing to outwin like messages do */
static void list_keys(WINDOW *outwin)
{
	gpgme_ctx_t	ctx;
	gpgme_key_t	key;
	gpgme_error_t	err;

	gpgme_new(&ctx);
	err = gpgme_op_keylist_start (ctx, NULL, 0);
	while(!err) {
		err = gpgme_op_keylist_next(ctx, &key);
		if (err)
			break;
		wprintw (outwin, "%s:", key->subkeys->keyid);
		if (key->uids && key->uids->name)
			wprintw(outwin, " %s", key->uids->name);
		if (key->uids && key->uids->email)
			wprintw(outwin, " <%s>", key->uids->email);
		wprintw(outwin, "\n");
		gpgme_key_release (key);
	}
	gpgme_release (ctx);

	if(gpg_err_code(err) != GPG_ERR_EOF)
		wprintw(outwin, " can not list keys: %s\n", gpgme_strerror (err));
	wrefresh(outwin);
}


int main(int argc, const char *argv[])
{
	int		i;
	struct pollfd	pfds[2] = { {.fd = 0, .events = POLLIN} };
	int		uipc[2];
	pthread_t	decoder_threads[DECODER_THREADS],
			encoder_thread,
			receiver_thread,
			xmitter_thread;
	WINDOW		*outwin, *statwin;
	char		input[255];
	int		input_len = 0, cursor_pos = 0;

	if(argc != 2) {
		fprintf(stderr, "usage: %s addr\n", argv[0]);
		return EXIT_FAILURE;
	}

	splode_addr = argv[1];

	/* setup gpgme */
	gpgme_check_version(NULL);

	/* setup ncurses */
	initscr();
	keypad(stdscr, TRUE);
	nonl();
	cbreak();
	noecho();
	nodelay(stdscr, TRUE);
	atexit((void(*)(void))endwin); /* cleanup ncurses at exit */

	if(has_colors()) {
		start_color();
		init_pair(COLOR_BLACK, COLOR_BLACK, COLOR_BLACK);
		init_pair(COLOR_GREEN, COLOR_GREEN, COLOR_BLACK);
		init_pair(COLOR_RED, COLOR_RED, COLOR_BLACK);
		init_pair(COLOR_CYAN, COLOR_CYAN, COLOR_BLACK);
		init_pair(COLOR_WHITE, COLOR_WHITE, COLOR_BLACK);
		init_pair(COLOR_MAGENTA, COLOR_MAGENTA, COLOR_BLACK);
		init_pair(COLOR_BLUE, COLOR_BLUE, COLOR_BLACK);
		init_pair(COLOR_YELLOW, COLOR_YELLOW, COLOR_BLACK);
	}

	clrtobot();
	getmaxyx(stdscr, scry, scrx);

	outwin = newwin(scry - 1, scrx, 0, 0);
	wclrtobot(outwin);
	idlok(outwin, true);
	scrollok(outwin, true); // XXX TODO just for now, while there's no history

	statwin = newwin(1, scrx, scry - 2, 0);
	wbkgdset(statwin, A_REVERSE);
	scrollok(statwin, false);
	refresh();

	/* setup a simple pipe for waking up the UI when there's new messages to show */
	pipe(uipc);
	pfds[1].fd = uipc[0];
	pfds[1].events = POLLIN;

	/* create the various threads */
	for(i = 0; i < nelems(decoder_threads); i++) {
		pthread_create(&decoder_threads[i], NULL, (void *(*)(void *))decoder, (void *)&uipc[1]);

	}
	pthread_create(&encoder_thread, NULL, (void *(*)(void *))encoder, NULL);
	pthread_create(&receiver_thread, NULL, (void *(*)(void *))receiver, NULL);
	pthread_create(&xmitter_thread, NULL, (void *(*)(void *))xmitter, NULL);

	/* wait for user and/or decoder input */
	do {
		if(pfds[0].revents & POLLIN) {
			int key;

			/* handle user input */
			while((key = getch()) != ERR) {
				/* input[] stores the currently composed message, and implemented here is a very rudimentary line editor */
				switch(key) {
				case KEY_UP:
					/* forward through input history */
					/* TODO */
					break;

				case KEY_DOWN:
					/* back through input history */
					/* TODO */
					break;

				case KEY_LEFT:
					/* cursor left in input */
					if(cursor_pos)
						cursor_pos--;
					break;

				case KEY_RIGHT:
					/* cursor right in input */
					if(cursor_pos < input_len)
						cursor_pos++;
					break;

				case '\t':
					/* autocomplete key */
					/* cause a list of keys in my keyring to
					 * display and give me a way to select
					 * interactively from the list */
					/* TODO */
					list_keys(outwin);
					break;

				case '\r':
				case '\n':
				case KEY_ENTER:
					if(input_len) {
						encode_t	*e;
						const char	*errmsg;
						if(!(e = input_to_encode(input, input_len, &errmsg))) {
							mvwprintw(statwin, 0, 20, "Input error: %s\n", errmsg);
							wclrtoeol(statwin);
							break;
						}
						move(scry - 1, 0);
						clrtoeol();

						q_put(plain_msgs, e, encoded_msgs);
						/* TODO: indicate the recipient and identity in the print */
						/* TODO: useful to show/update an encoding & xmitted status real-time? */
						/* TODO: use e->in_recipients etc for coloring
						 * */
						wprintw(outwin, "%.*s\n", input_len, input);
						wrefresh(outwin);
						input_len = cursor_pos = 0;
					}
					break;

				case 0x4: /* EOF/EOT/^D */
					goto _exit;

				case 0x15: /* NAK/^U */
					cursor_pos = input_len = 0;
					break;

				case KEY_BACKSPACE:
				case '\b':
					/* delete char behind cursor */
					if(cursor_pos) {
						memmove(&input[cursor_pos - 1], &input[cursor_pos], input_len - cursor_pos);
						cursor_pos--;
						input_len--;
					}
					break;

				case KEY_PPAGE:
					/* pageup, message buffer history */
					/* TODO */
					break;

				case KEY_NPAGE:
					/* pagedwn, message buffer history */
					/* TODO */
					break;

				default:
					input[cursor_pos] = key;
					if(cursor_pos + 1 < sizeof(input))
						cursor_pos++;
					if(cursor_pos > input_len)
						input_len = cursor_pos;
					break;
				}
				mvwprintw(stdscr, scry - 1, 0, "%.*s", input_len, input);
				wclrtoeol(stdscr);
			}
		}

		/* decoded messages */
		if(pfds[1].revents & POLLIN) {
			static uint64_t	last_seqnum;		/* seqnum of last _displayed_ message */
			static 		LIST_HEAD(ooo_msgs);	/* place to collect potentially out-of-order messages until they are in-order */
			decode_t	*d, *pos, *_pos;
			char		c;

			read(uipc[0], &c, 1);
			q_get(decoded_msgs, decode_t, d, decoded_msgs);

			/* insert the decoded (or errored) msg in-order on ooo_msgs according to seqnum */
			if(list_empty(&ooo_msgs)) {
				list_add(&d->decoded_msgs, &ooo_msgs);
			} else {
				list_for_each_entry(pos, &ooo_msgs, decoded_msgs) {
					if(d->seqnum < pos->seqnum)
						break;
				}
				list_add_tail(&d->decoded_msgs, &pos->decoded_msgs);
			}

			/* consume the from ooo_msgs until a gap is found */
			list_for_each_entry_safe(pos, _pos, &ooo_msgs, decoded_msgs) {
				if(pos->seqnum <= (last_seqnum + 1)) {
					last_seqnum = pos->seqnum;
					list_del(&pos->decoded_msgs);
					display_decoded(pos, outwin, statwin);
					decode_free(pos);
				} else {
					break;
				}
			}
		}

		move(scry - 1, cursor_pos);
		wrefresh(statwin);
		refresh();
	} while(poll(pfds, nelems(pfds), INFTIM) != -1);

_exit:
	return EXIT_SUCCESS;
}
