/* openpkcs11 fork from libp11, a simple layer on to of PKCS#11 API
 * Copyright (C) 2005 Olaf Kirch <okir@lst.de>
 * Copyright (C) 2015-2018 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Copyright (C) 2019 Antonio Iacono <antiac@gmail.com>
 * Portions Copyright (c) 2001 Markus Friedl
 * Portions Copyright (c) 2002 Juha Yrjölä
 * Portions Copyright (c) 2003 Kevin Stefanik
 * Portions Copyright (C) 2011-2016 Douglas E. Engert <deengert@gmail.com>
 * Portions Copyright 1999-2001 The OpenSSL Project Authors. All Rights Reserved.
 * Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 * Portions Copyright (c) 2003 Kevin Stefanik (kstef@mtppi.org)
 * Copied/modified by Kevin Stefanik (kstef@mtppi.org) for the OpenSC
 * project 2003.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <string.h>
#include <stdio.h>
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif
#ifndef OPENSSL_NO_ECDSA
#include <openssl/ecdsa.h>
#endif
#ifndef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif
#include <assert.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#endif
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ui.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#ifndef ENGINE_CMD_BASE
#error did not get engine.h
#endif
#include "openpkcs11.h"


static int pkcs11_init_slot(PKCS11_CTX *, PKCS11_SLOT *, CK_SLOT_ID);
static void pkcs11_release_slot(PKCS11_CTX *, PKCS11_SLOT *);
static int pkcs11_check_token(PKCS11_CTX *, PKCS11_SLOT *);
static void pkcs11_destroy_token(PKCS11_TOKEN *);

/*
 * Get slotid from private
 */
unsigned long pkcs11_get_slotid_from_slot(PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);

	return spriv->id;
}

/*
 * Enumerate slots
 */
int pkcs11_enumerate_slots(PKCS11_CTX *ctx, PKCS11_SLOT **slotp,
		unsigned int *countp)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	CK_SLOT_ID *slotid;
	CK_ULONG nslots, n;
	PKCS11_SLOT *slots;
	size_t alloc_size;
	int rv;

	rv = cpriv->method->C_GetSlotList(FALSE, NULL_PTR, &nslots);
	CRYPTOKI_checkerr(CKR_F_PKCS11_ENUMERATE_SLOTS, rv);

	alloc_size = nslots * sizeof(CK_SLOT_ID);
	if (alloc_size / sizeof(CK_SLOT_ID) != nslots) /* integer overflow */
		return -1;
	slotid = OPENSSL_malloc(alloc_size);
	if (slotid == NULL)
		return -1;

	rv = cpriv->method->C_GetSlotList(FALSE, slotid, &nslots);
	CRYPTOKI_checkerr(CKR_F_PKCS11_ENUMERATE_SLOTS, rv);

	alloc_size = nslots * sizeof(PKCS11_SLOT);
	if (alloc_size / sizeof(PKCS11_SLOT) != nslots) /* integer overflow */
		return -1;
	slots = OPENSSL_malloc(alloc_size);
	if (slots == NULL)
		return -1;
	memset(slots, 0, nslots * sizeof(PKCS11_SLOT));
	for (n = 0; n < nslots; n++) {
		if (pkcs11_init_slot(ctx, &slots[n], slotid[n])) {
			while (n--)
				pkcs11_release_slot(ctx, slots + n);
			OPENSSL_free(slotid);
			OPENSSL_free(slots);
			return -1;
		}
	}

	if (slotp)
		*slotp = slots;
	else
		OPENSSL_free(slots);
	if (countp)
		*countp = nslots;
	OPENSSL_free(slotid);
	return 0;
}

/*
 * Find a slot with a token that looks "valuable"
 */
PKCS11_SLOT *pkcs11_find_token(PKCS11_CTX *ctx, PKCS11_SLOT *slots,
		unsigned int nslots)
{
	PKCS11_SLOT *slot, *best;
	PKCS11_TOKEN *tok;
	unsigned int n;

	(void)ctx;

	if (slots == NULL)
		return NULL;

	best = NULL;
	for (n = 0, slot = slots; n < nslots; n++, slot++) {
		if ((tok = slot->token) != NULL) {
			if (best == NULL ||
					(tok->initialized > best->token->initialized &&
					tok->userPinSet > best->token->userPinSet &&
					tok->loginRequired > best->token->loginRequired))
				best = slot;
		}
	}
	return best;
}

/*
 * Find the next slot with a token that looks "valuable"
 */
PKCS11_SLOT *pkcs11_find_next_token(PKCS11_CTX *ctx, PKCS11_SLOT *slots,
		unsigned int nslots, PKCS11_SLOT *current)
{
	int offset;

	if (slots == NULL)
		return NULL;

	if (current) {
		offset = current + 1 - slots;
		if (offset < 1 || (unsigned int)offset >= nslots)
			return NULL;
	} else {
		offset = 0;
	}

	return pkcs11_find_token(ctx, slots + offset, nslots - offset);
}

/*
 * Open a session with this slot
 */
int pkcs11_open_session(PKCS11_SLOT *slot, int rw, int relogin)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	int rv;

	if (relogin == 0) {
		if (spriv->haveSession) {
			CRYPTOKI_call(ctx, C_CloseSession(spriv->session));
			spriv->haveSession = 0;
		}
	}
	rv = CRYPTOKI_call(ctx,
		C_OpenSession(spriv->id,
			CKF_SERIAL_SESSION | (rw ? CKF_RW_SESSION : 0),
			NULL, NULL, &spriv->session));
	CRYPTOKI_checkerr(CKR_F_PKCS11_OPEN_SESSION, rv);
	spriv->haveSession = 1;
	spriv->prev_rw = rw;

	return 0;
}

int pkcs11_reopen_session(PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	int rv;

	rv = CRYPTOKI_call(ctx,
		C_OpenSession(spriv->id,
			CKF_SERIAL_SESSION | (spriv->prev_rw ? CKF_RW_SESSION : 0),
			NULL, NULL, &spriv->session));
	CRYPTOKI_checkerr(CKR_F_PKCS11_REOPEN_SESSION, rv);
	spriv->haveSession = 1;

	return 0;
}

/*
 * Determines if user is authenticated with token
 */
int pkcs11_is_logged_in(PKCS11_SLOT *slot, int so, int *res)
{
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_SESSION_INFO session_info;
	int rv;

	if (spriv->loggedIn) {
		*res = 1;
		return 0;
	}
	if (!spriv->haveSession) {
		/* SO gets a r/w session by default,
		 * user gets a r/o session by default. */
		if (PKCS11_open_session(slot, so))
			return -1;
	}

	rv = CRYPTOKI_call(ctx, C_GetSessionInfo(spriv->session, &session_info));
	CRYPTOKI_checkerr(CKR_F_PKCS11_IS_LOGGED_IN, rv);
	if (so) {
		*res = session_info.state == CKS_RW_SO_FUNCTIONS;
	} else {
		*res = session_info.state == CKS_RO_USER_FUNCTIONS ||
			session_info.state == CKS_RW_USER_FUNCTIONS;
	}
	return 0;
}

/*
 * Authenticate with the card. relogin should be set if we automatically
 * relogin after a fork.
 */
int pkcs11_login(PKCS11_SLOT *slot, int so, const char *pin, int relogin)
{
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	int rv;

	if (!relogin && spriv->loggedIn)
		return 0; /* Nothing to do */

	if (!spriv->haveSession) {
		/* SO gets a r/w session by default,
		 * user gets a r/o session by default. */
		if (pkcs11_open_session(slot, so, relogin))
			return -1;
	}

	rv = CRYPTOKI_call(ctx,
		C_Login(spriv->session, so ? CKU_SO : CKU_USER,
			(CK_UTF8CHAR *) pin, pin ? (unsigned long) strlen(pin) : 0));
	if (rv && rv != CKR_USER_ALREADY_LOGGED_IN) /* logged in -> OK */
		CRYPTOKI_checkerr(CKR_F_PKCS11_LOGIN, rv);
	spriv->loggedIn = 1;

	if (spriv->prev_pin != pin) {
		if (spriv->prev_pin) {
			OPENSSL_cleanse(spriv->prev_pin, strlen(spriv->prev_pin));
			OPENSSL_free(spriv->prev_pin);
		}
		spriv->prev_pin = OPENSSL_strdup(pin);
	}
	spriv->prev_so = so;
	return 0;
}

/*
 * Authenticate with the card
 */
int pkcs11_relogin(PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);

	return pkcs11_login(slot, spriv->prev_so, spriv->prev_pin, 1);
}

/*
 * Log out
 */
int pkcs11_logout(PKCS11_SLOT *slot)
{
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	int rv;

	/* Calling PKCS11_logout invalidates all cached
	 * keys we have */
	if (slot->token) {
		pkcs11_destroy_keys(slot->token, CKO_PRIVATE_KEY);
		pkcs11_destroy_keys(slot->token, CKO_PUBLIC_KEY);
		pkcs11_destroy_certs(slot->token);
	}
	if (!spriv->haveSession) {
		P11err(P11_F_PKCS11_LOGOUT, P11_R_NO_SESSION);
		return -1;
	}

	rv = CRYPTOKI_call(ctx, C_Logout(spriv->session));
	CRYPTOKI_checkerr(CKR_F_PKCS11_LOGOUT, rv);
	spriv->loggedIn = 0;
	return 0;
}

/*
 * Initialize the token
 */
int pkcs11_init_token(PKCS11_TOKEN *token, const char *pin, const char *label)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	int rv;

	if (label == NULL)
		label = "PKCS#11 Token";
	rv = CRYPTOKI_call(ctx,
		C_InitToken(spriv->id,
			(CK_UTF8CHAR *) pin, (unsigned long) strlen(pin),
			(CK_UTF8CHAR *) label));
	CRYPTOKI_checkerr(CKR_F_PKCS11_INIT_TOKEN, rv);

	/* FIXME: how to update the token?
	 * PKCS11_CTX_private *cpriv;
	 * int n;
	 * cpriv = PRIVCTX(ctx);
	 * for (n = 0; n < cpriv->nslots; n++) {
	 * 	if (pkcs11_check_token(ctx, cpriv->slots + n) < 0)
	 * 		return -1;
	 * }
	 */

	return 0;
}

/*
 * Set the User PIN
 */
int pkcs11_init_pin(PKCS11_TOKEN *token, const char *pin)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	int len, rv;

	if (!spriv->haveSession) {
		P11err(P11_F_PKCS11_INIT_PIN, P11_R_NO_SESSION);
		return -1;
	}

	len = pin ? (int) strlen(pin) : 0;
	rv = CRYPTOKI_call(ctx, C_InitPIN(spriv->session, (CK_UTF8CHAR *) pin, len));
	CRYPTOKI_checkerr(CKR_F_PKCS11_INIT_PIN, rv);

	return pkcs11_check_token(ctx, TOKEN2SLOT(token));
}

/*
 * Change the User PIN
 */
int pkcs11_change_pin(PKCS11_SLOT *slot, const char *old_pin,
		const char *new_pin)
{
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	int old_len, new_len, rv;

	if (!spriv->haveSession) {
		P11err(P11_F_PKCS11_CHANGE_PIN, P11_R_NO_SESSION);
		return -1;
	}

	old_len = old_pin ? (int) strlen(old_pin) : 0;
	new_len = new_pin ? (int) strlen(new_pin) : 0;
	rv = CRYPTOKI_call(ctx,
		C_SetPIN(spriv->session, (CK_UTF8CHAR *) old_pin, old_len,
			(CK_UTF8CHAR *) new_pin, new_len));
	CRYPTOKI_checkerr(CKR_F_PKCS11_CHANGE_PIN, rv);

	return pkcs11_check_token(ctx, slot);
}

/*
 * Seed the random number generator
 */
int pkcs11_seed_random(PKCS11_SLOT *slot, const unsigned char *s,
		unsigned int s_len)
{
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	int rv;

	if (!spriv->haveSession && PKCS11_open_session(slot, 0)) {
		P11err(P11_F_PKCS11_SEED_RANDOM, P11_R_NO_SESSION);
		return -1;
	}

	rv = CRYPTOKI_call(ctx,
		C_SeedRandom(spriv->session, (CK_BYTE_PTR) s, s_len));
	CRYPTOKI_checkerr(CKR_F_PKCS11_SEED_RANDOM, rv);

	return pkcs11_check_token(ctx, slot);
}

/*
 * Generate random numbers
 */
int pkcs11_generate_random(PKCS11_SLOT *slot, unsigned char *r,
		unsigned int r_len)
{
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	int rv;

	if (!spriv->haveSession && PKCS11_open_session(slot, 0)) {
		P11err(P11_F_PKCS11_GENERATE_RANDOM, P11_R_NO_SESSION);
		return -1;
	}

	rv = CRYPTOKI_call(ctx,
		C_GenerateRandom(spriv->session, (CK_BYTE_PTR) r, r_len));
	CRYPTOKI_checkerr(CKR_F_PKCS11_GENERATE_RANDOM, rv);

	return pkcs11_check_token(ctx, slot);
}

/*
 * Helper functions
 */
static int pkcs11_init_slot(PKCS11_CTX *ctx, PKCS11_SLOT *slot, CK_SLOT_ID id)
{
	PKCS11_SLOT_private *spriv;
	CK_SLOT_INFO info;
	int rv;

	rv = CRYPTOKI_call(ctx, C_GetSlotInfo(id, &info));
	CRYPTOKI_checkerr(CKR_F_PKCS11_INIT_SLOT, rv);

	spriv = OPENSSL_malloc(sizeof(PKCS11_SLOT_private));
	if (spriv == NULL)
		return -1;
	memset(spriv, 0, sizeof(PKCS11_SLOT_private));

	spriv->parent = ctx;
	spriv->id = id;
	spriv->forkid = PRIVCTX(ctx)->forkid;
	spriv->prev_rw = 0;
	spriv->prev_pin = NULL;
	spriv->prev_so = 0;

	slot->description = PKCS11_DUP(info.slotDescription);
	slot->manufacturer = PKCS11_DUP(info.manufacturerID);
	slot->removable = (info.flags & CKF_REMOVABLE_DEVICE) ? 1 : 0;
	slot->_private = spriv;

	if ((info.flags & CKF_TOKEN_PRESENT) && pkcs11_check_token(ctx, slot))
		return -1;

	return 0;
}

void pkcs11_release_all_slots(PKCS11_CTX *ctx,  PKCS11_SLOT *slots,
		unsigned int nslots)
{
	unsigned int i;

	for (i=0; i < nslots; i++)
		pkcs11_release_slot(ctx, &slots[i]);
	OPENSSL_free(slots);
}

static void pkcs11_release_slot(PKCS11_CTX *ctx, PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);

	if (spriv) {
		if (spriv->prev_pin) {
			OPENSSL_cleanse(spriv->prev_pin, strlen(spriv->prev_pin));
			OPENSSL_free(spriv->prev_pin);
		}
		CRYPTOKI_call(ctx, C_CloseAllSessions(spriv->id));
	}
	OPENSSL_free(slot->_private);
	OPENSSL_free(slot->description);
	OPENSSL_free(slot->manufacturer);
	if (slot->token) {
		pkcs11_destroy_token(slot->token);
		OPENSSL_free(slot->token);
	}

	memset(slot, 0, sizeof(*slot));
}

static int pkcs11_check_token(PKCS11_CTX *ctx, PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_TOKEN_private *tpriv;
	CK_TOKEN_INFO info;
	int rv;

	if (slot->token) {
		pkcs11_destroy_token(slot->token);
	} else {
		slot->token = OPENSSL_malloc(sizeof(PKCS11_TOKEN));
		if (slot->token == NULL)
			return -1;
		memset(slot->token, 0, sizeof(PKCS11_TOKEN));
	}

	rv = CRYPTOKI_call(ctx, C_GetTokenInfo(spriv->id, &info));
	if (rv == CKR_TOKEN_NOT_PRESENT || rv == CKR_TOKEN_NOT_RECOGNIZED) {
		OPENSSL_free(slot->token);
		slot->token = NULL;
		return 0;
	}
	CRYPTOKI_checkerr(CKR_F_PKCS11_CHECK_TOKEN, rv);

	/* We have a token */
	tpriv = OPENSSL_malloc(sizeof(PKCS11_TOKEN_private));
	if (tpriv == NULL)
		return -1;
	memset(tpriv, 0, sizeof(PKCS11_TOKEN_private));
	tpriv->parent = slot;
	tpriv->prv.keys = NULL;
	tpriv->prv.num = 0;
	tpriv->pub.keys = NULL;
	tpriv->pub.num = 0;
	tpriv->ncerts = 0;

	slot->token->label = PKCS11_DUP(info.label);
	slot->token->manufacturer = PKCS11_DUP(info.manufacturerID);
	slot->token->model = PKCS11_DUP(info.model);
	slot->token->serialnr = PKCS11_DUP(info.serialNumber);
	slot->token->initialized = (info.flags & CKF_TOKEN_INITIALIZED) ? 1 : 0;
	slot->token->loginRequired = (info.flags & CKF_LOGIN_REQUIRED) ? 1 : 0;
	slot->token->secureLogin = (info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ? 1 : 0;
	slot->token->userPinSet = (info.flags & CKF_USER_PIN_INITIALIZED) ? 1 : 0;
	slot->token->readOnly = (info.flags & CKF_WRITE_PROTECTED) ? 1 : 0;
	slot->token->hasRng = (info.flags & CKF_RNG) ? 1 : 0;
	slot->token->userPinCountLow = (info.flags & CKF_USER_PIN_COUNT_LOW) ? 1 : 0;
	slot->token->userPinFinalTry = (info.flags & CKF_USER_PIN_FINAL_TRY) ? 1 : 0;
	slot->token->userPinLocked = (info.flags & CKF_USER_PIN_LOCKED) ? 1 : 0;
	slot->token->userPinToBeChanged = (info.flags & CKF_USER_PIN_TO_BE_CHANGED) ? 1 : 0;
	slot->token->soPinCountLow = (info.flags & CKF_SO_PIN_COUNT_LOW) ? 1 : 0;
	slot->token->soPinFinalTry = (info.flags & CKF_SO_PIN_FINAL_TRY) ? 1 : 0;
	slot->token->soPinLocked = (info.flags & CKF_SO_PIN_LOCKED) ? 1 : 0;
	slot->token->soPinToBeChanged = (info.flags & CKF_SO_PIN_TO_BE_CHANGED) ? 1 : 0;
	slot->token->_private = tpriv;

	return 0;
}

static void pkcs11_destroy_token(PKCS11_TOKEN *token)
{
	pkcs11_destroy_keys(token, CKO_PRIVATE_KEY);
	pkcs11_destroy_keys(token, CKO_PUBLIC_KEY);
	pkcs11_destroy_certs(token);

	OPENSSL_free(token->label);
	OPENSSL_free(token->manufacturer);
	OPENSSL_free(token->model);
	OPENSSL_free(token->serialnr);
	OPENSSL_free(token->_private);
	memset(token, 0, sizeof(*token));
}

/*
 * This file implements the handling of RSA keys stored on a
 * PKCS11 token
 */

static int rsa_ex_index = 0;

static RSA *pkcs11_rsa(PKCS11_KEY *key)
{
	EVP_PKEY *evp_key = pkcs11_get_key(key, key->isPrivate);
	RSA *rsa;
	if (evp_key == NULL)
		return NULL;
	rsa = EVP_PKEY_get0_RSA(evp_key);
	EVP_PKEY_free(evp_key);
	return rsa;
}

/* PKCS#1 v1.5 RSA signature */
/* TODO: remove this function in libp11 0.5.0 */
int pkcs11_sign(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, PKCS11_KEY *key)
{
	RSA *rsa = pkcs11_rsa(key);
	if (rsa == NULL)
		return -1;
	return RSA_sign(type, m, m_len, sigret, siglen, rsa);
}

/* Setup PKCS#11 mechanisms for encryption/decryption */
static int pkcs11_mechanism(CK_MECHANISM *mechanism, const int padding)
{
	memset(mechanism, 0, sizeof(CK_MECHANISM));
	switch (padding) {
	case RSA_PKCS1_PADDING:
		 mechanism->mechanism = CKM_RSA_PKCS;
		 break;
	case RSA_NO_PADDING:
		mechanism->mechanism = CKM_RSA_X_509;
		break;
	case RSA_X931_PADDING:
		mechanism->mechanism = CKM_RSA_X9_31;
		break;
	default:
		P11err(P11_F_PKCS11_MECHANISM, P11_R_UNSUPPORTED_PADDING_TYPE);
		return -1;
	}
	return 0;
}

/* RSA private key encryption (also invoked by OpenSSL for signing) */
/* OpenSSL assumes that the output buffer is always big enough */
int pkcs11_private_encrypt(int flen,
		const unsigned char *from, unsigned char *to,
		PKCS11_KEY *key, int padding)
{
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_MECHANISM mechanism;
	CK_ULONG size;
	int rv;

	size = pkcs11_get_key_size(key);

	if (pkcs11_mechanism(&mechanism, padding) < 0)
		return -1;

	CRYPTO_THREAD_write_lock(PRIVCTX(ctx)->rwlock);
	/* Try signing first, as applications are more likely to use it */
	rv = CRYPTOKI_call(ctx,
		C_SignInit(spriv->session, &mechanism, kpriv->object));
	if (!rv && kpriv->always_authenticate == CK_TRUE)
		rv = pkcs11_authenticate(key);
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Sign(spriv->session, (CK_BYTE *)from, flen, to, &size));
	if (rv == CKR_KEY_FUNCTION_NOT_PERMITTED) {
		/* OpenSSL may use it for encryption rather than signing */
		rv = CRYPTOKI_call(ctx,
			C_EncryptInit(spriv->session, &mechanism, kpriv->object));
		if (!rv && kpriv->always_authenticate == CK_TRUE)
			rv = pkcs11_authenticate(key);
		if (!rv)
			rv = CRYPTOKI_call(ctx,
				C_Encrypt(spriv->session, (CK_BYTE *)from, flen, to, &size));
	}
	CRYPTO_THREAD_unlock(PRIVCTX(ctx)->rwlock);

	if (rv) {
		CKRerr(CKR_F_PKCS11_PRIVATE_ENCRYPT, rv);
		return -1;
	}

	return size;
}

/* RSA private key decryption */
int pkcs11_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
		PKCS11_KEY *key, int padding)
{
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_MECHANISM mechanism;
	CK_ULONG size = flen;
	CK_RV rv;

	if (pkcs11_mechanism(&mechanism, padding) < 0)
		return -1;

	CRYPTO_THREAD_write_lock(PRIVCTX(ctx)->rwlock);
	rv = CRYPTOKI_call(ctx,
		C_DecryptInit(spriv->session, &mechanism, kpriv->object));
	if (!rv && kpriv->always_authenticate == CK_TRUE)
		rv = pkcs11_authenticate(key);
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Decrypt(spriv->session, (CK_BYTE *)from, size,
				(CK_BYTE_PTR)to, &size));
	CRYPTO_THREAD_unlock(PRIVCTX(ctx)->rwlock);

	if (rv) {
		CKRerr(CKR_F_PKCS11_PRIVATE_DECRYPT, rv);
		return -1;
	}

	return size;
}

/* TODO: remove this function in libp11 0.5.0 */
int pkcs11_verify(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *signature, unsigned int siglen, PKCS11_KEY *key)
{
	(void)type;
	(void)m;
	(void)m_len;
	(void)signature;
	(void)siglen;
	(void)key;

	/* PKCS11 calls go here */
	P11err(P11_F_PKCS11_VERIFY, P11_R_NOT_SUPPORTED);
	return -1;
}

/*
 * Get RSA key material
 */
static RSA *pkcs11_get_rsa(PKCS11_KEY *key)
{
	RSA *rsa;
	PKCS11_KEY *keys;
	unsigned int i, count;
	BIGNUM *rsa_n = NULL, *rsa_e = NULL;

	/* Retrieve the modulus */
	if (key_getattr_bn(key, CKA_MODULUS, &rsa_n))
		return NULL;

	/* Retrieve the public exponent */
	if (!key_getattr_bn(key, CKA_PUBLIC_EXPONENT, &rsa_e)) {
		if (!BN_is_zero(rsa_e)) /* A valid public exponent */
			goto success;
		BN_clear_free(rsa_e);
		rsa_e = NULL;
	}

	/* The public exponent was not found in the private key:
	 * retrieve it from the corresponding public key */
	if (!PKCS11_enumerate_public_keys(KEY2TOKEN(key), &keys, &count)) {
		for (i = 0; i < count; i++) {
			BIGNUM *pubmod = NULL;
			if (!key_getattr_bn(&keys[i], CKA_MODULUS, &pubmod)) {
				int found = BN_cmp(rsa_n, pubmod) == 0;
				BN_clear_free(pubmod);
				if (found && !key_getattr_bn(&keys[i],
						CKA_PUBLIC_EXPONENT, &rsa_e))
					goto success;
			}
		}
	}

	/* Last resort: use the most common default */
	rsa_e = BN_new();
	if (rsa_e && BN_set_word(rsa_e, RSA_F4))
		goto success;

failure:
	if (rsa_n)
		BN_clear_free(rsa_n);
	if (rsa_e)
		BN_clear_free(rsa_e);
	return NULL;

success:
	rsa = RSA_new();
	if (rsa == NULL)
		goto failure;
#if OPENSSL_VERSION_NUMBER >= 0x10100005L && !defined(LIBRESSL_VERSION_NUMBER)
	RSA_set0_key(rsa, rsa_n, rsa_e, NULL);
#else
	rsa->n = rsa_n;
	rsa->e = rsa_e;
#endif
	return rsa;
}

PKCS11_KEY *pkcs11_get_ex_data_rsa(const RSA *rsa)
{
	return RSA_get_ex_data(rsa, rsa_ex_index);
}

static void pkcs11_set_ex_data_rsa(RSA *rsa, PKCS11_KEY *key)
{
	RSA_set_ex_data(rsa, rsa_ex_index, key);
}

static void pkcs11_update_ex_data_rsa(PKCS11_KEY *key)
{
	EVP_PKEY *evp = key->evp_key;
	RSA *rsa;
	if (evp == NULL)
		return;
	if (EVP_PKEY_base_id(evp) != EVP_PKEY_RSA)
		return;

	rsa = EVP_PKEY_get1_RSA(evp);
	pkcs11_set_ex_data_rsa(rsa, key);
	RSA_free(rsa);
}
/*
 * Build an EVP_PKEY object
 */
static EVP_PKEY *pkcs11_get_evp_key_rsa(PKCS11_KEY *key)
{
	EVP_PKEY *pk;
	RSA *rsa;

	rsa = pkcs11_get_rsa(key);
	if (rsa == NULL)
		return NULL;
	pk = EVP_PKEY_new();
	if (pk == NULL) {
		RSA_free(rsa);
		return NULL;
	}
	EVP_PKEY_set1_RSA(pk, rsa); /* Also increments the rsa ref count */

	if (key->isPrivate)
		RSA_set_method(rsa, PKCS11_get_rsa_method());
	/* TODO: Retrieve the RSA private key object attributes instead,
	 * unless the key has the "sensitive" attribute set */

#if OPENSSL_VERSION_NUMBER < 0x01010000L
	/* RSA_FLAG_SIGN_VER is no longer needed since OpenSSL 1.1 */
	rsa->flags |= RSA_FLAG_SIGN_VER;
#endif
	pkcs11_set_ex_data_rsa(rsa, key);
	RSA_free(rsa); /* Drops our reference to it */
	return pk;
}

/* TODO: remove this function in libp11 0.5.0 */
int pkcs11_get_key_modulus(PKCS11_KEY *key, BIGNUM **bn)
{
	RSA *rsa = pkcs11_rsa(key);
	const BIGNUM *rsa_n;

	if (rsa == NULL)
		return 0;
#if OPENSSL_VERSION_NUMBER >= 0x10100005L && !defined(LIBRESSL_VERSION_NUMBER)
	RSA_get0_key(rsa, &rsa_n, NULL, NULL);
#else
	rsa_n=rsa->n;
#endif
	*bn = BN_dup(rsa_n);
	return *bn == NULL ? 0 : 1;
}

/* TODO: remove this function in libp11 0.5.0 */
int pkcs11_get_key_exponent(PKCS11_KEY *key, BIGNUM **bn)
{
	RSA *rsa = pkcs11_rsa(key);
	const BIGNUM *rsa_e;

	if (rsa == NULL)
		return 0;
#if OPENSSL_VERSION_NUMBER >= 0x10100005L && !defined(LIBRESSL_VERSION_NUMBER)
	RSA_get0_key(rsa, NULL, &rsa_e, NULL);
#else
	rsa_e=rsa->e;
#endif
	*bn = BN_dup(rsa_e);
	return *bn == NULL ? 0 : 1;
}

/* TODO: make this function static in libp11 0.5.0 */
int pkcs11_get_key_size(PKCS11_KEY *key)
{
	RSA *rsa = pkcs11_rsa(key);
	if (rsa == NULL)
		return 0;
	return RSA_size(rsa);
}

#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)

int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))
		(int flen, const unsigned char *from,
			unsigned char *to, RSA *rsa, int padding)
{
    return meth->rsa_priv_enc;
}

int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))
		(int flen, const unsigned char *from,
			unsigned char *to, RSA *rsa, int padding)
{
    return meth->rsa_priv_dec;
}

#endif

static int pkcs11_rsa_priv_dec_method(int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding)
{
	PKCS11_KEY *key = pkcs11_get_ex_data_rsa(rsa);
	int (*priv_dec) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding);
	if (check_key_fork(key) < 0) {
		priv_dec = RSA_meth_get_priv_dec(RSA_get_default_method());
		return priv_dec(flen, from, to, rsa, padding);
	}

	return pkcs11_private_decrypt(flen, from, to, key, padding);
}

static int pkcs11_rsa_priv_enc_method(int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding)
{
	PKCS11_KEY *key = pkcs11_get_ex_data_rsa(rsa);
	int (*priv_enc) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding);
	if (check_key_fork(key) < 0) {
		priv_enc = RSA_meth_get_priv_enc(RSA_get_default_method());
		return priv_enc(flen, from, to, rsa, padding);
	}

	return pkcs11_private_encrypt(flen, from, to, key, padding);
}

static int pkcs11_rsa_free_method(RSA *rsa)
{
	RSA_set_ex_data(rsa, rsa_ex_index, NULL);
	return 1;
}

static void alloc_rsa_ex_index()
{
	if (rsa_ex_index == 0) {
		while (rsa_ex_index == 0) /* Workaround for OpenSSL RT3710 */
			rsa_ex_index = RSA_get_ex_new_index(0, "libp11 rsa",
				NULL, NULL, NULL);
		if (rsa_ex_index < 0)
			rsa_ex_index = 0; /* Fallback to app_data */
	}
}

static void free_rsa_ex_index()
{
	/* CRYPTO_free_ex_index requires OpenSSL version >= 1.1.0-pre1 */
#if OPENSSL_VERSION_NUMBER >= 0x10100001L && !defined(LIBRESSL_VERSION_NUMBER)
	if (rsa_ex_index > 0) {
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA, rsa_ex_index);
		rsa_ex_index = 0;
	}
#endif
}

#if OPENSSL_VERSION_NUMBER < 0x10100005L || defined(LIBRESSL_VERSION_NUMBER)

static RSA_METHOD *RSA_meth_dup(const RSA_METHOD *meth)
{
	RSA_METHOD *ret = OPENSSL_malloc(sizeof(RSA_METHOD));
	if (ret == NULL)
		return NULL;
	memcpy(ret, meth, sizeof(RSA_METHOD));
	ret->name = OPENSSL_strdup(meth->name);
	if (ret->name == NULL) {
		OPENSSL_free(ret);
		return NULL;
	}
	return ret;
}

static int RSA_meth_set1_name(RSA_METHOD *meth, const char *name)
{
	char *tmp = OPENSSL_strdup(name);
	if (tmp == NULL)
		return 0;
	OPENSSL_free((char *)meth->name);
	meth->name = tmp;
	return 1;
}

static int RSA_meth_set_flags(RSA_METHOD *meth, int flags)
{
	meth->flags = flags;
	return 1;
}

static int RSA_meth_set_priv_enc(RSA_METHOD *meth,
		int (*priv_enc) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding))
{
	meth->rsa_priv_enc = priv_enc;
	return 1;
}

static int RSA_meth_set_priv_dec(RSA_METHOD *meth,
		int (*priv_dec) (int flen, const unsigned char *from,
		unsigned char *to, RSA *rsa, int padding))
{
	meth->rsa_priv_dec = priv_dec;
	return 1;
}

static int RSA_meth_set_finish(RSA_METHOD *meth, int (*finish)(RSA *rsa))
{
	meth->finish = finish;
	return 1;
}

#endif

/*
 * Overload the default OpenSSL methods for RSA
 */
RSA_METHOD *PKCS11_get_rsa_method(void)
{
	static RSA_METHOD *ops = NULL;

	if (ops == NULL) {
		alloc_rsa_ex_index();
		ops = RSA_meth_dup(RSA_get_default_method());
		if (ops == NULL)
			return NULL;
		RSA_meth_set1_name(ops, "libp11 RSA method");
		RSA_meth_set_flags(ops, 0);
		RSA_meth_set_priv_enc(ops, pkcs11_rsa_priv_enc_method);
		RSA_meth_set_priv_dec(ops, pkcs11_rsa_priv_dec_method);
		RSA_meth_set_finish(ops, pkcs11_rsa_free_method);
	}
	return ops;
}

/* This function is *not* currently exported */
void PKCS11_rsa_method_free(void)
{
	free_rsa_ex_index();
}

PKCS11_KEY_ops pkcs11_rsa_ops = {
	EVP_PKEY_RSA,
	pkcs11_get_evp_key_rsa,
	pkcs11_update_ex_data_rsa
};

/* The maximum length of PIN */
#define MAX_PIN_LENGTH   32

static int pkcs11_find_keys(PKCS11_TOKEN *, unsigned int);
static int pkcs11_next_key(PKCS11_CTX *ctx, PKCS11_TOKEN *token,
        CK_SESSION_HANDLE session, CK_OBJECT_CLASS type);
static int pkcs11_init_key(PKCS11_CTX *ctx, PKCS11_TOKEN *token,
        CK_SESSION_HANDLE session, CK_OBJECT_HANDLE o,
        CK_OBJECT_CLASS type, PKCS11_KEY **);
static int pkcs11_store_key(PKCS11_TOKEN *, EVP_PKEY *, unsigned int,
        char *, unsigned char *, size_t, PKCS11_KEY **);


/* Set UI method to allow retrieving CKU_CONTEXT_SPECIFIC PINs interactively */
int pkcs11_set_ui_method(PKCS11_CTX *ctx,
		UI_METHOD *ui_method, void *ui_user_data)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	if (cpriv == NULL)
		return -1;
	cpriv->ui_method = ui_method;
	cpriv->ui_user_data = ui_user_data;
	return 0;
}

/*
 * Find key matching a certificate
 */
PKCS11_KEY *pkcs11_find_key(PKCS11_CERT *cert)
{
	PKCS11_CERT_private *cpriv;
	PKCS11_KEY_private *kpriv;
	PKCS11_KEY *keys;
	unsigned int n, count;

	cpriv = PRIVCERT(cert);
	if (PKCS11_enumerate_keys(CERT2TOKEN(cert), &keys, &count))
		return NULL;
	for (n = 0; n < count; n++) {
		kpriv = PRIVKEY(&keys[n]);
		if (cpriv->id_len == kpriv->id_len
				&& !memcmp(cpriv->id, kpriv->id, cpriv->id_len))
			return &keys[n];
	}
	return NULL;
}

/*
 * Find key matching a key of the other type (public vs private)
 */
PKCS11_KEY *pkcs11_find_key_from_key(PKCS11_KEY *keyin)
{
	PKCS11_KEY_private *kinpriv = PRIVKEY(keyin);
	PKCS11_KEY *keys;
	unsigned int n, count;

	pkcs11_enumerate_keys(KEY2TOKEN(keyin),
		keyin->isPrivate ? CKO_PUBLIC_KEY : CKO_PRIVATE_KEY, /* other type */
		&keys, &count);
	for (n = 0; n < count; n++) {
		PKCS11_KEY_private *kpriv = PRIVKEY(&keys[n]);
		if (kinpriv->id_len == kpriv->id_len
				&& !memcmp(kinpriv->id, kpriv->id, kinpriv->id_len))
			return &keys[n];
	}
	return NULL;
}

/*
 * Reopens the object associated with the key
 */
int pkcs11_reload_key(PKCS11_KEY *key)
{
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	CK_OBJECT_CLASS key_search_class =
		key->isPrivate ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
	CK_ATTRIBUTE key_search_attrs[2] = {
		{CKA_CLASS, &key_search_class, sizeof(key_search_class)},
		{CKA_ID, kpriv->id, kpriv->id_len},
	};
	CK_ULONG count;
	int rv;

	/* this is already covered with a per-ctx lock */

	rv = CRYPTOKI_call(ctx,
		C_FindObjectsInit(spriv->session, key_search_attrs, 2));
	CRYPTOKI_checkerr(CKR_F_PKCS11_RELOAD_KEY, rv);

	rv = CRYPTOKI_call(ctx,
		C_FindObjects(spriv->session, &kpriv->object, 1, &count));
	CRYPTOKI_checkerr(CKR_F_PKCS11_RELOAD_KEY, rv);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(spriv->session));

	return 0;
}

/**
 * Generate a keyPair directly on token
 */
int pkcs11_generate_key(PKCS11_TOKEN *token, int algorithm, unsigned int bits,
		char *label, unsigned char* id, size_t id_len) {

	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);

	CK_ATTRIBUTE pubkey_attrs[32];
	CK_ATTRIBUTE privkey_attrs[32];
	unsigned int n_pub = 0, n_priv = 0;
	CK_MECHANISM mechanism = {
		CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE public_exponent[] = { 1, 0, 1 };
	CK_OBJECT_HANDLE pub_key_obj, priv_key_obj;
	int rv;

	(void)algorithm; /* squash the unused parameter warning */

	/* make sure we have a session */
	if (!spriv->haveSession && PKCS11_open_session(slot, 1))
		return -1;

	/* pubkey attributes */
	pkcs11_addattr(pubkey_attrs + n_pub++, CKA_ID, id, id_len);
	if (label)
		pkcs11_addattr_s(pubkey_attrs + n_pub++, CKA_LABEL, label);
	pkcs11_addattr_bool(pubkey_attrs + n_pub++, CKA_TOKEN, TRUE);

	pkcs11_addattr_bool(pubkey_attrs + n_pub++, CKA_ENCRYPT, TRUE);
	pkcs11_addattr_bool(pubkey_attrs + n_pub++, CKA_VERIFY, TRUE);
	pkcs11_addattr_bool(pubkey_attrs + n_pub++, CKA_WRAP, TRUE);
	pkcs11_addattr_int(pubkey_attrs + n_pub++, CKA_MODULUS_BITS, bits);
	pkcs11_addattr(pubkey_attrs + n_pub++, CKA_PUBLIC_EXPONENT, public_exponent, 3);

	/* privkey attributes */
	pkcs11_addattr(privkey_attrs + n_priv++, CKA_ID, id, id_len);
	if (label)
		pkcs11_addattr_s(privkey_attrs + n_priv++, CKA_LABEL, label);
	pkcs11_addattr_bool(privkey_attrs + n_priv++, CKA_TOKEN, TRUE);
	pkcs11_addattr_bool(privkey_attrs + n_priv++, CKA_PRIVATE, TRUE);
	pkcs11_addattr_bool(privkey_attrs + n_priv++, CKA_SENSITIVE, TRUE);
	pkcs11_addattr_bool(privkey_attrs + n_priv++, CKA_DECRYPT, TRUE);
	pkcs11_addattr_bool(privkey_attrs + n_priv++, CKA_SIGN, TRUE);
	pkcs11_addattr_bool(privkey_attrs + n_priv++, CKA_UNWRAP, TRUE);

	/* call the pkcs11 module to create the key pair */
	rv = CRYPTOKI_call(ctx, C_GenerateKeyPair(
		spriv->session,
		&mechanism,
		pubkey_attrs,
		n_pub,
		privkey_attrs,
		n_priv,
		&pub_key_obj,
		&priv_key_obj
	));

	/* zap all memory allocated when building the template */
	pkcs11_zap_attrs(privkey_attrs, n_priv);
	pkcs11_zap_attrs(pubkey_attrs, n_pub);

	CRYPTOKI_checkerr(CKR_F_PKCS11_GENERATE_KEY, rv);

	return 0;
}

/*
 * Store a private key on the token
 */
int pkcs11_store_private_key(PKCS11_TOKEN *token, EVP_PKEY *pk,
		char *label, unsigned char *id, size_t id_len)
{
	if (pkcs11_store_key(token, pk, CKO_PRIVATE_KEY, label, id, id_len, NULL))
		return -1;
	return 0;
}

int pkcs11_store_public_key(PKCS11_TOKEN *token, EVP_PKEY *pk,
		char *label, unsigned char *id, size_t id_len)
{
	if (pkcs11_store_key(token, pk, CKO_PUBLIC_KEY, label, id, id_len, NULL))
		return -1;
	return 0;
}

/*
 * Store private key
 */
static int pkcs11_store_key(PKCS11_TOKEN *token, EVP_PKEY *pk,
		unsigned int type, char *label, unsigned char *id, size_t id_len,
		PKCS11_KEY ** ret_key)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[32];
	unsigned int n = 0;
	int rv;
	const BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_p, *rsa_q, *rsa_dmp1, *rsa_dmq1, *rsa_iqmp;

	/* First, make sure we have a session */
	if (!spriv->haveSession && PKCS11_open_session(slot, 1))
		return -1;

	/* Now build the key attrs */
	pkcs11_addattr_int(attrs + n++, CKA_CLASS, type);
	if (label)
		pkcs11_addattr_s(attrs + n++, CKA_LABEL, label);
	if (id && id_len)
		pkcs11_addattr(attrs + n++, CKA_ID, id, id_len);
	pkcs11_addattr_bool(attrs + n++, CKA_TOKEN, TRUE);
	if (type == CKO_PRIVATE_KEY) {
		pkcs11_addattr_bool(attrs + n++, CKA_PRIVATE, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_SENSITIVE, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_DECRYPT, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_SIGN, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_UNWRAP, TRUE);
	} else { /* CKO_PUBLIC_KEY */
		pkcs11_addattr_bool(attrs + n++, CKA_ENCRYPT, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_VERIFY, TRUE);
		pkcs11_addattr_bool(attrs + n++, CKA_WRAP, TRUE);
	}
#if OPENSSL_VERSION_NUMBER >= 0x10100003L && !defined(LIBRESSL_VERSION_NUMBER)
	if (EVP_PKEY_base_id(pk) == EVP_PKEY_RSA) {
		RSA *rsa = EVP_PKEY_get1_RSA(pk);
		pkcs11_addattr_int(attrs + n++, CKA_KEY_TYPE, CKK_RSA);
		RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
		RSA_get0_factors(rsa, &rsa_p, &rsa_q);
		RSA_get0_crt_params(rsa, &rsa_dmp1, &rsa_dmq1, &rsa_iqmp);
		RSA_free(rsa);
#else
	if (pk->type == EVP_PKEY_RSA) {
		RSA *rsa = pk->pkey.rsa;
		pkcs11_addattr_int(attrs + n++, CKA_KEY_TYPE, CKK_RSA);
		rsa_n=rsa->n;
		rsa_e=rsa->e;
		rsa_d=rsa->d;
		rsa_p=rsa->p;
		rsa_q=rsa->q;
		rsa_dmp1=rsa->dmp1;
		rsa_dmq1=rsa->dmq1;
		rsa_iqmp=rsa->iqmp;
#endif
		pkcs11_addattr_bn(attrs + n++, CKA_MODULUS, rsa_n);
		pkcs11_addattr_bn(attrs + n++, CKA_PUBLIC_EXPONENT, rsa_e);
		if (type == CKO_PRIVATE_KEY) {
			pkcs11_addattr_bn(attrs + n++, CKA_PRIVATE_EXPONENT, rsa_d);
			pkcs11_addattr_bn(attrs + n++, CKA_PRIME_1, rsa_p);
			pkcs11_addattr_bn(attrs + n++, CKA_PRIME_2, rsa_q);
			if (rsa_dmp1)
				pkcs11_addattr_bn(attrs + n++, CKA_EXPONENT_1, rsa_dmp1);
			if (rsa_dmq1)
				pkcs11_addattr_bn(attrs + n++, CKA_EXPONENT_2, rsa_dmq1);
			if (rsa_iqmp)
				pkcs11_addattr_bn(attrs + n++, CKA_COEFFICIENT, rsa_iqmp);
		}
	} else {
		pkcs11_zap_attrs(attrs, n);
		P11err(P11_F_PKCS11_STORE_KEY, P11_R_NOT_SUPPORTED);
		return -1;
	}

	/* Now call the pkcs11 module to create the object */
	rv = CRYPTOKI_call(ctx, C_CreateObject(spriv->session, attrs, n, &object));

	/* Zap all memory allocated when building the template */
	pkcs11_zap_attrs(attrs, n);

	CRYPTOKI_checkerr(CKR_F_PKCS11_STORE_KEY, rv);

	/* Gobble the key object */
	return pkcs11_init_key(ctx, token, spriv->session, object, type, ret_key);
}

/*
 * Get the key type
 */
int pkcs11_get_key_type(PKCS11_KEY *key)
{
	PKCS11_KEY_private *kpriv = PRIVKEY(key);

	return kpriv->ops->type;
}

/*
 * Create an EVP_PKEY OpenSSL object for a given key
 * Returns private or public key depending on isPrivate
 */
EVP_PKEY *pkcs11_get_key(PKCS11_KEY *key, int isPrivate)
{
	if (key->isPrivate != isPrivate)
		key = pkcs11_find_key_from_key(key);
	if (key == NULL)
		return NULL;
	if (key->evp_key == NULL) {
		PKCS11_KEY_private *kpriv = PRIVKEY(key);
		key->evp_key = kpriv->ops->get_evp_key(key);
		if (key->evp_key == NULL)
			return NULL;
		kpriv->always_authenticate = CK_FALSE;
		if (isPrivate && key_getattr_val(key, CKA_ALWAYS_AUTHENTICATE,
				&kpriv->always_authenticate, sizeof(CK_BBOOL))) {
#ifdef DEBUG
			fprintf(stderr, "Missing CKA_ALWAYS_AUTHENTICATE attribute\n");
#endif
		}
	}
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	EVP_PKEY_up_ref(key->evp_key);
#else
	CRYPTO_add(&key->evp_key->references, 1, CRYPTO_LOCK_EVP_PKEY);
#endif
	return key->evp_key;
}

/*
 * Authenticate a private the key operation if needed
 * This function *only* handles CKU_CONTEXT_SPECIFIC logins.
 */
int pkcs11_authenticate(PKCS11_KEY *key)
{
	PKCS11_TOKEN *token = KEY2TOKEN(key);
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	char pin[MAX_PIN_LENGTH+1];
	char* prompt;
	UI *ui;
	int rv;

	/* Handle CKF_PROTECTED_AUTHENTICATION_PATH */
	if (token->secureLogin) {
		rv = CRYPTOKI_call(ctx,
			C_Login(spriv->session, CKU_CONTEXT_SPECIFIC, NULL, 0));
		return rv == CKR_USER_ALREADY_LOGGED_IN ? 0 : rv;
	}

	/* Call UI to ask for a PIN */
	ui = UI_new_method(cpriv->ui_method);
	if (ui == NULL)
		return P11_R_UI_FAILED;
	if (cpriv->ui_user_data != NULL)
		UI_add_user_data(ui, cpriv->ui_user_data);
	memset(pin, 0, MAX_PIN_LENGTH+1);
	prompt = UI_construct_prompt(ui, "PKCS#11 key PIN", key->label);
	if (!prompt) {
		return P11_R_UI_FAILED;
	}
	if (!UI_dup_input_string(ui, prompt,
			UI_INPUT_FLAG_DEFAULT_PWD, pin, 4, MAX_PIN_LENGTH)) {
		UI_free(ui);
		OPENSSL_free(prompt);
		return P11_R_UI_FAILED;
	}
	OPENSSL_free(prompt);

	if (UI_process(ui)) {
		UI_free(ui);
		return P11_R_UI_FAILED;
	}
	UI_free(ui);

	/* Login with the PIN */
	rv = CRYPTOKI_call(ctx,
		C_Login(spriv->session, CKU_CONTEXT_SPECIFIC,
			(CK_UTF8CHAR *)pin, strlen(pin)));
	OPENSSL_cleanse(pin, MAX_PIN_LENGTH+1);
	return rv == CKR_USER_ALREADY_LOGGED_IN ? 0 : rv;
}

/*
 * Return keys of a given type (public or private)
 * Use the cached values if available
 */
int pkcs11_enumerate_keys(PKCS11_TOKEN *token, unsigned int type,
		PKCS11_KEY ** keyp, unsigned int *countp)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	PKCS11_keys *keys = (type == CKO_PRIVATE_KEY) ? &tpriv->prv : &tpriv->pub;
	PKCS11_KEY *first_key_prev = keys->keys;
	int rv;
	int i;

	/* Make sure we have a session */
	if (!spriv->haveSession && PKCS11_open_session(slot, 0))
		return -1;

	CRYPTO_THREAD_write_lock(cpriv->rwlock);
	rv = pkcs11_find_keys(token, type);
	CRYPTO_THREAD_unlock(cpriv->rwlock);
	if (rv < 0) {
		pkcs11_destroy_keys(token, type);
		return -1;
	}

	/* Always update key references if the keys pointer changed */
	if (first_key_prev != NULL && first_key_prev != keys->keys) {
		for (i = 0; i < keys->num; ++i) {
			PKCS11_KEY *key = keys->keys + i;
			PKCS11_KEY_private *kpriv = PRIVKEY(key);
			kpriv->ops->update_ex_data(key);
		}
	}

	if (keyp)
		*keyp = keys->keys;
	if (countp)
		*countp = keys->num;
	return 0;
}

/**
 * Remove a key from the associated token
 */ 
int pkcs11_remove_key(PKCS11_KEY *key) {
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_OBJECT_HANDLE obj;
	CK_ULONG count;
	CK_ATTRIBUTE search_parameters[32];
	unsigned int n = 0;
	int rv;

	/* First, make sure we have a session */
	if (!spriv->haveSession && PKCS11_open_session(slot, 1))
		return -1;
	if (key->isPrivate)
		pkcs11_addattr_int(search_parameters + n++, CKA_CLASS, CKO_PRIVATE_KEY);
	else
		pkcs11_addattr_int(search_parameters + n++, CKA_CLASS, CKO_PUBLIC_KEY);
	if (key->id && key->id_len)
		pkcs11_addattr(search_parameters + n++, CKA_ID, key->id, key->id_len);
	if (key->label)
	 	pkcs11_addattr_s(search_parameters + n++, CKA_LABEL, key->label);

	rv = CRYPTOKI_call(ctx,
		C_FindObjectsInit(spriv->session, search_parameters, n));
	CRYPTOKI_checkerr(CKR_F_PKCS11_REMOVE_KEY, rv);

	rv = CRYPTOKI_call(ctx, C_FindObjects(spriv->session, &obj, 1, &count));
	CRYPTOKI_checkerr(CKR_F_PKCS11_REMOVE_KEY, rv);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(spriv->session));
	if (count!=1) {
		pkcs11_zap_attrs(search_parameters, n);
		return -1;
	}
	rv = CRYPTOKI_call(ctx, C_DestroyObject(spriv->session, obj));
	if (rv != CKR_OK) {
		pkcs11_zap_attrs(search_parameters, n);
		return -1;
	}
	pkcs11_zap_attrs(search_parameters, n);
	return 0;
}

/*
 * Find all keys of a given type (public or private)
 */
static int pkcs11_find_keys(PKCS11_TOKEN *token, unsigned int type)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_OBJECT_CLASS key_search_class;
	CK_ATTRIBUTE key_search_attrs[1] = {
		{CKA_CLASS, &key_search_class, sizeof(key_search_class)},
	};
	int rv, res = -1;

	/* Tell the PKCS11 lib to enumerate all matching objects */
	key_search_class = type;
	rv = CRYPTOKI_call(ctx,
		C_FindObjectsInit(spriv->session, key_search_attrs, 1));
	CRYPTOKI_checkerr(CKR_F_PKCS11_FIND_KEYS, rv);

	do {
		res = pkcs11_next_key(ctx, token, spriv->session, type);
	} while (res == 0);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(spriv->session));

	return (res < 0) ? -1 : 0;
}

static int pkcs11_next_key(PKCS11_CTX *ctx, PKCS11_TOKEN *token,
		CK_SESSION_HANDLE session, CK_OBJECT_CLASS type)
{
	CK_OBJECT_HANDLE obj;
	CK_ULONG count;
	int rv;

	/* Get the next matching object */
	rv = CRYPTOKI_call(ctx, C_FindObjects(session, &obj, 1, &count));
	CRYPTOKI_checkerr(CKR_F_PKCS11_NEXT_KEY, rv);

	if (count == 0)
		return 1;

	if (pkcs11_init_key(ctx, token, session, obj, type, NULL))
		return -1;

	return 0;
}

static int pkcs11_init_key(PKCS11_CTX *ctx, PKCS11_TOKEN *token,
		CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
		CK_OBJECT_CLASS type, PKCS11_KEY ** ret)
{
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);
	PKCS11_keys *keys = (type == CKO_PRIVATE_KEY) ? &tpriv->prv : &tpriv->pub;
	PKCS11_KEY_private *kpriv;
	PKCS11_KEY *key, *tmp;
	CK_KEY_TYPE key_type;
	PKCS11_KEY_ops *ops;
	size_t size;
	int i;

	(void)ctx;
	(void)session;

	/* Ignore unknown key types */
	size = sizeof(CK_KEY_TYPE);
	if (pkcs11_getattr_var(token, obj, CKA_KEY_TYPE, (CK_BYTE *)&key_type, &size))
		return -1;
	switch (key_type) {
	case CKK_RSA:
		ops = &pkcs11_rsa_ops;
		break;
	case CKK_EC:
		ops = pkcs11_ec_ops;
		if (ops == NULL)
			return 0; /* not supported */
		break;
	default:
		/* Ignore any keys we don't understand */
		return 0;
	}

	/* Prevent re-adding existing PKCS#11 object handles */
	/* TODO: Rewrite the O(n) algorithm as O(log n),
	 * or it may be too slow with a large number of keys */
	for (i=0; i < keys->num; ++i)
		if (PRIVKEY(keys->keys + i)->object == obj)
			return 0;

	/* Allocate memory */
	kpriv = OPENSSL_malloc(sizeof(PKCS11_KEY_private));
	if (kpriv == NULL)
		return -1;
	memset(kpriv, 0, sizeof(PKCS11_KEY_private));
	tmp = OPENSSL_realloc(keys->keys, (keys->num + 1) * sizeof(PKCS11_KEY));
	if (tmp == NULL)
		return -1;
	keys->keys = tmp;
	key = keys->keys + keys->num++;
	memset(key, 0, sizeof(PKCS11_KEY));

	/* Fill public properties */
	pkcs11_getattr_alloc(token, obj, CKA_LABEL, (CK_BYTE **)&key->label, NULL);
	key->id_len = 0;
	pkcs11_getattr_alloc(token, obj, CKA_ID, &key->id, &key->id_len);
	key->isPrivate = (type == CKO_PRIVATE_KEY);

	/* Fill private properties */
	key->_private = kpriv;
	kpriv->object = obj;
	kpriv->parent = token;
	kpriv->id_len = sizeof kpriv->id;
	if (pkcs11_getattr_var(token, obj, CKA_ID, kpriv->id, &kpriv->id_len))
		kpriv->id_len = 0;
	kpriv->ops = ops;
	kpriv->forkid = get_forkid();

	if (ret)
		*ret = key;
	return 0;
}

/*
 * Destroy all keys of a given type (public or private)
 */
void pkcs11_destroy_keys(PKCS11_TOKEN *token, unsigned int type)
{
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);
	PKCS11_keys *keys = (type == CKO_PRIVATE_KEY) ? &tpriv->prv : &tpriv->pub;

	while (keys->num > 0) {
		PKCS11_KEY *key = &keys->keys[--(keys->num)];

		if (key->evp_key)
			EVP_PKEY_free(key->evp_key);
		OPENSSL_free(key->label);
		if (key->id)
			OPENSSL_free(key->id);
		if (key->_private != NULL)
			OPENSSL_free(key->_private);
	}
	if (keys->keys)
		OPENSSL_free(keys->keys);
	keys->keys = NULL;
	keys->num = 0;
}

/* PKCS11 strings are fixed size blank padded,
 * so when strduping them we must make sure
 * we stop at the end of the buffer, and while we're
 * at it it's nice to remove the padding */
char *pkcs11_strdup(char *mem, size_t size)
{
	char *res;

	while (size && mem[size - 1] == ' ')
		size--;
	res = OPENSSL_malloc(size + 1);
	if (res == NULL)
		return NULL;
	memcpy(res, mem, size);
	res[size] = '\0';
	return res;
}

/*
 * CRYPTO dynlock wrappers: 0 is an invalid dynamic lock ID
 */

#if OPENSSL_VERSION_NUMBER < 0x10100004L || defined(LIBRESSL_VERSION_NUMBER)

int CRYPTO_THREAD_lock_new()
{
	int i;

	if (CRYPTO_get_dynlock_create_callback() == NULL ||
			CRYPTO_get_dynlock_lock_callback() == NULL ||
			CRYPTO_get_dynlock_destroy_callback() == NULL)
		return 0; /* Dynamic callbacks not set */
	i = CRYPTO_get_new_dynlockid();
	if (i == 0)
		ERR_clear_error(); /* Dynamic locks are optional -> ignore */
	return i;
}

void CRYPTO_THREAD_lock_free(int i)
{
	if (i)
		CRYPTO_destroy_dynlockid(i);
}

#endif

/*
 * Create a new context
 */
PKCS11_CTX *pkcs11_CTX_new(void)
{
	PKCS11_CTX_private *cpriv = NULL;
	PKCS11_CTX *ctx = NULL;

	/* Load error strings */
	ERR_load_PKCS11_strings();

	cpriv = OPENSSL_malloc(sizeof(PKCS11_CTX_private));
	if (cpriv == NULL)
		goto fail;
	memset(cpriv, 0, sizeof(PKCS11_CTX_private));
	ctx = OPENSSL_malloc(sizeof(PKCS11_CTX));
	if (ctx == NULL)
		goto fail;
	memset(ctx, 0, sizeof(PKCS11_CTX));
	ctx->_private = cpriv;
	cpriv->forkid = get_forkid();
	cpriv->rwlock = CRYPTO_THREAD_lock_new();
	cpriv->sign_initialized = 0;
	cpriv->decrypt_initialized = 0;

	return ctx;
fail:
	OPENSSL_free(cpriv);
	OPENSSL_free(ctx);
	return NULL;
}

/*
 * Set private init args for module
 */
void pkcs11_CTX_init_args(PKCS11_CTX *ctx, const char *init_args)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	/* Free previously duplicated string */
	if (cpriv->init_args) {
		OPENSSL_free(cpriv->init_args);
	}
	cpriv->init_args = init_args ? OPENSSL_strdup(init_args) : NULL;
}

/*
 * Load the shared library, and initialize it.
 */
int pkcs11_CTX_load(PKCS11_CTX *ctx, const char *name)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	CK_C_INITIALIZE_ARGS args;
	CK_INFO ck_info;
	int rv;

	cpriv->handle = C_LoadModule(name, &cpriv->method);
	if (cpriv->handle == NULL) {
		P11err(P11_F_PKCS11_CTX_LOAD, P11_R_LOAD_MODULE_ERROR);
		return -1;
	}

	/* Tell the PKCS11 to initialize itself */
	memset(&args, 0, sizeof(args));
	/* Unconditionally say using OS locking primitives is OK */
	args.flags |= CKF_OS_LOCKING_OK;
	args.pReserved = cpriv->init_args;
	rv = cpriv->method->C_Initialize(&args);
	if (rv && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		C_UnloadModule(cpriv->handle);
		cpriv->handle = NULL;
		CKRerr(P11_F_PKCS11_CTX_LOAD, rv);
		return -1;
	}

	/* Get info on the library */
	rv = cpriv->method->C_GetInfo(&ck_info);
	if (rv) {
		cpriv->method->C_Finalize(NULL);
		C_UnloadModule(cpriv->handle);
		cpriv->handle = NULL;
		CKRerr(P11_F_PKCS11_CTX_LOAD, rv);
		return -1;
	}

	ctx->manufacturer = PKCS11_DUP(ck_info.manufacturerID);
	ctx->description = PKCS11_DUP(ck_info.libraryDescription);

	return 0;
}

/*
 * Reinitialize (e.g., after a fork).
 */
int pkcs11_CTX_reload(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	CK_C_INITIALIZE_ARGS _args;
	CK_C_INITIALIZE_ARGS *args = NULL;
	int rv;

	if (cpriv->method == NULL) /* Module not loaded */
		return 0;

	/* Tell the PKCS11 to initialize itself */
	if (cpriv->init_args != NULL) {
		memset(&_args, 0, sizeof(_args));
		args = &_args;
		args->pReserved = cpriv->init_args;
	}
	rv = cpriv->method->C_Initialize(args);
	if (rv && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		CKRerr(P11_F_PKCS11_CTX_RELOAD, rv);
		return -1;
	}

	return 0;
}

/*
 * Unload the shared library
 */
void pkcs11_CTX_unload(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);

	/* Tell the PKCS11 library to shut down */
	if (cpriv->forkid == get_forkid())
		cpriv->method->C_Finalize(NULL);

	/* Unload the module */
	C_UnloadModule(cpriv->handle);
	cpriv->handle = NULL;
}

/*
 * Free a context
 */
void pkcs11_CTX_free(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);

	/* TODO: Move the global methods and ex_data indexes into
	 * the ctx structure, so they can be safely deallocated here:
	PKCS11_rsa_method_free(ctx);
	PKCS11_ecdsa_method_free(ctx);
	*/
	if (cpriv->init_args) {
		OPENSSL_free(cpriv->init_args);
	}
	if (cpriv->handle) {
		OPENSSL_free(cpriv->handle);
	}
	CRYPTO_THREAD_lock_free(cpriv->rwlock);
	OPENSSL_free(ctx->manufacturer);
	OPENSSL_free(ctx->description);
	OPENSSL_free(ctx->_private);
	OPENSSL_free(ctx);
}

/* The following exported functions are *not* implemented here:
 * PKCS11_get_rsa_method
 * PKCS11_get_ecdsa_method
 * PKCS11_ecdsa_method_free
 * PKCS11_get_ec_key_method
 */

/* External interface to the libp11 features */

PKCS11_CTX *PKCS11_CTX_new(void)
{
	return pkcs11_CTX_new();
}

void PKCS11_CTX_init_args(PKCS11_CTX *ctx, const char *init_args)
{
	if (check_fork(ctx) < 0)
		return;
	pkcs11_CTX_init_args(ctx, init_args);
}

int PKCS11_CTX_load(PKCS11_CTX *ctx, const char *ident)
{
	if (check_fork(ctx) < 0)
		return -1;
	return pkcs11_CTX_load(ctx, ident);
}

void PKCS11_CTX_unload(PKCS11_CTX *ctx)
{
	if (check_fork(ctx) < 0)
		return;
	pkcs11_CTX_unload(ctx);
}

void PKCS11_CTX_free(PKCS11_CTX *ctx)
{
	if (check_fork(ctx) < 0)
		return;
	pkcs11_CTX_free(ctx);
}

int PKCS11_open_session(PKCS11_SLOT *slot, int rw)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_open_session(slot, rw, 0);
}

int PKCS11_enumerate_slots(PKCS11_CTX *ctx,
		PKCS11_SLOT **slotsp, unsigned int *nslotsp)
{
	if (check_fork(ctx) < 0)
		return -1;
	return pkcs11_enumerate_slots(ctx, slotsp, nslotsp);
}

unsigned long PKCS11_get_slotid_from_slot(PKCS11_SLOT *slot)
{
	if (check_slot_fork(slot) < 0)
		return 0L;
	return pkcs11_get_slotid_from_slot(slot);
}

void PKCS11_release_all_slots(PKCS11_CTX *ctx,
		PKCS11_SLOT *slots, unsigned int nslots)
{
	if (check_fork(ctx) < 0)
		return;
	pkcs11_release_all_slots(ctx, slots, nslots);
}

PKCS11_SLOT *PKCS11_find_token(PKCS11_CTX *ctx,
		PKCS11_SLOT *slots, unsigned int nslots)
{
	if (check_fork(ctx) < 0)
		return NULL;
	return pkcs11_find_token(ctx, slots, nslots);
}

PKCS11_SLOT *PKCS11_find_next_token(PKCS11_CTX *ctx,
		PKCS11_SLOT *slots, unsigned int nslots,
		PKCS11_SLOT *current)
{
	if (check_fork(ctx) < 0)
		return NULL;
	return pkcs11_find_next_token(ctx, slots, nslots, current);
}

int PKCS11_is_logged_in(PKCS11_SLOT *slot, int so, int *res)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_is_logged_in(slot, so, res);
}

int PKCS11_login(PKCS11_SLOT *slot, int so, const char *pin)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_login(slot, so, pin, 0);
}

int PKCS11_logout(PKCS11_SLOT *slot)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_logout(slot);
}

int PKCS11_enumerate_keys(PKCS11_TOKEN *token,
		PKCS11_KEY **keys, unsigned int *nkeys)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_enumerate_keys(token, CKO_PRIVATE_KEY, keys, nkeys);
}

int PKCS11_remove_key(PKCS11_KEY *key)
{
	if (check_key_fork(key) < 0)
		return -1;
	return pkcs11_remove_key(key);
}

int PKCS11_enumerate_public_keys(PKCS11_TOKEN *token,
		PKCS11_KEY **keys, unsigned int *nkeys)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_enumerate_keys(token, CKO_PUBLIC_KEY, keys, nkeys);
}

int PKCS11_get_key_type(PKCS11_KEY *key)
{
	if (check_key_fork(key) < 0)
		return -1;
	return pkcs11_get_key_type(key);
}

EVP_PKEY *PKCS11_get_private_key(PKCS11_KEY *key)
{
	if (check_key_fork(key) < 0)
		return NULL;
	return pkcs11_get_key(key, 1);
}

EVP_PKEY *PKCS11_get_public_key(PKCS11_KEY *key)
{
	if (check_key_fork(key) < 0)
		return NULL;
	return pkcs11_get_key(key, 0);
}

PKCS11_CERT *PKCS11_find_certificate(PKCS11_KEY *key)
{
	if (check_key_fork(key) < 0)
		return NULL;
	return pkcs11_find_certificate(key);
}

PKCS11_KEY *PKCS11_find_key(PKCS11_CERT *cert)
{
	if (check_cert_fork(cert) < 0)
		return NULL;
	return pkcs11_find_key(cert);
}

int PKCS11_enumerate_certs(PKCS11_TOKEN *token,
		PKCS11_CERT **certs, unsigned int *ncerts)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_enumerate_certs(token, certs, ncerts);
}

int PKCS11_remove_certificate(PKCS11_CERT *cert)
{
	if (check_cert_fork(cert) < 0)
		return -1;
	return pkcs11_remove_certificate(cert);
}

int PKCS11_init_token(PKCS11_TOKEN *token, const char *pin,
		const char *label)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_init_token(token, pin, label);
}

int PKCS11_init_pin(PKCS11_TOKEN *token, const char *pin)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_init_pin(token, pin);
}

int PKCS11_change_pin(PKCS11_SLOT *slot,
		const char *old_pin, const char *new_pin)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_change_pin(slot, old_pin, new_pin);
}

int PKCS11_store_private_key(PKCS11_TOKEN *token,
		EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_store_private_key(token, pk, label, id, id_len);
}

int PKCS11_store_public_key(PKCS11_TOKEN *token,
    	EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_store_public_key(token, pk, label, id, id_len);
}

int PKCS11_store_certificate(PKCS11_TOKEN *token, X509 *x509,
		char *label, unsigned char *id, size_t id_len,
		PKCS11_CERT **ret_cert)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_store_certificate(token, x509, label, id, id_len, ret_cert);
}

int PKCS11_seed_random(PKCS11_SLOT *slot, const unsigned char *s, unsigned int s_len)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_seed_random(slot, s, s_len);
}

int PKCS11_generate_random(PKCS11_SLOT *slot, unsigned char *r, unsigned int r_len)
{
	if (check_slot_fork(slot) < 0)
		return -1;
	return pkcs11_generate_random(slot, r, r_len);
}

void ERR_load_PKCS11_strings(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif
	ERR_load_P11_strings();
	ERR_load_CKR_strings();
}

int PKCS11_set_ui_method(PKCS11_CTX *ctx, UI_METHOD *ui_method, void *ui_user_data)
{
	if (check_fork(ctx) < 0)
		return -1;
	return pkcs11_set_ui_method(ctx, ui_method, ui_user_data);
}

/* External interface to the deprecated features */

int PKCS11_generate_key(PKCS11_TOKEN *token,
		int algorithm, unsigned int bits,
		char *label, unsigned char *id, size_t id_len)
{
	if (check_token_fork(token) < 0)
		return -1;
	return pkcs11_generate_key(token, algorithm, bits, label, id, id_len);
}

int PKCS11_get_key_size(PKCS11_KEY *key)
{
	if (check_key_fork(key) < 0)
		return -1;
	return pkcs11_get_key_size(key);
}

int PKCS11_get_key_modulus(PKCS11_KEY *key, BIGNUM **bn)
{
	if (check_key_fork(key) < 0)
		return -1;
	return pkcs11_get_key_modulus(key, bn);
}

int PKCS11_get_key_exponent(PKCS11_KEY *key, BIGNUM **bn)
{
	if (check_key_fork(key) < 0)
		return -1;
	return pkcs11_get_key_exponent(key, bn);
}

int PKCS11_sign(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, PKCS11_KEY *key)
{
	if (check_key_fork(key) < 0)
		return -1;
	return pkcs11_sign(type, m, m_len, sigret, siglen, key);
}

int PKCS11_verify(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *signature, unsigned int siglen, PKCS11_KEY *key)
{
	(void)type;
	(void)m;
	(void)m_len;
	(void)signature;
	(void)siglen;
	(void)key;

	/* PKCS11 calls go here */
	P11err(P11_F_PKCS11_VERIFY, P11_R_NOT_SUPPORTED);
	return -1;
}

#define P11_LIB_NAME "libp11"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(0,func,0)
# define ERR_REASON(reason) ERR_PACK(0,0,reason)

static ERR_STRING_DATA P11_str_functs[] = {
    {ERR_FUNC(P11_F_PKCS11_CHANGE_PIN), "pkcs11_change_pin"},
    {ERR_FUNC(P11_F_PKCS11_CTX_LOAD), "pkcs11_CTX_load"},
    {ERR_FUNC(P11_F_PKCS11_CTX_RELOAD), "pkcs11_CTX_reload"},
    {ERR_FUNC(P11_F_PKCS11_ECDH_DERIVE), "pkcs11_ecdh_derive"},
    {ERR_FUNC(P11_F_PKCS11_GENERATE_RANDOM), "pkcs11_generate_random"},
    {ERR_FUNC(P11_F_PKCS11_INIT_PIN), "pkcs11_init_pin"},
    {ERR_FUNC(P11_F_PKCS11_LOGOUT), "pkcs11_logout"},
    {ERR_FUNC(P11_F_PKCS11_MECHANISM), "pkcs11_mechanism"},
    {ERR_FUNC(P11_F_PKCS11_SEED_RANDOM), "pkcs11_seed_random"},
    {ERR_FUNC(P11_F_PKCS11_STORE_KEY), "pkcs11_store_key"},
    {ERR_FUNC(P11_F_PKCS11_VERIFY), "PKCS11_verify"},
    {0, NULL}
};

static ERR_STRING_DATA P11_str_reasons[] = {
    {ERR_REASON(P11_R_KEYGEN_FAILED), "Key generation failed"},
    {ERR_REASON(P11_R_LOAD_MODULE_ERROR), "Unable to load PKCS#11 module"},
    {ERR_REASON(P11_R_NOT_SUPPORTED), "Not supported"},
    {ERR_REASON(P11_R_NO_SESSION), "No session open"},
    {ERR_REASON(P11_R_UI_FAILED), "UI request failed"},
    {ERR_REASON(P11_R_UNSUPPORTED_PADDING_TYPE), "Unsupported padding type"},
    {0, NULL}
};

#endif

#ifdef P11_LIB_NAME
static ERR_STRING_DATA P11_lib_name[] = {
    {0, P11_LIB_NAME},
    {0, NULL}
};
#endif

static int P11_lib_error_code = 0;
static int P11_error_init = 1;

int ERR_load_P11_strings(void)
{
    if (P11_lib_error_code == 0)
        P11_lib_error_code = ERR_get_next_error_library();

    if (P11_error_init) {
        P11_error_init = 0;
#ifndef OPENSSL_NO_ERR
        ERR_load_strings(P11_lib_error_code, P11_str_functs);
        ERR_load_strings(P11_lib_error_code, P11_str_reasons);
#endif

#ifdef P11_LIB_NAME
        P11_lib_name->error = ERR_PACK(P11_lib_error_code, 0, 0);
        ERR_load_strings(0, P11_lib_name);
#endif
    }
    return 1;
}

void ERR_unload_P11_strings(void)
{
    if (P11_error_init == 0) {
#ifndef OPENSSL_NO_ERR
        ERR_unload_strings(P11_lib_error_code, P11_str_functs);
        ERR_unload_strings(P11_lib_error_code, P11_str_reasons);
#endif

#ifdef P11_LIB_NAME
        ERR_unload_strings(0, P11_lib_name);
#endif
        P11_error_init = 1;
    }
}

void ERR_P11_error(int function, int reason, char *file, int line)
{
    if (P11_lib_error_code == 0)
        P11_lib_error_code = ERR_get_next_error_library();
    ERR_PUT_error(P11_lib_error_code, function, reason, file, line);
}

/*
 * This file implements the handling of EC keys stored on a
 * PKCS11 token
 */

#ifndef OPENSSL_NO_EC

#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
typedef int (*compute_key_fn)(unsigned char **, size_t *,
	const EC_POINT *, const EC_KEY *);
#else
typedef int (*compute_key_fn)(void *, size_t,
	const EC_POINT *, const EC_KEY *,
	void *(*)(const void *, size_t, void *, size_t *));
#endif
static compute_key_fn ossl_ecdh_compute_key;

static int ec_ex_index = 0;

/********** Missing ECDSA_METHOD functions for OpenSSL < 1.1.0 */

typedef ECDSA_SIG *(*sign_sig_fn)(const unsigned char *, int,
	const BIGNUM *, const BIGNUM *, EC_KEY *);

#if OPENSSL_VERSION_NUMBER < 0x10100000L

/* ecdsa_method maintains unchanged layout between 0.9.8 and 1.0.2 */

/* Data pointers and function pointers may have different sizes on some
 * architectures */
struct ecdsa_method {
	char *name;
	sign_sig_fn ecdsa_do_sign;
	void (*ecdsa_sign_setup)();
	void (*ecdsa_do_verify)();
	int flags;
	char *app_data;
};

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)

/* Define missing functions */

ECDSA_METHOD *ECDSA_METHOD_new(const ECDSA_METHOD *m)
{
	ECDSA_METHOD *out;
	out = OPENSSL_malloc(sizeof(ECDSA_METHOD));
	if (out == NULL)
		return NULL;
	if (m)
		memcpy(out, m, sizeof(ECDSA_METHOD));
	else
		memset(out, 0, sizeof(ECDSA_METHOD));
	return out;
}

void ECDSA_METHOD_free(ECDSA_METHOD *m)
{
	OPENSSL_free(m);
}

void ECDSA_METHOD_set_sign(ECDSA_METHOD *m, sign_sig_fn f)
{
	m->ecdsa_do_sign = f;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10002000L */

/********** Missing ECDH_METHOD functions for OpenSSL < 1.1.0 */

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

/* ecdh_method maintains unchanged layout between 0.9.8 and 1.0.2 */

/* Data pointers and function pointers may have different sizes on some
 * architectures */
struct ecdh_method {
	char *name;
	compute_key_fn compute_key;
	int flags;
	char *data;
};

/* Define missing functions */

ECDH_METHOD *ECDH_METHOD_new(const ECDH_METHOD *m)
{
	ECDH_METHOD *out;
	out = OPENSSL_malloc(sizeof(ECDH_METHOD));
	if (out == NULL)
		return NULL;
	if (m)
		memcpy(out, m, sizeof(ECDH_METHOD));
	else
		memset(out, 0, sizeof(ECDH_METHOD));
	return out;
}

void ECDH_METHOD_free(ECDH_METHOD *m)
{
	OPENSSL_free(m);
}

void ECDH_METHOD_get_compute_key(ECDH_METHOD *m, compute_key_fn *f)
{
	*f = m->compute_key;
}

void ECDH_METHOD_set_compute_key(ECDH_METHOD *m, compute_key_fn f)
{
	m->compute_key = f;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

/********** Manage EC ex_data */

/* NOTE: ECDH also uses ECDSA ex_data and *not* ECDH ex_data */
static void alloc_ec_ex_index()
{
	if (ec_ex_index == 0) {
		while (ec_ex_index == 0) /* Workaround for OpenSSL RT3710 */
#if OPENSSL_VERSION_NUMBER >= 0x10100002L && !defined(LIBRESSL_VERSION_NUMBER)
			ec_ex_index = EC_KEY_get_ex_new_index(0, "libp11 ec_key",
				NULL, NULL, NULL);
#else
			ec_ex_index = ECDSA_get_ex_new_index(0, "libp11 ecdsa",
				NULL, NULL, NULL);
#endif
		if (ec_ex_index < 0)
			ec_ex_index = 0; /* Fallback to app_data */
	}
}

#if 0
/* TODO: Free the indexes on unload */
static void free_ec_ex_index()
{
	if (ec_ex_index > 0) {
#if OPENSSL_VERSION_NUMBER >= 0x10100002L
		/* CRYPTO_free_ex_index requires OpenSSL version >= 1.1.0-pre1 */
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_EC_KEY, ec_ex_index);
#endif
		ec_ex_index = 0;
	}
}
#endif

/********** EVP_PKEY retrieval */

/* Retrieve EC parameters from key into ec
 * return nonzero on error */
static int pkcs11_get_params(EC_KEY *ec, PKCS11_KEY *key)
{
	CK_BYTE *params;
	size_t params_len = 0;
	const unsigned char *a;
	int rv;

	if (key_getattr_alloc(key, CKA_EC_PARAMS, &params, &params_len))
		return -1;

	a = params;
	rv = d2i_ECParameters(&ec, &a, (long)params_len) == NULL;
	OPENSSL_free(params);
	return rv;
}

/* Retrieve EC point from key into ec
 * return nonzero on error */
static int pkcs11_get_point(EC_KEY *ec, PKCS11_KEY *key)
{
	CK_BYTE *point;
	size_t point_len = 0;
	const unsigned char *a;
	ASN1_OCTET_STRING *os;
	int rv = -1;

	if (key == NULL ||
			key_getattr_alloc(key, CKA_EC_POINT, &point, &point_len))
		return -1;

	/* PKCS#11-compliant modules should return ASN1_OCTET_STRING */
	a = point;
	os = d2i_ASN1_OCTET_STRING(NULL, &a, (long)point_len);
	if (os) {
		a = os->data;
		rv = o2i_ECPublicKey(&ec, &a, os->length) == NULL;
		ASN1_STRING_free(os);
	}
	if (rv) { /* Workaround for broken PKCS#11 modules */
		a = point;
		rv = o2i_ECPublicKey(&ec, &a, (long)point_len) == NULL;
	}
	OPENSSL_free(point);
	return rv;
}

static EC_KEY *pkcs11_get_ec(PKCS11_KEY *key)
{
	EC_KEY *ec;
	int no_params, no_point;

	ec = EC_KEY_new();
	if (ec == NULL)
		return NULL;

	/* For OpenSSL req we need at least the
	 * EC_KEY_get0_group(ec_key)) to return the group.
	 * Continue even if it fails, as the sign operation does not need
	 * it if the PKCS#11 module or the hardware can figure this out
	 */
	no_params = pkcs11_get_params(ec, key);
	no_point = pkcs11_get_point(ec, key);
	if (no_point && key->isPrivate) /* Retry with the public key */
		no_point = pkcs11_get_point(ec, pkcs11_find_key_from_key(key));

	if (key->isPrivate && EC_KEY_get0_private_key(ec) == NULL) {
		EC_KEY_set_private_key(ec, BN_new());
	}

	/* A public keys requires both the params and the point to be present */
	if (!key->isPrivate && (no_params || no_point)) {
		EC_KEY_free(ec);
		return NULL;
	}

	return ec;
}

PKCS11_KEY *pkcs11_get_ex_data_ec(const EC_KEY *ec)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	return EC_KEY_get_ex_data(ec, ec_ex_index);
#else
	return ECDSA_get_ex_data((EC_KEY *)ec, ec_ex_index);
#endif
}

static void pkcs11_set_ex_data_ec(EC_KEY *ec, PKCS11_KEY *key)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	EC_KEY_set_ex_data(ec, ec_ex_index, key);
#else
	ECDSA_set_ex_data(ec, ec_ex_index, key);
#endif
}

static void pkcs11_update_ex_data_ec(PKCS11_KEY *key)
{
	EVP_PKEY *evp = key->evp_key;
	EC_KEY *ec;
	if (evp == NULL)
		return;
	if (EVP_PKEY_base_id(evp) != EVP_PKEY_EC)
		return;

	ec = EVP_PKEY_get1_EC_KEY(evp);
	pkcs11_set_ex_data_ec(ec, key);
	EC_KEY_free(ec);
}

/*
 * Get EC key material and stash pointer in ex_data
 * Note we get called twice, once for private key, and once for public
 * We need to get the EC_PARAMS and EC_POINT into both,
 * as lib11 dates from RSA only where all the pub key components
 * were also part of the private key.  With EC the point
 * is not in the private key, and the params may or may not be.
 *
 */
static EVP_PKEY *pkcs11_get_evp_key_ec(PKCS11_KEY *key)
{
	EVP_PKEY *pk;
	EC_KEY *ec;

	ec = pkcs11_get_ec(key);
	if (ec == NULL)
		return NULL;
	pk = EVP_PKEY_new();
	if (pk == NULL) {
		EC_KEY_free(ec);
		return NULL;
	}
	EVP_PKEY_set1_EC_KEY(pk, ec); /* Also increments the ec ref count */

	if (key->isPrivate) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		EC_KEY_set_method(ec, PKCS11_get_ec_key_method());
#else
		ECDSA_set_method(ec, PKCS11_get_ecdsa_method());
		ECDH_set_method(ec, PKCS11_get_ecdh_method());
#endif
	}
	/* TODO: Retrieve the ECDSA private key object attributes instead,
	 * unless the key has the "sensitive" attribute set */

	pkcs11_set_ex_data_ec(ec, key);
	EC_KEY_free(ec); /* Drops our reference to it */
	return pk;
}

/********** ECDSA signing */

/* Signature size is the issue, will assume the caller has a big buffer! */
/* No padding or other stuff needed.  We can call PKCS11 from here */
static int pkcs11_ecdsa_sign(const unsigned char *msg, unsigned int msg_len,
		unsigned char *sigret, unsigned int *siglen, PKCS11_KEY *key)
{
	int rv;
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_MECHANISM mechanism;
	CK_ULONG ck_sigsize;

	ck_sigsize = *siglen;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_ECDSA;

	CRYPTO_THREAD_write_lock(PRIVCTX(ctx)->rwlock);
	rv = CRYPTOKI_call(ctx,
		C_SignInit(spriv->session, &mechanism, kpriv->object));
	if (!rv && kpriv->always_authenticate == CK_TRUE)
		rv = pkcs11_authenticate(key);
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Sign(spriv->session, (CK_BYTE *)msg, msg_len, sigret, &ck_sigsize));
	CRYPTO_THREAD_unlock(PRIVCTX(ctx)->rwlock);

	if (rv) {
		CKRerr(CKR_F_PKCS11_ECDSA_SIGN, rv);
		return -1;
	}
	*siglen = ck_sigsize;

	return ck_sigsize;
}

/**
 * ECDSA signing method (replaces ossl_ecdsa_sign_sig)
 *
 *  @param  dgst     hash value to sign
 *  @param  dlen     length of the hash value
 *  @param  kinv     precomputed inverse k (from the sign_setup method)
 *  @param  rp       precomputed rp (from the sign_setup method)
 *  @param  ec       private EC signing key
 *  @return pointer to a ECDSA_SIG structure or NULL if an error occurred
 */
static ECDSA_SIG *pkcs11_ecdsa_sign_sig(const unsigned char *dgst, int dlen,
		const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *ec)
{
	unsigned char sigret[512]; /* HACK for now */
	ECDSA_SIG *sig;
	PKCS11_KEY *key;
	unsigned int siglen;
	BIGNUM *r, *s, *order;

	(void)kinv; /* Precomputed values are not used for PKCS#11 */
	(void)rp; /* Precomputed values are not used for PKCS#11 */

	key = pkcs11_get_ex_data_ec(ec);
	if (check_key_fork(key) < 0) {
		sign_sig_fn orig_sign_sig;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		const EC_KEY_METHOD *meth = EC_KEY_OpenSSL();
		EC_KEY_METHOD_get_sign((EC_KEY_METHOD *)meth,
			NULL, NULL, &orig_sign_sig);
#else
		const ECDSA_METHOD *meth = ECDSA_OpenSSL();
		orig_sign_sig = meth->ecdsa_do_sign;
#endif
		return orig_sign_sig(dgst, dlen, kinv, rp, ec);
	}

	/* Truncate digest if its byte size is longer than needed */
	order = BN_new();
	if (order) {
		const EC_GROUP *group = EC_KEY_get0_group(ec);
		if (group && EC_GROUP_get_order(group, order, NULL)) {
			int klen = BN_num_bits(order);
			if (klen < 8*dlen)
				dlen = (klen+7)/8;
		}
		BN_free(order);
	}

	siglen = sizeof sigret;
	if (pkcs11_ecdsa_sign(dgst, dlen, sigret, &siglen, key) <= 0)
		return NULL;

	r = BN_bin2bn(sigret, siglen/2, NULL);
	s = BN_bin2bn(sigret + siglen/2, siglen/2, NULL);
	sig = ECDSA_SIG_new();
	if (sig == NULL)
		return NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
	ECDSA_SIG_set0(sig, r, s);
#else
	BN_free(sig->r);
	sig->r = r;
	BN_free(sig->s);
	sig->s = s;
#endif
	return sig;
}

/********** ECDH key derivation */

static CK_ECDH1_DERIVE_PARAMS *pkcs11_ecdh_params_alloc(
		const EC_GROUP *group, const EC_POINT *point)
{
	CK_ECDH1_DERIVE_PARAMS *parms;
	size_t len;
	unsigned char *buf = NULL;

	if (group == NULL || point == NULL)
		return NULL;
	len = EC_POINT_point2oct(group, point,
		POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	if (len == 0)
		return NULL;
	buf = OPENSSL_malloc(len);
	if (buf == NULL)
		return NULL;
	len = EC_POINT_point2oct(group, point,
		POINT_CONVERSION_UNCOMPRESSED, buf, len, NULL);
	if (len == 0) {
		OPENSSL_free(buf);
		return NULL;
	}

	parms = OPENSSL_malloc(sizeof(CK_ECDH1_DERIVE_PARAMS));
	if (parms == NULL) {
		OPENSSL_free(buf);
		return NULL;
	}
	parms->kdf = CKD_NULL;
	parms->pSharedData = NULL;
	parms->ulSharedDataLen = 0;
	parms->pPublicData = buf;
	parms->ulPublicDataLen = len;
	return parms;
}

static void pkcs11_ecdh_params_free(CK_ECDH1_DERIVE_PARAMS *parms)
{
	OPENSSL_free(parms->pPublicData);
	OPENSSL_free(parms);
}

/* initial code will only support what is needed for pkcs11_ec_ckey
 * i.e. CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE
 * and CK_EC_KDF_TYPE  supported by token
 * The secret key object is deleted
 *
 * In future CKM_ECMQV_DERIVE with CK_ECMQV_DERIVE_PARAMS
 * could also be supported, and the secret key object could be returned.
 */
static int pkcs11_ecdh_derive(unsigned char **out, size_t *outlen,
		const unsigned long ecdh_mechanism,
		const void *ec_params,
		void *outnewkey,
		PKCS11_KEY *key)
{
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_CTX *ctx = KEY2CTX(key);
	PKCS11_TOKEN *token = KEY2TOKEN(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_MECHANISM mechanism;
	int rv;

	CK_BBOOL true = TRUE;
	CK_BBOOL false = FALSE;
	CK_OBJECT_HANDLE newkey = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS newkey_class= CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	CK_OBJECT_HANDLE *tmpnewkey = (CK_OBJECT_HANDLE *)outnewkey;
	CK_ATTRIBUTE newkey_template[] = {
		{CKA_TOKEN, &false, sizeof(false)}, /* session only object */
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
		{CKA_ENCRYPT, &true, sizeof(true)},
		{CKA_DECRYPT, &true, sizeof(true)}
	};

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism  = ecdh_mechanism;
	mechanism.pParameter =  (void*)ec_params;
	switch (ecdh_mechanism) {
		case CKM_ECDH1_DERIVE:
		case CKM_ECDH1_COFACTOR_DERIVE:
			mechanism.ulParameterLen  = sizeof(CK_ECDH1_DERIVE_PARAMS);
			break;
#if 0
		/* TODO */
		case CK_ECMQV_DERIVE_PARAMS:
			mechanism.ulParameterLen  = sizeof(CK_ECMQV_DERIVE_PARAMS);
			break;
#endif
		default:
			P11err(P11_F_PKCS11_ECDH_DERIVE, P11_R_NOT_SUPPORTED);
			return -1;
	}

	rv = CRYPTOKI_call(ctx, C_DeriveKey(spriv->session, &mechanism, kpriv->object, newkey_template, 5, &newkey));
	CRYPTOKI_checkerr(CKR_F_PKCS11_ECDH_DERIVE, rv);

	/* Return the value of the secret key and/or the object handle of the secret key */
	if (out && outlen) { /* pkcs11_ec_ckey only asks for the value */
		if (pkcs11_getattr_alloc(token, newkey, CKA_VALUE, out, outlen)) {
			CKRerr(CKR_F_PKCS11_ECDH_DERIVE, CKR_ATTRIBUTE_VALUE_INVALID);
			CRYPTOKI_call(ctx, C_DestroyObject(spriv->session, newkey));
			return -1;
		}
	}
	if (tmpnewkey) /* For future use (not used by pkcs11_ec_ckey) */
		*tmpnewkey = newkey;
	else /* Destroy the temporary key */
		CRYPTOKI_call(ctx, C_DestroyObject(spriv->session, newkey));

	return 0;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)

/**
 * ECDH key derivation method (replaces ossl_ecdh_compute_key)
 * Implementation for OpenSSL 1.1.0-pre4 and later
 *
 * @param  out        derived key
 * @param  outlen     derived key length
 * @param  peer_point public key point
 * @param  ecdh       private key
 * @return 1 on success or 0 on error
 */
static int pkcs11_ec_ckey(unsigned char **out, size_t *outlen,
		const EC_POINT *peer_point, const EC_KEY *ecdh)
{
	PKCS11_KEY *key;
	CK_ECDH1_DERIVE_PARAMS *parms;
	unsigned char *buf = NULL;
	size_t buflen;
	int rv;

	key = pkcs11_get_ex_data_ec(ecdh);
	if (check_key_fork(key) < 0)
		return ossl_ecdh_compute_key(out, outlen, peer_point, ecdh);

	/* both peer and ecdh use same group parameters */
	parms = pkcs11_ecdh_params_alloc(EC_KEY_get0_group(ecdh), peer_point);
	if (parms == NULL)
		return 0;
	rv = pkcs11_ecdh_derive(&buf, &buflen, CKM_ECDH1_DERIVE, parms, NULL, key);
	pkcs11_ecdh_params_free(parms);
	if (rv < 0)
		return 0;

	*out = buf;
	*outlen = buflen;
	return 1;
}

#else

/**
 * ECDH key derivation method (replaces ossl_ecdh_compute_key)
 * Implementation for OpenSSL 1.1.0-pre3 and earlier
 *
 * @param  out        derived key
 * @param  outlen     derived key length
 * @param  peer_point public key point
 * @param  ecdh       private key
 * @param  KCF        key derivation function
 * @return the length of the derived key or -1 if an error occurred
 */
static int pkcs11_ec_ckey(void *out, size_t outlen,
		const EC_POINT *peer_point, const EC_KEY *ecdh,
		void *(*KDF)(const void *, size_t, void *, size_t *))
{
	PKCS11_KEY *key;
	CK_ECDH1_DERIVE_PARAMS *parms;
	unsigned char *buf = NULL;
	size_t buflen;
	int rv;

	key = pkcs11_get_ex_data_ec(ecdh);
	if (check_key_fork(key) < 0)
		return ossl_ecdh_compute_key(out, outlen, peer_point, ecdh, KDF);

	/* both peer and ecdh use same group parameters */
	parms = pkcs11_ecdh_params_alloc(EC_KEY_get0_group(ecdh), peer_point);
	if (parms == NULL)
		return -1;
	rv = pkcs11_ecdh_derive(&buf, &buflen, CKM_ECDH1_DERIVE, parms, NULL, key);
	pkcs11_ecdh_params_free(parms);
	if (rv < 0)
		return -1;

	if (KDF) {
		if (KDF(buf, buflen, out, &outlen) == NULL) {
			OPENSSL_free(buf);
			return -1;
		}
	} else {
		if (outlen > buflen)
			outlen = buflen;
		memcpy(out, buf, outlen);
	}
	OPENSSL_free(buf);
	return outlen;
}

#endif

/********** Set OpenSSL EC methods */

/*
 * Overload the default OpenSSL methods for ECDSA
 * If OpenSSL supports ECDSA_METHOD_new we will use it.
 * First introduced in 1.0.2, changed in 1.1-pre
 */

/* New way to allocate an ECDSA_METOD object */
/* OpenSSL 1.1 has single method  EC_KEY_METHOD for ECDSA and ECDH */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)

EC_KEY_METHOD *PKCS11_get_ec_key_method(void)
{
	static EC_KEY_METHOD *ops = NULL;
	int (*orig_sign)(int, const unsigned char *, int, unsigned char *,
		unsigned int *, const BIGNUM *, const BIGNUM *, EC_KEY *) = NULL;

	alloc_ec_ex_index();
	if (ops == NULL) {
		ops = EC_KEY_METHOD_new((EC_KEY_METHOD *)EC_KEY_OpenSSL());
		EC_KEY_METHOD_get_sign(ops, &orig_sign, NULL, NULL);
		EC_KEY_METHOD_set_sign(ops, orig_sign, NULL, pkcs11_ecdsa_sign_sig);
		EC_KEY_METHOD_get_compute_key(ops, &ossl_ecdh_compute_key);
		EC_KEY_METHOD_set_compute_key(ops, pkcs11_ec_ckey);
	}
	return ops;
}

/* define old way to keep old engines working without ECDSA */
void *PKCS11_get_ecdsa_method(void)
{
	return NULL;
}

void *PKCS11_get_ecdh_method(void)
{
	return NULL;
}

#else /* OPENSSL_VERSION_NUMBER */

/* define new way to keep new engines from crashing with older libp11 */
void *PKCS11_get_ec_key_method(void)
{
	return NULL;
}

ECDSA_METHOD *PKCS11_get_ecdsa_method(void)
{
	static ECDSA_METHOD *ops = NULL;

	if (ops == NULL) {
		alloc_ec_ex_index();
		ops = ECDSA_METHOD_new((ECDSA_METHOD *)ECDSA_OpenSSL());
		ECDSA_METHOD_set_sign(ops, pkcs11_ecdsa_sign_sig);
	}
	return ops;
}

ECDH_METHOD *PKCS11_get_ecdh_method(void)
{
	static ECDH_METHOD *ops = NULL;

	if (ops == NULL) {
		alloc_ec_ex_index();
		ops = ECDH_METHOD_new((ECDH_METHOD *)ECDH_OpenSSL());
		ECDH_METHOD_get_compute_key(ops, &ossl_ecdh_compute_key);
		ECDH_METHOD_set_compute_key(ops, pkcs11_ec_ckey);
	}
	return ops;
}

#endif /* OPENSSL_VERSION_NUMBER */

PKCS11_KEY_ops pkcs11_ec_ops_s = {
	EVP_PKEY_EC,
	pkcs11_get_evp_key_ec,
	pkcs11_update_ex_data_ec,
};
PKCS11_KEY_ops *pkcs11_ec_ops = {&pkcs11_ec_ops_s};

#else /* OPENSSL_NO_EC */

PKCS11_KEY_ops *pkcs11_ec_ops = {NULL};

/* if not built with EC or OpenSSL does not support ECDSA
 * add these routines so engine_pkcs11 can be built now and not
 * require further changes */
#warning "ECDSA support not built with libp11"

ECDSA_METHOD *PKCS11_get_ecdsa_method(void)
{
	return NULL;
}

#endif /* OPENSSL_NO_EC */

/* TODO: remove this function in libp11 0.5.0 */
void PKCS11_ecdsa_method_free(void)
{
	/* no op */
}

#define CKR_LIB_NAME "PKCS#11 module"

/* BEGIN ERROR CODES */
#ifndef NO_ERR

# define ERR_FUNC(func) ERR_PACK(0,func,0)
# define ERR_REASON(reason) ERR_PACK(0,0,reason)

static ERR_STRING_DATA CKR_str_functs[] = {
    {ERR_FUNC(CKR_F_PKCS11_CHANGE_PIN), "pkcs11_change_pin"},
    {ERR_FUNC(CKR_F_PKCS11_CHECK_TOKEN), "pkcs11_check_token"},
    {ERR_FUNC(CKR_F_PKCS11_CTX_LOAD), "pkcs11_CTX_load"},
    {ERR_FUNC(CKR_F_PKCS11_ECDH_DERIVE), "pkcs11_ecdh_derive"},
    {ERR_FUNC(CKR_F_PKCS11_ECDSA_SIGN), "pkcs11_ecdsa_sign"},
    {ERR_FUNC(CKR_F_PKCS11_ENUMERATE_SLOTS), "pkcs11_enumerate_slots"},
    {ERR_FUNC(CKR_F_PKCS11_FIND_CERTS), "pkcs11_find_certs"},
    {ERR_FUNC(CKR_F_PKCS11_FIND_KEYS), "pkcs11_find_keys"},
    {ERR_FUNC(CKR_F_PKCS11_GENERATE_RANDOM), "pkcs11_generate_random"},
    {ERR_FUNC(CKR_F_PKCS11_GETATTR_ALLOC), "pkcs11_getattr_alloc"},
    {ERR_FUNC(CKR_F_PKCS11_GETATTR_BN), "pkcs11_getattr_bn"},
    {ERR_FUNC(CKR_F_PKCS11_GETATTR_INT), "pkcs11_getattr_int"},
    {ERR_FUNC(CKR_F_PKCS11_INIT_PIN), "pkcs11_init_pin"},
    {ERR_FUNC(CKR_F_PKCS11_INIT_SLOT), "pkcs11_init_slot"},
    {ERR_FUNC(CKR_F_PKCS11_INIT_TOKEN), "pkcs11_init_token"},
    {ERR_FUNC(CKR_F_PKCS11_IS_LOGGED_IN), "pkcs11_is_logged_in"},
    {ERR_FUNC(CKR_F_PKCS11_LOGIN), "pkcs11_login"},
    {ERR_FUNC(CKR_F_PKCS11_LOGOUT), "pkcs11_logout"},
    {ERR_FUNC(CKR_F_PKCS11_NEXT_CERT), "pkcs11_next_cert"},
    {ERR_FUNC(CKR_F_PKCS11_NEXT_KEY), "pkcs11_next_key"},
    {ERR_FUNC(CKR_F_PKCS11_OPEN_SESSION), "pkcs11_open_session"},
    {ERR_FUNC(CKR_F_PKCS11_PRIVATE_DECRYPT), "pkcs11_private_decrypt"},
    {ERR_FUNC(CKR_F_PKCS11_PRIVATE_ENCRYPT), "pkcs11_private_encrypt"},
    {ERR_FUNC(CKR_F_PKCS11_RELOAD_KEY), "pkcs11_reload_key"},
    {ERR_FUNC(CKR_F_PKCS11_REOPEN_SESSION), "pkcs11_reopen_session"},
    {ERR_FUNC(CKR_F_PKCS11_SEED_RANDOM), "pkcs11_seed_random"},
    {ERR_FUNC(CKR_F_PKCS11_STORE_CERTIFICATE), "pkcs11_store_certificate"},
    {ERR_FUNC(CKR_F_PKCS11_STORE_KEY), "pkcs11_store_key"},
	{0, NULL}
};

static ERR_STRING_DATA CKR_str_reasons[] = {
	{CKR_CANCEL, "Cancel"},
	{CKR_HOST_MEMORY, "Host memory error"},
	{CKR_SLOT_ID_INVALID, "Invalid slot ID"},
	{CKR_GENERAL_ERROR, "General Error"},
	{CKR_FUNCTION_FAILED, "Function failed"},
	{CKR_ARGUMENTS_BAD, "Invalid arguments"},
	{CKR_NO_EVENT, "No event"},
	{CKR_NEED_TO_CREATE_THREADS, "Need to create threads"},
	{CKR_CANT_LOCK, "Cannott lock"},
	{CKR_ATTRIBUTE_READ_ONLY, "Attribute read only"},
	{CKR_ATTRIBUTE_SENSITIVE, "Attribute sensitive"},
	{CKR_ATTRIBUTE_TYPE_INVALID, "Attribute type invalid"},
	{CKR_ATTRIBUTE_VALUE_INVALID, "Attribute value invalid"},
	{CKR_DATA_INVALID, "Data invalid"},
	{CKR_DATA_LEN_RANGE, "Data len range"},
	{CKR_DEVICE_ERROR, "Device error"},
	{CKR_DEVICE_MEMORY, "Device memory"},
	{CKR_DEVICE_REMOVED, "Device removed"},
	{CKR_ENCRYPTED_DATA_INVALID, "Encrypted data invalid"},
	{CKR_ENCRYPTED_DATA_LEN_RANGE, "Encrypted data len range"},
	{CKR_FUNCTION_CANCELED, "Function canceled"},
	{CKR_FUNCTION_NOT_PARALLEL, "Function not parallel"},
	{CKR_FUNCTION_NOT_SUPPORTED, "Function not supported"},
	{CKR_KEY_HANDLE_INVALID, "Key handle invalid"},
	{CKR_KEY_SIZE_RANGE, "Key size range"},
	{CKR_KEY_TYPE_INCONSISTENT, "Key type inconsistent"},
	{CKR_KEY_NOT_NEEDED, "Key not needed"},
	{CKR_KEY_CHANGED, "Key changed"},
	{CKR_KEY_NEEDED, "Key needed"},
	{CKR_KEY_INDIGESTIBLE, "Key indigestible"},
	{CKR_KEY_FUNCTION_NOT_PERMITTED, "Key function not permitted"},
	{CKR_KEY_NOT_WRAPPABLE, "Key not wrappable"},
	{CKR_KEY_UNEXTRACTABLE, "Key unextractable"},
	{CKR_MECHANISM_INVALID, "Mechanism invalid"},
	{CKR_MECHANISM_PARAM_INVALID, "Mechanism param invalid"},
	{CKR_OBJECT_HANDLE_INVALID, "Object handle invalid"},
	{CKR_OPERATION_ACTIVE, "Operation active"},
	{CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized"},
	{CKR_PIN_INCORRECT, "PIN incorrect"},
	{CKR_PIN_INVALID, "PIN invalid"},
	{CKR_PIN_LEN_RANGE, "Invalid PIN length"},
	{CKR_PIN_EXPIRED, "PIN expired"},
	{CKR_PIN_LOCKED, "PIN locked"},
	{CKR_SESSION_CLOSED, "Session closed"},
	{CKR_SESSION_COUNT, "Session count"},
	{CKR_SESSION_HANDLE_INVALID, "Session handle invalid"},
	{CKR_SESSION_PARALLEL_NOT_SUPPORTED, "Session parallel not supported"},
	{CKR_SESSION_READ_ONLY, "Session read only"},
	{CKR_SESSION_EXISTS, "Session exists"},
	{CKR_SESSION_READ_ONLY_EXISTS, "Read-only session exists"},
	{CKR_SESSION_READ_WRITE_SO_EXISTS, "Read/write SO session exists"},
	{CKR_SIGNATURE_INVALID, "Signature invalid"},
	{CKR_SIGNATURE_LEN_RANGE, "Signature len range"},
	{CKR_TEMPLATE_INCOMPLETE, "Incomplete template"},
	{CKR_TEMPLATE_INCONSISTENT, "Inconsistent template"},
	{CKR_TOKEN_NOT_PRESENT, "No PKCS#11 token present"},
	{CKR_TOKEN_NOT_RECOGNIZED, "PKCS#11 token not recognized"},
	{CKR_TOKEN_WRITE_PROTECTED, "Token write protected"},
	{CKR_UNWRAPPING_KEY_HANDLE_INVALID, "Unwrapping key handle invalid"},
	{CKR_UNWRAPPING_KEY_SIZE_RANGE, "Unwrapping key size range"},
	{CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, "Unwrapping key type inconsistent"},
	{CKR_USER_ALREADY_LOGGED_IN, "User already logged in"},
	{CKR_USER_NOT_LOGGED_IN, "User not logged in"},
	{CKR_USER_PIN_NOT_INITIALIZED, "User pin not initialized"},
	{CKR_USER_TYPE_INVALID, "User type invalid"},
	{CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "User another is already logged in"},
	{CKR_USER_TOO_MANY_TYPES, "User too many types"},
	{CKR_WRAPPED_KEY_INVALID, "Wrapped key invalid"},
	{CKR_WRAPPED_KEY_LEN_RANGE, "Wrapped key len range"},
	{CKR_WRAPPING_KEY_HANDLE_INVALID, "Wrapping key handle invalid"},
	{CKR_WRAPPING_KEY_SIZE_RANGE, "Wrapping key size range"},
	{CKR_WRAPPING_KEY_TYPE_INCONSISTENT, "Wrapping key type inconsistent"},
	{CKR_RANDOM_SEED_NOT_SUPPORTED, "Random seed not supported"},
	{CKR_RANDOM_NO_RNG, "Random no rng"},
	{CKR_DOMAIN_PARAMS_INVALID, "Domain params invalid"},
	{CKR_BUFFER_TOO_SMALL, "Buffer too small"},
	{CKR_SAVED_STATE_INVALID, "Saved state invalid"},
	{CKR_INFORMATION_SENSITIVE, "Information sensitive"},
	{CKR_STATE_UNSAVEABLE, "State unsaveable"},
	{CKR_CRYPTOKI_NOT_INITIALIZED, "Cryptoki not initialized"},
	{CKR_CRYPTOKI_ALREADY_INITIALIZED, "Cryptoki already initialized"},
	{CKR_MUTEX_BAD, "Mutex bad"},
	{CKR_MUTEX_NOT_LOCKED, "Mutex not locked"},
	{CKR_VENDOR_DEFINED, "Vendor defined"},
	{0, NULL}
};
#endif

#ifdef CKR_LIB_NAME
static ERR_STRING_DATA CKR_lib_name[] = {
	{0, CKR_LIB_NAME},
	{0, NULL}
};
#endif

static int CKR_lib_error_code = 0;
static int CKR_error_init = 1;

int ERR_load_CKR_strings(void)
{
	if (CKR_lib_error_code == 0)
		CKR_lib_error_code = ERR_get_next_error_library();

	if (CKR_error_init) {
		CKR_error_init = 0;
#ifndef OPENSSL_NO_ERR
		ERR_load_strings(CKR_lib_error_code, CKR_str_functs);
		ERR_load_strings(CKR_lib_error_code, CKR_str_reasons);
#endif

#ifdef CKR_LIB_NAME
		CKR_lib_name->error = ERR_PACK(CKR_lib_error_code, 0, 0);
		ERR_load_strings(0, CKR_lib_name);
#endif
	}
	return 1;
}

void ERR_unload_CKR_strings(void)
{
	if (CKR_error_init == 0) {
#ifndef OPENSSL_NO_ERR
		ERR_unload_strings(CKR_lib_error_code, CKR_str_functs);
		ERR_unload_strings(CKR_lib_error_code, CKR_str_reasons);
#endif

#ifdef CKR_LIB_NAME
		ERR_unload_strings(0, CKR_lib_name);
#endif
		CKR_error_init = 1;
	}
}

void ERR_CKR_error(int function, int reason, char *file, int line)
{
	if (CKR_lib_error_code == 0)
		CKR_lib_error_code = ERR_get_next_error_library();
	ERR_PUT_error(CKR_lib_error_code, function, reason, file, line);
}

int ERR_get_CKR_code(void)
{
	if (CKR_lib_error_code == 0)
		CKR_lib_error_code = ERR_get_next_error_library();
	return CKR_lib_error_code;
}

static int pkcs11_find_certs(PKCS11_TOKEN *);
static int pkcs11_next_cert(PKCS11_CTX *, PKCS11_TOKEN *, CK_SESSION_HANDLE);
static int pkcs11_init_cert(PKCS11_CTX *ctx, PKCS11_TOKEN *token,
	CK_SESSION_HANDLE session, CK_OBJECT_HANDLE o, PKCS11_CERT **);

/*
 * Enumerate all certs on the card
 */
int pkcs11_enumerate_certs(PKCS11_TOKEN *token,
		PKCS11_CERT **certp, unsigned int *countp)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);
	int rv;

	/* Make sure we have a session */
	if (!spriv->haveSession && PKCS11_open_session(slot, 0))
		return -1;

	CRYPTO_THREAD_write_lock(cpriv->rwlock);
	rv = pkcs11_find_certs(token);
	CRYPTO_THREAD_unlock(cpriv->rwlock);
	if (rv < 0) {
		pkcs11_destroy_certs(token);
		return -1;
	}

	if (certp)
		*certp = tpriv->certs;
	if (countp)
		*countp = tpriv->ncerts;
	return 0;
}

/**
 * Remove a certificate from the associated token
 */ 
int pkcs11_remove_certificate(PKCS11_CERT *cert){
	PKCS11_SLOT *slot = CERT2SLOT(cert);
	PKCS11_CTX *ctx = CERT2CTX(cert);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_OBJECT_HANDLE obj;
	CK_ULONG count;
	CK_ATTRIBUTE search_parameters[32];
	unsigned int n = 0;
	int rv;

	/* First, make sure we have a session */
	if (!spriv->haveSession && PKCS11_open_session(slot, 1)){
		return -1;
	}
	
	pkcs11_addattr_int(search_parameters + n++, CKA_CLASS, CKO_CERTIFICATE);
	if (cert->id && cert->id_len){
		pkcs11_addattr(search_parameters + n++, CKA_ID, cert->id, cert->id_len);
	}
	if (cert->label){
	 	pkcs11_addattr_s(search_parameters + n++, CKA_LABEL, cert->label);
	}

	rv = CRYPTOKI_call(ctx,
		C_FindObjectsInit(spriv->session, search_parameters, n));
	CRYPTOKI_checkerr(CKR_F_PKCS11_REMOVE_CERTIFICATE, rv);
	
	rv = CRYPTOKI_call(ctx, C_FindObjects(spriv->session, &obj, 1, &count));
	CRYPTOKI_checkerr(CKR_F_PKCS11_REMOVE_CERTIFICATE, rv);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(spriv->session));
	if (count!=1){
		pkcs11_zap_attrs(search_parameters, n);
		return -1;
	}
	rv = CRYPTOKI_call(ctx, C_DestroyObject(spriv->session, obj));
	if (rv != CKR_OK){
		pkcs11_zap_attrs(search_parameters, n);
		return -1;
	}
	pkcs11_zap_attrs(search_parameters, n);
	return 0;
}

/*
 * Find certificate matching a key
 */
PKCS11_CERT *pkcs11_find_certificate(PKCS11_KEY *key)
{
	PKCS11_KEY_private *kpriv;
	PKCS11_CERT_private *cpriv;
	PKCS11_CERT *cert;
	unsigned int n, count;

	kpriv = PRIVKEY(key);
	if (PKCS11_enumerate_certs(KEY2TOKEN(key), &cert, &count))
		return NULL;
	for (n = 0; n < count; n++, cert++) {
		cpriv = PRIVCERT(cert);
		if (cpriv->id_len == kpriv->id_len
				&& !memcmp(cpriv->id, kpriv->id, kpriv->id_len))
			return cert;
	}
	return NULL;
}

/*
 * Find all certs of a given type (public or private)
 */
static int pkcs11_find_certs(PKCS11_TOKEN *token)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_OBJECT_CLASS cert_search_class;
	CK_ATTRIBUTE cert_search_attrs[] = {
		{CKA_CLASS, &cert_search_class, sizeof(cert_search_class)},
	};
	int rv, res = -1;

	/* Tell the PKCS11 lib to enumerate all matching objects */
	cert_search_class = CKO_CERTIFICATE;
	rv = CRYPTOKI_call(ctx, C_FindObjectsInit(spriv->session, cert_search_attrs, 1));
	CRYPTOKI_checkerr(CKR_F_PKCS11_FIND_CERTS, rv);

	do {
		res = pkcs11_next_cert(ctx, token, spriv->session);
	} while (res == 0);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(spriv->session));

	return (res < 0) ? -1 : 0;
}

static int pkcs11_next_cert(PKCS11_CTX *ctx, PKCS11_TOKEN *token,
		CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE obj;
	CK_ULONG count;
	int rv;

	/* Get the next matching object */
	rv = CRYPTOKI_call(ctx, C_FindObjects(session, &obj, 1, &count));
	CRYPTOKI_checkerr(CKR_F_PKCS11_NEXT_CERT, rv);

	if (count == 0)
		return 1;

	if (pkcs11_init_cert(ctx, token, session, obj, NULL))
		return -1;

	return 0;
}

static int pkcs11_init_cert(PKCS11_CTX *ctx, PKCS11_TOKEN *token,
		CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj, PKCS11_CERT ** ret)
{
	PKCS11_TOKEN_private *tpriv;
	PKCS11_CERT_private *cpriv;
	PKCS11_CERT *cert, *tmp;
	unsigned char *data;
	CK_CERTIFICATE_TYPE cert_type;
	size_t size;
	int i;

	(void)ctx;
	(void)session;

	/* Ignore unknown certificate types */
	size = sizeof(CK_CERTIFICATE_TYPE);
	if (pkcs11_getattr_var(token, obj, CKA_CERTIFICATE_TYPE, (CK_BYTE *)&cert_type, &size))
		return -1;
	if (cert_type != CKC_X_509)
		return 0;

	/* Prevent re-adding existing PKCS#11 object handles */
	/* TODO: Rewrite the O(n) algorithm as O(log n),
	 * or it may be too slow with a large number of certificates */
	for (i=0; i < PRIVTOKEN(token)->ncerts; ++i)
		if (PRIVCERT(PRIVTOKEN(token)->certs + i)->object == obj)
			return 0;

	/* Allocate memory */
	cpriv = OPENSSL_malloc(sizeof(PKCS11_CERT_private));
	if (cpriv == NULL)
		return -1;
	memset(cpriv, 0, sizeof(PKCS11_CERT_private));
	tpriv = PRIVTOKEN(token);
	tmp = OPENSSL_realloc(tpriv->certs,
		(tpriv->ncerts + 1) * sizeof(PKCS11_CERT));
	if (tmp == NULL)
		return -1;
	tpriv->certs = tmp;
	cert = tpriv->certs + tpriv->ncerts++;
	memset(cert, 0, sizeof(PKCS11_CERT));

	/* Fill public properties */
	pkcs11_getattr_alloc(token, obj, CKA_LABEL, (CK_BYTE **)&cert->label, NULL);
	size = 0;
	if (!pkcs11_getattr_alloc(token, obj, CKA_VALUE, &data, &size)) {
		const unsigned char *p = data;

		cert->x509 = d2i_X509(NULL, &p, (long)size);
		OPENSSL_free(data);
	}
	cert->id_len = 0;
	pkcs11_getattr_alloc(token, obj, CKA_ID, &cert->id, &cert->id_len);

	/* Fill private properties */
	cert->_private = cpriv;
	cpriv->object = obj;
	cpriv->parent = token;
	cpriv->id_len = sizeof cpriv->id;
	if (pkcs11_getattr_var(token, obj, CKA_ID, cpriv->id, &cpriv->id_len))
		cpriv->id_len = 0;

	if (ret)
		*ret = cert;
	return 0;
}

/*
 * Destroy all certs
 */
void pkcs11_destroy_certs(PKCS11_TOKEN *token)
{
	PKCS11_TOKEN_private *tpriv = PRIVTOKEN(token);

	while (tpriv->ncerts > 0) {
		PKCS11_CERT *cert = &tpriv->certs[--(tpriv->ncerts)];

		if (cert->x509)
			X509_free(cert->x509);
		OPENSSL_free(cert->label);
		if (cert->id)
			OPENSSL_free(cert->id);
		if (cert->_private != NULL)
			OPENSSL_free(cert->_private);
	}
	if (tpriv->certs)
		OPENSSL_free(tpriv->certs);
	tpriv->certs = NULL;
	tpriv->ncerts = 0;
}

/*
 * Store certificate
 */
int pkcs11_store_certificate(PKCS11_TOKEN *token, X509 *x509, char *label,
		unsigned char *id, size_t id_len, PKCS11_CERT ** ret_cert)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[32];
	unsigned int n = 0;
	int rv;
	const EVP_MD* evp_md;
	CK_MECHANISM_TYPE ckm_md;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len;

	/* First, make sure we have a session */
	if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 1))
		return -1;

	/* Now build the template */
	pkcs11_addattr_int(attrs + n++, CKA_CLASS, CKO_CERTIFICATE);
	pkcs11_addattr_bool(attrs + n++, CKA_TOKEN, TRUE);
	pkcs11_addattr_int(attrs + n++, CKA_CERTIFICATE_TYPE, CKC_X_509);
	pkcs11_addattr_obj(attrs + n++, CKA_SUBJECT,
		(pkcs11_i2d_fn)i2d_X509_NAME, X509_get_subject_name(x509));
	pkcs11_addattr_obj(attrs + n++, CKA_ISSUER,
		(pkcs11_i2d_fn)i2d_X509_NAME, X509_get_issuer_name(x509));

	/* Get digest algorithm from x509 certificate */
	evp_md = EVP_get_digestbynid(X509_get_signature_nid(x509));
	switch (EVP_MD_type(evp_md)) {
	default:
	case NID_sha1:
		ckm_md = CKM_SHA_1;
		break;
	case NID_sha224:
		ckm_md = CKM_SHA224;
		break;
	case NID_sha256:
		ckm_md = CKM_SHA256;
		break;
	case NID_sha512:
		ckm_md = CKM_SHA512;
		break;
	case NID_sha384:
		ckm_md = CKM_SHA384;
		break;
	}

	/* Set hash algorithm; default is SHA-1 */
	pkcs11_addattr_int(attrs + n++, CKA_NAME_HASH_ALGORITHM, ckm_md);
	if(X509_pubkey_digest(x509,evp_md,md,&md_len))
		pkcs11_addattr(attrs + n++, CKA_HASH_OF_SUBJECT_PUBLIC_KEY,md,md_len);

	pkcs11_addattr_obj(attrs + n++, CKA_VALUE, (pkcs11_i2d_fn)i2d_X509, x509);
	if (label)
		pkcs11_addattr_s(attrs + n++, CKA_LABEL, label);
	if (id && id_len)
		pkcs11_addattr(attrs + n++, CKA_ID, id, id_len);

	/* Now call the pkcs11 module to create the object */
	rv = CRYPTOKI_call(ctx, C_CreateObject(spriv->session, attrs, n, &object));

	/* Zap all memory allocated when building the template */
	pkcs11_zap_attrs(attrs, n);

	CRYPTOKI_checkerr(CKR_F_PKCS11_STORE_CERTIFICATE, rv);

	/* Gobble the key object */
	return pkcs11_init_cert(ctx, token, spriv->session, object, ret_cert);
}

/*
 * Query pkcs11 attributes
 */
static int pkcs11_getattr_int(PKCS11_CTX *ctx, CK_SESSION_HANDLE session,
		CK_OBJECT_HANDLE o, CK_ATTRIBUTE_TYPE type, CK_BYTE *value,
		size_t *size)
{
	CK_ATTRIBUTE templ;
	int rv;

	templ.type = type;
	templ.pValue = value;
	templ.ulValueLen = *size;

	rv = CRYPTOKI_call(ctx, C_GetAttributeValue(session, o, &templ, 1));
	CRYPTOKI_checkerr(CKR_F_PKCS11_GETATTR_INT, rv);

	*size = templ.ulValueLen;
	return 0;
}

int pkcs11_getattr_var(PKCS11_TOKEN *token, CK_OBJECT_HANDLE object,
		unsigned int type, CK_BYTE *value, size_t *size)
{
	return pkcs11_getattr_int(TOKEN2CTX(token),
		PRIVSLOT(TOKEN2SLOT(token))->session,
		object, type, value, size);
}

int pkcs11_getattr_val(PKCS11_TOKEN *token, CK_OBJECT_HANDLE object,
		unsigned int type, void *value, size_t size)
{
	return pkcs11_getattr_var(token, object, type, value, &size);
}

int pkcs11_getattr_alloc(PKCS11_TOKEN *token, CK_OBJECT_HANDLE object,
		unsigned int type, CK_BYTE **value, size_t *size)
{
	CK_BYTE *data;
	size_t len = 0;

	if (pkcs11_getattr_var(token, object, type, NULL, &len))
		return -1;
	data = OPENSSL_malloc(len+1);
	if (data == NULL) {
		CKRerr(CKR_F_PKCS11_GETATTR_ALLOC, CKR_HOST_MEMORY);
		return -1;
	}
	memset(data, 0, len+1); /* also null-terminate the allocated data */
	if (pkcs11_getattr_var(token, object, type, data, &len)) {
		OPENSSL_free(data);
		return -1;
	}
	if (value)
		*value = data;
	if (size)
		*size = len;
	return 0;
}

int pkcs11_getattr_bn(PKCS11_TOKEN *token, CK_OBJECT_HANDLE object,
		unsigned int type, BIGNUM **bn)
{
	CK_BYTE *binary;
	size_t size;

	size = 0;
	if (pkcs11_getattr_alloc(token, object, type, &binary, &size))
		return -1;
	/*
	 * @ALON: invalid object,
	 * not sure it will survive the ulValueLen->size_t and keep sign at all platforms
	 */
	if (size == (size_t)-1) {
		CKRerr(CKR_F_PKCS11_GETATTR_BN, CKR_ATTRIBUTE_TYPE_INVALID);
		OPENSSL_free(binary);
		return -1;
	}
	*bn = BN_bin2bn(binary, (int)size, *bn);
	OPENSSL_free(binary);
	return *bn ? 0 : -1;
}

/*
 * Add attributes to template
 */
void pkcs11_addattr(CK_ATTRIBUTE_PTR ap, int type, const void *data, size_t size)
{
	ap->type = type;
	ap->pValue = OPENSSL_malloc(size);
	if (ap->pValue == NULL)
		return;
	memcpy(ap->pValue, data, size);
	ap->ulValueLen = size;
}

/* In PKCS11, virtually every integer is a CK_ULONG */
void pkcs11_addattr_int(CK_ATTRIBUTE_PTR ap, int type, unsigned long value)
{
	CK_ULONG ulValue = value;

	pkcs11_addattr(ap, type, &ulValue, sizeof(ulValue));
}

void pkcs11_addattr_bool(CK_ATTRIBUTE_PTR ap, int type, int value)
{
	pkcs11_addattr(ap, type, &value, sizeof(CK_BBOOL));
}

void pkcs11_addattr_s(CK_ATTRIBUTE_PTR ap, int type, const char *s)
{
	pkcs11_addattr(ap, type, s, s ? strlen(s) : 0); /* RFC2279 string an unpadded string of CK_UTF8CHARs with no null-termination */
}

void pkcs11_addattr_bn(CK_ATTRIBUTE_PTR ap, int type, const BIGNUM *bn)
{
	unsigned char temp[1024];
	unsigned int n;

	assert((size_t)BN_num_bytes(bn) <= sizeof(temp));
	n = BN_bn2bin(bn, temp);
	pkcs11_addattr(ap, type, temp, n);
}

void pkcs11_addattr_obj(CK_ATTRIBUTE_PTR ap, int type, pkcs11_i2d_fn enc, void *obj)
{
	unsigned char *p;

	ap->type = type;
	ap->ulValueLen = enc(obj, NULL);
	ap->pValue = OPENSSL_malloc(ap->ulValueLen);
	if (ap->pValue == NULL)
		return;
	p = ap->pValue;
	enc(obj, &p);
}

void pkcs11_zap_attrs(CK_ATTRIBUTE_PTR ap, unsigned int n)
{
	while (n--) {
		if (ap[n].pValue)
			OPENSSL_free(ap[n].pValue);
	}
}

#ifndef _WIN32

#ifndef __STDC_VERSION__
/* older than C90 */
#define inline
#endif /* __STDC_VERSION__ */

#ifdef HAVE___REGISTER_ATFORK

#ifdef __sun
#pragma fini(lib_deinit)
#pragma init(lib_init)
#define _CONSTRUCTOR
#define _DESTRUCTOR
#else /* __sun */
#define _CONSTRUCTOR __attribute__((constructor))
#define _DESTRUCTOR __attribute__((destructor))
#endif /* __sun */

static unsigned int P11_forkid = 0;

inline static unsigned int _P11_get_forkid(void)
{
	return P11_forkid;
}

inline static int _P11_detect_fork(unsigned int forkid)
{
	if (forkid == P11_forkid)
		return 0;
	return 1;
}

static void fork_handler(void)
{
	P11_forkid++;
}

extern int __register_atfork(void (*)(void), void(*)(void), void (*)(void), void *);
extern void *__dso_handle;

_CONSTRUCTOR
int _P11_register_fork_handler(void)
{
	if (__register_atfork(0, 0, fork_handler, __dso_handle) != 0)
		return -1;
	return 0;
}

#else /* HAVE___REGISTER_ATFORK */

inline static unsigned int _P11_get_forkid(void)
{
	return getpid();
}

inline static int _P11_detect_fork(unsigned int forkid)
{
	if (getpid() == forkid)
		return 0;
	return 1;
}

#endif /* HAVE___REGISTER_ATFORK */

#else /* !_WIN32 */

#define _P11_get_forkid() 0
#define _P11_detect_fork(x) 0

#endif /* !_WIN32 */

unsigned int get_forkid()
{
	return _P11_get_forkid();
}

/*
 * PKCS#11 reinitialization after fork
 * It wipes out the internal state of the PKCS#11 library
 * Any libp11 references to this state are no longer valid
 */
static int check_fork_int(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);

	if (_P11_detect_fork(cpriv->forkid)) {
		if (pkcs11_CTX_reload(ctx) < 0)
			return -1;
		cpriv->forkid = _P11_get_forkid();
	}
	return 0;
}

/*
 * PKCS#11 reinitialization after fork
 * Also relogins and reopens the session if needed
 */
static int check_slot_fork_int(PKCS11_SLOT *slot)
{
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	PKCS11_CTX_private *cpriv = PRIVCTX(ctx);

	if (check_fork_int(SLOT2CTX(slot)) < 0)
		return -1;
	if (spriv->forkid != cpriv->forkid) {
		if (spriv->loggedIn) {
			int saved = spriv->haveSession;
			spriv->haveSession = 0;
			spriv->loggedIn = 0;
			if (pkcs11_relogin(slot) < 0)
				return -1;
			spriv->haveSession = saved;
		}
		if (spriv->haveSession) {
			spriv->haveSession = 0;
			if (pkcs11_reopen_session(slot) < 0)
				return -1;
		}
		spriv->forkid = cpriv->forkid;
	}
	return 0;
}

/*
 * PKCS#11 reinitialization after fork
 * Also reloads the key
 */
static int check_key_fork_int(PKCS11_KEY *key)
{
	PKCS11_SLOT *slot = KEY2SLOT(key);
	PKCS11_KEY_private *kpriv = PRIVKEY(key);
	PKCS11_SLOT_private *spriv = PRIVSLOT(slot);

	if (check_slot_fork_int(slot) < 0)
		return -1;
	if (spriv->forkid != kpriv->forkid) {
		pkcs11_reload_key(key);
		kpriv->forkid = spriv->forkid;
	}
	return 0;
}

/*
 * Locking interface to check_fork_int()
 */
int check_fork(PKCS11_CTX *ctx)
{
	PKCS11_CTX_private *cpriv;
	int rv;

	if (ctx == NULL)
		return -1;
	cpriv = PRIVCTX(ctx);
	CRYPTO_THREAD_write_lock(cpriv->rwlock);
	rv = check_fork_int(ctx);
	CRYPTO_THREAD_unlock(cpriv->rwlock);
	return rv;
}

/*
 * Locking interface to check_slot_fork_int()
 */
int check_slot_fork(PKCS11_SLOT *slot)
{
	PKCS11_CTX_private *cpriv;
	int rv;

	if (slot == NULL)
		return -1;
	cpriv = PRIVCTX(SLOT2CTX(slot));
	CRYPTO_THREAD_write_lock(cpriv->rwlock);
	rv = check_slot_fork_int(slot);
	CRYPTO_THREAD_unlock(cpriv->rwlock);
	return rv;
}

/*
 * Reinitialize token (just its slot)
 */
int check_token_fork(PKCS11_TOKEN *token)
{
	if (token == NULL)
		return -1;
	return check_slot_fork(TOKEN2SLOT(token));
}

/*
 * Locking interface to check_key_fork_int()
 */
int check_key_fork(PKCS11_KEY *key)
{
	PKCS11_CTX_private *cpriv;
	int rv;

	if (key == NULL)
		return -1;
	cpriv = PRIVCTX(KEY2CTX(key));
	CRYPTO_THREAD_write_lock(cpriv->rwlock);
	rv = check_key_fork_int(key);
	CRYPTO_THREAD_unlock(cpriv->rwlock);
	return rv;
}

/*
 * Reinitialize cert (just its token)
 */
int check_cert_fork(PKCS11_CERT *cert)
{
	if (cert == NULL)
		return -1;
	return check_token_fork(CERT2TOKEN(cert));
}

#define MAGIC			0xd00bed00

struct sc_pkcs11_module {
	unsigned int _magic;
	void *handle;
};
typedef struct sc_pkcs11_module sc_pkcs11_module_t;

/*
 * Load a module - this will load the shared object, call
 * C_Initialize, and get the list of function pointers
 */
void *
C_LoadModule(const char *mspec, CK_FUNCTION_LIST_PTR_PTR funcs)
{
	sc_pkcs11_module_t *mod;
	CK_RV (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
	int rv;

	if (mspec == NULL)
		return NULL;

	mod = OPENSSL_malloc(sizeof(sc_pkcs11_module_t));
	if (mod == NULL)
		return NULL;
	memset(mod, 0, sizeof(sc_pkcs11_module_t));
	mod->_magic = MAGIC;

#ifdef WIN32
	mod->handle = LoadLibraryA(mspec);
#else
	mod->handle = dlopen(mspec, RTLD_LAZY | RTLD_LOCAL);
#endif

	if (mod->handle == NULL) {
#ifndef WIN32
		fprintf(stderr, "%s\n", dlerror());
#endif
		goto failed;
	}

#ifdef WIN32
	c_get_function_list = (CK_C_GetFunctionList)
		GetProcAddress(mod->handle, "C_GetFunctionList");
#else
	{
		/*
		 * Make compiler happy!
		 */
		void *p = dlsym(mod->handle, "C_GetFunctionList");
		memmove(&c_get_function_list, &p, sizeof(void *));
	}
#endif

	if (c_get_function_list == NULL) {
#ifndef WIN32
		fprintf(stderr, "%s\n", dlerror());
#endif
		goto failed;
	}
	rv = c_get_function_list(funcs);
	if (rv == CKR_OK)
		return mod;

failed:
	C_UnloadModule((void *) mod);
	return NULL;
}

/*
 * Unload a pkcs11 module.
 * The calling application is responsible for cleaning up
 * and calling C_Finalize
 */
CK_RV
C_UnloadModule(void *module)
{
	sc_pkcs11_module_t *mod = (sc_pkcs11_module_t *) module;

	if (mod == NULL || mod->_magic != MAGIC)
		return CKR_ARGUMENTS_BAD;

	if (mod->handle) {
#ifdef WIN32
		FreeLibrary(mod->handle);
#else
		dlclose(mod->handle);
#endif
	}

	memset(mod, 0, sizeof(sc_pkcs11_module_t));
	OPENSSL_free(mod);

	return CKR_OK;
}

static int hex_to_bin(ENGINE_CTX *ctx,
		const char *in, unsigned char *out, size_t *outlen)
{
	size_t left, count = 0;

	if (in == NULL || *in == '\0') {
		*outlen = 0;
		return 1;
	}

	left = *outlen;

	while (*in != '\0') {
		int byte = 0, nybbles = 2;

		while (nybbles-- && *in && *in != ':') {
			char c;
			byte <<= 4;
			c = *in++;
			if ('0' <= c && c <= '9')
				c -= '0';
			else if ('a' <= c && c <= 'f')
				c = c - 'a' + 10;
			else if ('A' <= c && c <= 'F')
				c = c - 'A' + 10;
			else {
				ctx_log(ctx, 0,
					"hex_to_bin(): invalid char '%c' in hex string\n",
					c);
				*outlen = 0;
				return 0;
			}
			byte |= c;
		}
		if (*in == ':')
			in++;
		if (left == 0) {
			ctx_log(ctx, 0, "hex_to_bin(): hex string too long\n");
			*outlen = 0;
			return 0;
		}
		out[count++] = (unsigned char)byte;
		left--;
	}

	*outlen = count;
	return 1;
}

/* parse string containing slot and id information */
int parse_slot_id_string(ENGINE_CTX *ctx,
		const char *slot_id, int *slot,
		unsigned char *id, size_t *id_len, char **label)
{
	int n, i;

	/* support for several formats */
#define HEXDIGITS "01234567890ABCDEFabcdef"
#define DIGITS "0123456789"

	/* first: pure hex number (id, slot is undefined) */
	if (strspn(slot_id, HEXDIGITS) == strlen(slot_id)) {
		/* ah, easiest case: only hex. */
		if ((strlen(slot_id) + 1) / 2 > *id_len) {
			ctx_log(ctx, 0, "ID string too long!\n");
			return 0;
		}
		*slot = -1;
		return hex_to_bin(ctx, slot_id, id, id_len);
	}

	/* second: slot:id. slot is an digital int. */
	if (sscanf(slot_id, "%d", &n) == 1) {
		i = strspn(slot_id, DIGITS);

		if (slot_id[i] != ':') {
			ctx_log(ctx, 0, "Could not parse string!\n");
			return 0;
		}
		i++;
		if (slot_id[i] == 0) {
			*slot = n;
			*id_len = 0;
			return 1;
		}
		if (strspn(slot_id + i, HEXDIGITS) + i != strlen(slot_id)) {
			ctx_log(ctx, 0, "Could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - i + 1) / 2 > *id_len) {
			ctx_log(ctx, 0, "ID string too long!\n");
			return 0;
		}
		*slot = n;
		return hex_to_bin(ctx, slot_id + i, id, id_len);
	}

	/* third: id_<id>, slot is undefined */
	if (strncmp(slot_id, "id_", 3) == 0) {
		if (strspn(slot_id + 3, HEXDIGITS) + 3 != strlen(slot_id)) {
			ctx_log(ctx, 0, "Could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - 3 + 1) / 2 > *id_len) {
			ctx_log(ctx, 0, "ID string too long!\n");
			return 0;
		}
		*slot = -1;
		return hex_to_bin(ctx, slot_id + 3, id, id_len);
	}

	/* label_<label>, slot is undefined */
	if (strncmp(slot_id, "label_", 6) == 0) {
		*slot = -1;
		*label = OPENSSL_strdup(slot_id + 6);
		*id_len = 0;
		return *label != NULL;
	}

	/* last try: it has to be slot_<slot> and then "-id_<cert>" */

	if (strncmp(slot_id, "slot_", 5) != 0) {
		ctx_log(ctx, 0, "Format not recognized!\n");
		return 0;
	}

	/* slot is an digital int. */
	if (sscanf(slot_id + 5, "%d", &n) != 1) {
		ctx_log(ctx, 0, "Could not decode slot number!\n");
		return 0;
	}

	i = strspn(slot_id + 5, DIGITS);

	if (slot_id[i + 5] == 0) {
		*slot = n;
		*id_len = 0;
		return 1;
	}

	if (slot_id[i + 5] != '-') {
		ctx_log(ctx, 0, "Could not parse string!\n");
		return 0;
	}

	i = 5 + i + 1;

	/* now followed by "id_" */
	if (strncmp(slot_id + i, "id_", 3) == 0) {
		if (strspn(slot_id + i + 3, HEXDIGITS) + 3 + i != strlen(slot_id)) {
			ctx_log(ctx, 0, "Could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - i - 3 + 1) / 2 > *id_len) {
			ctx_log(ctx, 0, "ID string too long!\n");
			return 0;
		}
		*slot = n;
		return hex_to_bin(ctx, slot_id + i + 3, id, id_len);
	}

	/* ... or "label_" */
	if (strncmp(slot_id + i, "label_", 6) == 0) {
		*slot = n;
		*label = OPENSSL_strdup(slot_id + i + 6);
		*id_len = 0;
		return *label != NULL;
	}

	ctx_log(ctx, 0, "Could not parse string!\n");
	return 0;
}

static int parse_uri_attr(ENGINE_CTX *ctx,
		const char *attr, int attrlen, unsigned char **field,
		size_t *field_len)
{
	size_t max, outlen = 0;
	unsigned char *out;
	int ret = 1;

	if (field_len) {
		out = *field;
		max = *field_len;
	} else {
		out = OPENSSL_malloc(attrlen + 1);
		if (out == NULL)
			return 0;
		max = attrlen + 1;
	}

	while (ret && attrlen && outlen < max) {
		if (*attr == '%') {
			if (attrlen < 3) {
				ret = 0;
			} else {
				char tmp[3];
				size_t l = 1;

				tmp[0] = attr[1];
				tmp[1] = attr[2];
				tmp[2] = 0;
				ret = hex_to_bin(ctx, tmp, &out[outlen++], &l);
				attrlen -= 3;
				attr += 3;
			}

		} else {
			out[outlen++] = *(attr++);
			attrlen--;
		}
	}
	if (attrlen && outlen == max)
		ret = 0;

	if (ret) {
		if (field_len) {
			*field_len = outlen;
		} else {
			out[outlen] = 0;
			*field = out;
		}
	} else {
		if (field_len == NULL)
			OPENSSL_free(out);
	}

	return ret;
}

int parse_pkcs11_uri(ENGINE_CTX *ctx,
		const char *uri, PKCS11_TOKEN **p_tok,
		unsigned char *id, size_t *id_len, char *pin, size_t *pin_len,
		char **label)
{
	PKCS11_TOKEN *tok;
	char *newlabel = NULL;
	const char *end, *p;
	int rv = 1, id_set = 0, pin_set = 0;

	tok = OPENSSL_malloc(sizeof(PKCS11_TOKEN));
	if (tok == NULL) {
		ctx_log(ctx, 0, "Could not allocate memory for token info\n");
		return 0;
	}
	memset(tok, 0, sizeof(PKCS11_TOKEN));

	/* We are only ever invoked if the string starts with 'pkcs11:' */
	end = uri + 6;
	while (rv && end[0] && end[1]) {
		p = end + 1;
		end = strpbrk(p, ";?&");
		if (end == NULL)
			end = p + strlen(p);

		if (!strncmp(p, "model=", 6)) {
			p += 6;
			rv = parse_uri_attr(ctx, p, end - p, (void *)&tok->model, NULL);
		} else if (!strncmp(p, "manufacturer=", 13)) {
			p += 13;
			rv = parse_uri_attr(ctx, p, end - p, (void *)&tok->manufacturer, NULL);
		} else if (!strncmp(p, "token=", 6)) {
			p += 6;
			rv = parse_uri_attr(ctx, p, end - p, (void *)&tok->label, NULL);
		} else if (!strncmp(p, "serial=", 7)) {
			p += 7;
			rv = parse_uri_attr(ctx, p, end - p, (void *)&tok->serialnr, NULL);
		} else if (!strncmp(p, "object=", 7)) {
			p += 7;
			rv = parse_uri_attr(ctx, p, end - p, (void *)&newlabel, NULL);
		} else if (!strncmp(p, "id=", 3)) {
			p += 3;
			rv = parse_uri_attr(ctx, p, end - p, (void *)&id, id_len);
			id_set = 1;
		} else if (!strncmp(p, "pin-value=", 10)) {
			p += 10;
			rv = parse_uri_attr(ctx, p, end - p, (void *)&pin, pin_len);
			pin_set = 1;
		} else if (!strncmp(p, "type=", 5) || !strncmp(p, "object-type=", 12)) {
			p = strchr(p, '=') + 1;

			if ((end - p == 4 && !strncmp(p, "cert", 4)) ||
					(end - p == 6 && !strncmp(p, "public", 6)) ||
					(end - p == 7 && !strncmp(p, "private", 7))) {
				/* Actually, just ignore it */
			} else {
				ctx_log(ctx, 0, "Unknown object type\n");
				rv = 0;
			}
		} else {
			rv = 0;
		}
	}

	if (!id_set)
		*id_len = 0;
	if (!pin_set)
		*pin_len = 0;

	if (rv) {
		*label = newlabel;
		*p_tok = tok;
	} else {
		OPENSSL_free(tok);
		tok = NULL;
		OPENSSL_free(newlabel);
	}

	return rv;
}

#define PKCS11_ENGINE_ID "pkcs11"
#define PKCS11_ENGINE_NAME "pkcs11 engine"

static int pkcs11_idx = -1;

/* The definitions for control commands specific to this engine */

/* need to add function to pass in reader id? or user reader:key as key id string? */

static const ENGINE_CMD_DEFN engine_cmd_defns[] = {
	{CMD_SO_PATH,
		"SO_PATH",
		"Specifies the path to the 'pkcs11' engine shared library",
		ENGINE_CMD_FLAG_STRING},
	{CMD_MODULE_PATH,
		"MODULE_PATH",
		"Specifies the path to the PKCS#11 module shared library",
		ENGINE_CMD_FLAG_STRING},
	{CMD_PIN,
		"PIN",
		"Specifies the pin code",
		ENGINE_CMD_FLAG_STRING},
	{CMD_VERBOSE,
		"VERBOSE",
		"Print additional details",
		ENGINE_CMD_FLAG_NO_INPUT},
	{CMD_QUIET,
		"QUIET",
		"Remove additional details",
		ENGINE_CMD_FLAG_NO_INPUT},
	{CMD_LOAD_CERT_CTRL,
		"LOAD_CERT_CTRL",
		"Get the certificate from card",
		ENGINE_CMD_FLAG_INTERNAL},
	{CMD_INIT_ARGS,
		"INIT_ARGS",
		"Specifies additional initialization arguments to the PKCS#11 module",
		ENGINE_CMD_FLAG_STRING},
	{CMD_SET_USER_INTERFACE,
		"SET_USER_INTERFACE",
		"Set the global user interface (internal)",
		ENGINE_CMD_FLAG_INTERNAL},
	{CMD_SET_CALLBACK_DATA,
		"SET_CALLBACK_DATA",
		"Set the global user interface extra data (internal)",
		ENGINE_CMD_FLAG_INTERNAL},
	{CMD_FORCE_LOGIN,
		"FORCE_LOGIN",
		"Force login to the PKCS#11 module",
		ENGINE_CMD_FLAG_NO_INPUT},
	{0, NULL, NULL, 0}
};

static ENGINE_CTX *get_ctx(ENGINE *engine)
{
	ENGINE_CTX *ctx;

	if (pkcs11_idx < 0) {
		pkcs11_idx = ENGINE_get_ex_new_index(0, "pkcs11", NULL, NULL, 0);
		if (pkcs11_idx < 0)
			return NULL;
		ctx = NULL;
	} else {
		ctx = ENGINE_get_ex_data(engine, pkcs11_idx);
	}
	if (ctx == NULL) {
		ctx = ctx_new();
		ENGINE_set_ex_data(engine, pkcs11_idx, ctx);
	}
	return ctx;
}

/* Destroy the context allocated with ctx_new() */
static int engine_destroy(ENGINE *engine)
{
	ENGINE_CTX *ctx;
	int rv = 1;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;

	/* ENGINE_remove() invokes our engine_destroy() function with
	 * CRYPTO_LOCK_ENGINE / global_engine_lock acquired.
	 * Any attempt to re-acquire the lock either by directly
	 * invoking OpenSSL functions, or indirectly via PKCS#11 modules
	 * that use OpenSSL engines, causes a deadlock. */
	/* Our workaround is to skip ctx_finish() entirely, as a memory
	 * leak is better than a deadlock. */
#if 0
	rv &= ctx_finish(ctx);
#endif

	rv &= ctx_destroy(ctx);
	ENGINE_set_ex_data(engine, pkcs11_idx, NULL);
	ERR_unload_ENG_strings();
	return rv;
}

static int engine_init(ENGINE *engine)
{
	ENGINE_CTX *ctx;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	return ctx_init(ctx);
}

/* Finish engine operations initialized with ctx_init() */
static int engine_finish(ENGINE *engine)
{
	ENGINE_CTX *ctx;
	int rv = 1;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;

	/* ENGINE_cleanup() used by OpenSSL versions before 1.1.0 invokes
	 * our engine_finish() function with CRYPTO_LOCK_ENGINE acquired.
	 * Any attempt to re-acquire CRYPTO_LOCK_ENGINE either by directly
	 * invoking OpenSSL functions, or indirectly via PKCS#11 modules
	 * that use OpenSSL engines, causes a deadlock. */
	/* Our workaround is to skip ctx_finish() for the affected OpenSSL
	 * versions, as a memory leak is better than a deadlock. */
	/* We cannot simply temporarily release CRYPTO_LOCK_ENGINE here, as
	 * engine_finish() is also executed from ENGINE_finish() without
	 * acquired CRYPTO_LOCK_ENGINE, and there is no way with to check
	 * whether a lock is already acquired with OpenSSL < 1.1.0 API. */
#if OPENSSL_VERSION_NUMBER >= 0x10100005L && !defined(LIBRESSL_VERSION_NUMBER)
	rv &= ctx_finish(ctx);
#endif

	return rv;
}

static EVP_PKEY *load_pubkey(ENGINE *engine, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	ENGINE_CTX *ctx;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	return ctx_load_pubkey(ctx, s_key_id, ui_method, callback_data);
}

static EVP_PKEY *load_privkey(ENGINE *engine, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	ENGINE_CTX *ctx;
	EVP_PKEY *pkey;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	pkey = ctx_load_privkey(ctx, s_key_id, ui_method, callback_data);
#ifdef EVP_F_EVP_PKEY_SET1_ENGINE
	/* EVP_PKEY_set1_engine() is required for OpenSSL 1.1.x,
	 * but otherwise setting pkey->engine breaks OpenSSL 1.0.2 */
	if (pkey && !EVP_PKEY_set1_engine(pkey, engine)) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
#endif /* EVP_F_EVP_PKEY_SET1_ENGINE */
	return pkey;
}

static int engine_ctrl(ENGINE *engine, int cmd, long i, void *p, void (*f) ())
{
	ENGINE_CTX *ctx;

	ctx = get_ctx(engine);
	if (ctx == NULL)
		return 0;
	return ctx_engine_ctrl(ctx, cmd, i, p, f);
}

/* This internal function is used by ENGINE_pkcs11() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_helper(ENGINE *e)
{
	if (!ENGINE_set_id(e, PKCS11_ENGINE_ID) ||
			!ENGINE_set_destroy_function(e, engine_destroy) ||
			!ENGINE_set_init_function(e, engine_init) ||
			!ENGINE_set_finish_function(e, engine_finish) ||
			!ENGINE_set_ctrl_function(e, engine_ctrl) ||
			!ENGINE_set_cmd_defns(e, engine_cmd_defns) ||
			!ENGINE_set_name(e, PKCS11_ENGINE_NAME) ||
#ifndef OPENSSL_NO_RSA
			!ENGINE_set_RSA(e, PKCS11_get_rsa_method()) ||
#endif
#if OPENSSL_VERSION_NUMBER  >= 0x10100002L
#ifndef OPENSSL_NO_EC
			/* PKCS11_get_ec_key_method combines ECDSA and ECDH */
			!ENGINE_set_EC(e, PKCS11_get_ec_key_method()) ||
#endif /* OPENSSL_NO_EC */
#else /* OPENSSL_VERSION_NUMBER */
#ifndef OPENSSL_NO_ECDSA
			!ENGINE_set_ECDSA(e, PKCS11_get_ecdsa_method()) ||
#endif
#ifndef OPENSSL_NO_ECDH
			!ENGINE_set_ECDH(e, PKCS11_get_ecdh_method()) ||
#endif
#endif /* OPENSSL_VERSION_NUMBER */
			!ENGINE_set_pkey_meths(e, PKCS11_pkey_meths) ||
			!ENGINE_set_load_pubkey_function(e, load_pubkey) ||
			!ENGINE_set_load_privkey_function(e, load_privkey)) {
		return 0;
	} else {
		ERR_load_ENG_strings();
		return 1;
	}
}

static int bind_fn(ENGINE *e, const char *id)
{
	if (id && (strcmp(id, PKCS11_ENGINE_ID) != 0)) {
		fprintf(stderr, "bad engine id\n");
		return 0;
	}
	if (!bind_helper(e)) {
		fprintf(stderr, "bind failed\n");
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)

#define ENG_LIB_NAME "pkcs11 engine"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(0,func,0)
# define ERR_REASON(reason) ERR_PACK(0,0,reason)

static ERR_STRING_DATA ENG_str_functs[] = {
    {ERR_FUNC(ENG_F_CTX_CTRL_LOAD_CERT), "ctx_ctrl_load_cert"},
    {ERR_FUNC(ENG_F_CTX_CTRL_SET_PIN), "ctx_ctrl_set_pin"},
    {ERR_FUNC(ENG_F_CTX_ENGINE_CTRL), "ctx_engine_ctrl"},
    {ERR_FUNC(ENG_F_CTX_LOAD_CERT), "ctx_load_cert"},
    {ERR_FUNC(ENG_F_CTX_LOAD_KEY), "ctx_load_key"},
    {ERR_FUNC(ENG_F_CTX_LOAD_PRIVKEY), "ctx_load_privkey"},
    {ERR_FUNC(ENG_F_CTX_LOAD_PUBKEY), "ctx_load_pubkey"},
    {0, NULL}
};

static ERR_STRING_DATA ENG_str_reasons[] = {
    {ERR_REASON(ENG_R_INVALID_ID), "invalid id"},
    {ERR_REASON(ENG_R_INVALID_PARAMETER), "invalid parameter"},
    {ERR_REASON(ENG_R_OBJECT_NOT_FOUND), "object not found"},
    {ERR_REASON(ENG_R_UNKNOWN_COMMAND), "unknown command"},
    {0, NULL}
};

#endif

#ifdef ENG_LIB_NAME
static ERR_STRING_DATA ENG_lib_name[] = {
    {0, ENG_LIB_NAME},
    {0, NULL}
};
#endif

static int ENG_lib_error_code = 0;
static int ENG_error_init = 1;

int ERR_load_ENG_strings(void)
{
    if (ENG_lib_error_code == 0)
        ENG_lib_error_code = ERR_get_next_error_library();

    if (ENG_error_init) {
        ENG_error_init = 0;
#ifndef OPENSSL_NO_ERR
        ERR_load_strings(ENG_lib_error_code, ENG_str_functs);
        ERR_load_strings(ENG_lib_error_code, ENG_str_reasons);
#endif

#ifdef ENG_LIB_NAME
        ENG_lib_name->error = ERR_PACK(ENG_lib_error_code, 0, 0);
        ERR_load_strings(0, ENG_lib_name);
#endif
    }
    return 1;
}

void ERR_unload_ENG_strings(void)
{
    if (ENG_error_init == 0) {
#ifndef OPENSSL_NO_ERR
        ERR_unload_strings(ENG_lib_error_code, ENG_str_functs);
        ERR_unload_strings(ENG_lib_error_code, ENG_str_reasons);
#endif

#ifdef ENG_LIB_NAME
        ERR_unload_strings(0, ENG_lib_name);
#endif
        ENG_error_init = 1;
    }
}

void ERR_ENG_error(int function, int reason, char *file, int line)
{
    if (ENG_lib_error_code == 0)
        ENG_lib_error_code = ERR_get_next_error_library();
    ERR_PUT_error(ENG_lib_error_code, function, reason, file, line);
}

#if defined(_WIN32) || defined(_WIN64)
#define strncasecmp _strnicmp
#endif

/* The maximum length of an internally-allocated PIN */
#define MAX_PIN_LENGTH   32
#define MAX_VALUE_LEN	200

struct st_engine_ctx {
	/* Engine configuration */
	/*
	 * The PIN used for login. Cache for the ctx_get_pin function.
	 * The memory for this PIN is always owned internally,
	 * and may be freed as necessary. Before freeing, the PIN
	 * must be whitened, to prevent security holes.
	 */
	char *pin;
	size_t pin_length;
	int verbose;
	char *module;
	char *init_args;
	UI_METHOD *ui_method;
	void *callback_data;
	int force_login;

	/* Engine initialization mutex */
#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
	CRYPTO_RWLOCK *rwlock;
#else
	int rwlock;
#endif

	/* Current operations */
	PKCS11_CTX *pkcs11_ctx;
	PKCS11_SLOT *slot_list;
	unsigned int slot_count;
};

/******************************************************************************/
/* Utility functions                                                          */
/******************************************************************************/

void ctx_log(ENGINE_CTX *ctx, int level, const char *format, ...)
{
	va_list ap;

	if (level > ctx->verbose)
			return;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

static void dump_hex(ENGINE_CTX *ctx, int level,
		const unsigned char *val, const size_t len)
{
	size_t n;

	for (n = 0; n < len; n++)
		ctx_log(ctx, level, "%02x", val[n]);
}

/******************************************************************************/
/* PIN handling                                                               */
/******************************************************************************/

/* Free PIN storage in secure way. */
static void ctx_destroy_pin(ENGINE_CTX *ctx)
{
	if (ctx->pin != NULL) {
		OPENSSL_cleanse(ctx->pin, ctx->pin_length);
		OPENSSL_free(ctx->pin);
		ctx->pin = NULL;
		ctx->pin_length = 0;
	}
}

/* Get the PIN via asking user interface. The supplied call-back data are
 * passed to the user interface implemented by an application. Only the
 * application knows how to interpret the call-back data.
 * A (strdup'ed) copy of the PIN code will be stored in the pin variable. */
static int ctx_get_pin(ENGINE_CTX *ctx, const char* token_label, UI_METHOD *ui_method, void *callback_data)
{
	UI *ui;
	char* prompt;

	/* call ui to ask for a pin */
	ui = UI_new_method(ui_method);
	if (ui == NULL) {
		ctx_log(ctx, 0, "UI_new failed\n");
		return 0;
	}
	if (callback_data != NULL)
		UI_add_user_data(ui, callback_data);

	ctx_destroy_pin(ctx);
	ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
	if (ctx->pin == NULL)
		return 0;
	memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
	ctx->pin_length = MAX_PIN_LENGTH;
	prompt = UI_construct_prompt(ui, "PKCS#11 token PIN", token_label);
	if (!prompt) {
		return 0;
	}
	if (!UI_dup_input_string(ui, prompt,
			UI_INPUT_FLAG_DEFAULT_PWD, ctx->pin, 4, MAX_PIN_LENGTH)) {
		ctx_log(ctx, 0, "UI_dup_input_string failed\n");
		UI_free(ui);
		OPENSSL_free(prompt);
		return 0;
	}
	OPENSSL_free(prompt);

	if (UI_process(ui)) {
		ctx_log(ctx, 0, "UI_process failed\n");
		UI_free(ui);
		return 0;
	}
	UI_free(ui);
	return 1;
}

/* Return 1 if the user has already logged in */
static int slot_logged_in(ENGINE_CTX *ctx, PKCS11_SLOT *slot) {
	int logged_in = 0;

	/* Check if already logged in to avoid resetting state */
	if (PKCS11_is_logged_in(slot, 0, &logged_in) != 0) {
		ctx_log(ctx, 0, "Unable to check if already logged in\n");
		return 0;
	}
	return logged_in;
}

/*
 * Log-into the token if necessary.
 *
 * @slot is PKCS11 slot to log in
 * @tok is PKCS11 token to log in (??? could be derived as @slot->token)
 * @ui_method is OpenSSL user interface which is used to ask for a password
 * @callback_data are application data to the user interface
 * @return 1 on success, 0 on error.
 */
static int ctx_login(ENGINE_CTX *ctx, PKCS11_SLOT *slot, PKCS11_TOKEN *tok,
		UI_METHOD *ui_method, void *callback_data)
{
	if (!(ctx->force_login || tok->loginRequired) || slot_logged_in(ctx, slot))
		return 1;

	/* If the token has a secure login (i.e., an external keypad),
	 * then use a NULL PIN. Otherwise, obtain a new PIN if needed. */
	if (tok->secureLogin) {
		/* Free the PIN if it has already been
		 * assigned (i.e, cached by ctx_get_pin) */
		ctx_destroy_pin(ctx);
	} else if (ctx->pin == NULL) {
		ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
		ctx->pin_length = MAX_PIN_LENGTH;
		if (ctx->pin == NULL) {
			ctx_log(ctx, 0, "Could not allocate memory for PIN\n");
			return 0;
		}
		memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
		if (!ctx_get_pin(ctx, tok->label, ui_method, callback_data)) {
			ctx_destroy_pin(ctx);
			ctx_log(ctx, 0, "No PIN code was entered\n");
			return 0;
		}
	}

	/* Now login in with the (possibly NULL) PIN */
	if (PKCS11_login(slot, 0, ctx->pin)) {
		/* Login failed, so free the PIN if present */
		ctx_destroy_pin(ctx);
		ctx_log(ctx, 0, "Login failed\n");
		return 0;
	}
	return 1;
}

/******************************************************************************/
/* Initialization and cleanup                                                 */
/******************************************************************************/

ENGINE_CTX *ctx_new()
{
	ENGINE_CTX *ctx;
	char *mod;

	ctx = OPENSSL_malloc(sizeof(ENGINE_CTX));
	if (ctx == NULL)
		return NULL;
	memset(ctx, 0, sizeof(ENGINE_CTX));

	mod = getenv("PKCS11_MODULE_PATH");
	if (mod) {
		ctx->module = OPENSSL_strdup(mod);
	} else {
#ifdef DEFAULT_PKCS11_MODULE
		ctx->module = OPENSSL_strdup(DEFAULT_PKCS11_MODULE);
#else
		ctx->module = NULL;
#endif
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
	ctx->rwlock = CRYPTO_THREAD_lock_new();
#else
	ctx->rwlock = CRYPTO_get_dynlock_create_callback() ?
		CRYPTO_get_new_dynlockid() : 0;
#endif

	return ctx;
}

/* Destroy the context allocated with ctx_new() */
int ctx_destroy(ENGINE_CTX *ctx)
{
	if (ctx) {
		ctx_destroy_pin(ctx);
		OPENSSL_free(ctx->module);
		OPENSSL_free(ctx->init_args);
#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
		CRYPTO_THREAD_lock_free(ctx->rwlock);
#else
		if (ctx->rwlock)
			CRYPTO_destroy_dynlockid(ctx->rwlock);
#endif
		OPENSSL_free(ctx);
	}
	return 1;
}

/* Initialize libp11 data: ctx->pkcs11_ctx and ctx->slot_list */
static void ctx_init_libp11_unlocked(ENGINE_CTX *ctx)
{
	PKCS11_CTX *pkcs11_ctx;
	PKCS11_SLOT *slot_list = NULL;
	unsigned int slot_count = 0;

	ctx_log(ctx, 1, "PKCS#11: Initializing the engine\n");

	pkcs11_ctx = PKCS11_CTX_new();
	PKCS11_CTX_init_args(pkcs11_ctx, ctx->init_args);
	PKCS11_set_ui_method(pkcs11_ctx, ctx->ui_method, ctx->callback_data);

	/* PKCS11_CTX_load() uses C_GetSlotList() via p11-kit */
	if (PKCS11_CTX_load(pkcs11_ctx, ctx->module) < 0) {
		ctx_log(ctx, 0, "Unable to load module %s\n", ctx->module);
		PKCS11_CTX_free(pkcs11_ctx);
		return;
	}

	/* PKCS11_enumerate_slots() uses C_GetSlotList() via libp11 */
	if (PKCS11_enumerate_slots(pkcs11_ctx, &slot_list, &slot_count) < 0) {
		ctx_log(ctx, 0, "Failed to enumerate slots\n");
		PKCS11_CTX_unload(pkcs11_ctx);
		PKCS11_CTX_free(pkcs11_ctx);
		return;
	}

	ctx_log(ctx, 1, "Found %u slot%s\n", slot_count,
		slot_count <= 1 ? "" : "s");

	ctx->pkcs11_ctx = pkcs11_ctx;
	ctx->slot_list = slot_list;
	ctx->slot_count = slot_count;
}

static int ctx_init_libp11(ENGINE_CTX *ctx)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
	CRYPTO_THREAD_write_lock(ctx->rwlock);
#else
	if (ctx->rwlock)
		CRYPTO_w_lock(ctx->rwlock);
#endif
	if (ctx->pkcs11_ctx == NULL || ctx->slot_list == NULL)
		ctx_init_libp11_unlocked(ctx);
#if OPENSSL_VERSION_NUMBER >= 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
	CRYPTO_THREAD_unlock(ctx->rwlock);
#else
	if (ctx->rwlock)
		CRYPTO_w_unlock(ctx->rwlock);
#endif
	return ctx->pkcs11_ctx && ctx->slot_list ? 0 : -1;
}

/* Function called from ENGINE_init() */
int ctx_init(ENGINE_CTX *ctx)
{
	/* OpenSC implicitly locks CRYPTO_LOCK_ENGINE during C_GetSlotList().
	 * OpenSSL also locks CRYPTO_LOCK_ENGINE in ENGINE_init().
	 * Double-locking a non-recursive rwlock causes the application to
	 * crash or hang, depending on the locking library implementation. */

	/* Only attempt initialization when dynamic locks are unavailable.
	 * This likely also indicates a single-threaded application,
	 * so temporarily unlocking CRYPTO_LOCK_ENGINE should be safe. */
#if OPENSSL_VERSION_NUMBER < 0x10100004L && !defined(LIBRESSL_VERSION_NUMBER)
	if (CRYPTO_get_dynlock_create_callback() == NULL ||
			CRYPTO_get_dynlock_lock_callback() == NULL ||
			CRYPTO_get_dynlock_destroy_callback() == NULL) {
		CRYPTO_w_unlock(CRYPTO_LOCK_ENGINE);
		ctx_init_libp11_unlocked(ctx);
		CRYPTO_w_lock(CRYPTO_LOCK_ENGINE);
		return ctx->pkcs11_ctx && ctx->slot_list ? 1 : 0;
	}
#else
	(void)ctx; /* squash the unused parameter warning */
#endif
	return 1;
}

/* Finish engine operations initialized with ctx_init() */
int ctx_finish(ENGINE_CTX *ctx)
{
	if (ctx) {
		if (ctx->slot_list) {
			PKCS11_release_all_slots(ctx->pkcs11_ctx,
				ctx->slot_list, ctx->slot_count);
			ctx->slot_list = NULL;
			ctx->slot_count = 0;
		}
		if (ctx->pkcs11_ctx) {
			PKCS11_CTX_unload(ctx->pkcs11_ctx);
			PKCS11_CTX_free(ctx->pkcs11_ctx);
			ctx->pkcs11_ctx = NULL;
		}
	}
	return 1;
}

/******************************************************************************/
/* Certificate handling                                                       */
/******************************************************************************/

/* prototype for OpenSSL ENGINE_load_cert */
/* used by load_cert_ctrl via ENGINE_ctrl for now */

static X509 *ctx_load_cert(ENGINE_CTX *ctx, const char *s_slot_cert_id,
		const int login)
{
	PKCS11_SLOT *slot;
	PKCS11_SLOT *found_slot = NULL;
	PKCS11_TOKEN *tok, *match_tok = NULL;
	PKCS11_CERT *certs, *selected_cert = NULL;
	X509 *x509;
	unsigned int cert_count, n, m;
	unsigned char cert_id[MAX_VALUE_LEN / 2];
	size_t cert_id_len = sizeof(cert_id);
	char *cert_label = NULL;
	char tmp_pin[MAX_PIN_LENGTH+1];
	size_t tmp_pin_len = MAX_PIN_LENGTH;
	int slot_nr = -1;
	char flags[64];

	if (ctx_init_libp11(ctx)) /* Delayed libp11 initialization */
		return NULL;

	if (s_slot_cert_id && *s_slot_cert_id) {
		if (!strncasecmp(s_slot_cert_id, "pkcs11:", 7)) {
			n = parse_pkcs11_uri(ctx, s_slot_cert_id, &match_tok,
				cert_id, &cert_id_len,
				tmp_pin, &tmp_pin_len, &cert_label);
			if (!n) {
				ctx_log(ctx, 0,
					"The certificate ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n");
				ENGerr(ENG_F_CTX_LOAD_CERT, ENG_R_INVALID_ID);
				return NULL;
			}
			if (tmp_pin_len > 0 && tmp_pin[0] != 0) {
				if (!login)
					return NULL; /* Process on second attempt */
				ctx_destroy_pin(ctx);
				ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
				if (ctx->pin != NULL) {
					memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
					memcpy(ctx->pin, tmp_pin, tmp_pin_len);
					ctx->pin_length = tmp_pin_len;
				}
			}
		} else {
			n = parse_slot_id_string(ctx, s_slot_cert_id, &slot_nr,
				cert_id, &cert_id_len, &cert_label);
			if (!n) {
				ctx_log(ctx, 0,
					"The certificate ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n"
					"The legacy ENGINE_pkcs11 ID format is also "
					"still accepted for now\n");
				ENGerr(ENG_F_CTX_LOAD_CERT, ENG_R_INVALID_ID);
				return NULL;
			}
		}
		ctx_log(ctx, 1, "Looking in slot %d for certificate: ",
			slot_nr);
		if (cert_id_len != 0) {
			ctx_log(ctx, 1, "id=");
			dump_hex(ctx, 1, cert_id, cert_id_len);
		}
		if (cert_id_len != 0 && cert_label != NULL)
			ctx_log(ctx, 1, " ");
		if (cert_label != NULL)
			ctx_log(ctx, 1, "label=%s", cert_label);
		ctx_log(ctx, 1, "\n");
	}

	for (n = 0; n < ctx->slot_count; n++) {
		slot = ctx->slot_list + n;
		flags[0] = '\0';
		if (slot->token) {
			if (!slot->token->initialized)
				strcat(flags, "uninitialized, ");
			else if (!slot->token->userPinSet)
				strcat(flags, "no pin, ");
			if (slot->token->loginRequired)
				strcat(flags, "login, ");
			if (slot->token->readOnly)
				strcat(flags, "ro, ");
		} else {
			strcpy(flags, "no token");
		}
		if ((m = strlen(flags)) != 0) {
			flags[m - 2] = '\0';
		}

		if (slot_nr != -1 &&
			slot_nr == (int)PKCS11_get_slotid_from_slot(slot)) {
			found_slot = slot;
		}
		if (match_tok && slot->token &&
				(match_tok->label == NULL ||
					!strcmp(match_tok->label, slot->token->label)) &&
				(match_tok->manufacturer == NULL ||
					!strcmp(match_tok->manufacturer, slot->token->manufacturer)) &&
				(match_tok->serialnr == NULL ||
					!strcmp(match_tok->serialnr, slot->token->serialnr)) &&
				(match_tok->model == NULL ||
					!strcmp(match_tok->model, slot->token->model))) {
			found_slot = slot;
		}
		ctx_log(ctx, 1, "[%lu] %-25.25s  %-16s",
			PKCS11_get_slotid_from_slot(slot),
			slot->description, flags);
		if (slot->token) {
			ctx_log(ctx, 1, "  (%s)",
				slot->token->label[0] ?
				slot->token->label : "no label");
		}
		ctx_log(ctx, 1, "\n");
	}

	if (match_tok) {
		OPENSSL_free(match_tok->model);
		OPENSSL_free(match_tok->manufacturer);
		OPENSSL_free(match_tok->serialnr);
		OPENSSL_free(match_tok->label);
		OPENSSL_free(match_tok);
	}
	if (found_slot) {
		slot = found_slot;
	} else if (match_tok) {
		ctx_log(ctx, 0, "Specified object not found\n");
		return NULL;
	} else if (slot_nr == -1) {
		if (!(slot = PKCS11_find_token(ctx->pkcs11_ctx,
				ctx->slot_list, ctx->slot_count))) {
			ctx_log(ctx, 0, "No tokens found\n");
			return NULL;
		}
	} else {
		ctx_log(ctx, 0, "Invalid slot number: %d\n", slot_nr);
		return NULL;
	}
	tok = slot->token;

	if (tok == NULL) {
		ctx_log(ctx, 0, "Empty token found\n");
		return NULL;
	}

	ctx_log(ctx, 1, "Found slot:  %s\n", slot->description);
	ctx_log(ctx, 1, "Found token: %s\n", slot->token->label);

	/* In several tokens certificates are marked as private */
	if (login && !ctx_login(ctx, slot, tok,
			ctx->ui_method, ctx->callback_data)) {
		ctx_log(ctx, 0, "Login to token failed, returning NULL...\n");
		return NULL;
	}

	if (PKCS11_enumerate_certs(tok, &certs, &cert_count)) {
		ctx_log(ctx, 0, "Unable to enumerate certificates\n");
		return NULL;
	}

	ctx_log(ctx, 1, "Found %u cert%s:\n", cert_count,
		(cert_count <= 1) ? "" : "s");
	if ((s_slot_cert_id && *s_slot_cert_id) &&
			(cert_id_len != 0 || cert_label != NULL)) {
		for (n = 0; n < cert_count; n++) {
			PKCS11_CERT *k = certs + n;

			if (cert_label != NULL && strcmp(k->label, cert_label) == 0)
				selected_cert = k;
			if (cert_id_len != 0 && k->id_len == cert_id_len &&
					memcmp(k->id, cert_id, cert_id_len) == 0)
				selected_cert = k;
		}
	} else { 
		for (n = 0; n < cert_count; n++) {
			PKCS11_CERT *k = certs + n;
			if (k->id && *(k->id)) {
				selected_cert = k; /* Use the first certificate with nonempty id */
				break;
			}
		}
		if (!selected_cert)
			selected_cert = certs; /* Use the first certificate */
	}

	if (selected_cert != NULL) {
		x509 = X509_dup(selected_cert->x509);
	} else {
		if (login) /* Only print the error on the second attempt */
			ctx_log(ctx, 0, "Certificate not found.\n");
		x509 = NULL;
	}
	if (cert_label != NULL)
		OPENSSL_free(cert_label);
	return x509;
}

static int ctx_ctrl_load_cert(ENGINE_CTX *ctx, void *p)
{
	struct {
		const char *s_slot_cert_id;
		X509 *cert;
	} *parms = p;

	if (parms == NULL) {
		ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (parms->cert != NULL) {
		ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ENG_R_INVALID_PARAMETER);
		return 0;
	}
	ERR_clear_error();
	if (!ctx->force_login)
		parms->cert = ctx_load_cert(ctx, parms->s_slot_cert_id, 0);
	if (parms->cert == NULL) { /* Try again with login */
		ERR_clear_error();
		parms->cert = ctx_load_cert(ctx, parms->s_slot_cert_id, 1);
	}
	if (parms->cert == NULL) {
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_CTRL_LOAD_CERT, ENG_R_OBJECT_NOT_FOUND);
		return 0;
	}
	return 1;
}

/******************************************************************************/
/* Private and public key handling                                            */
/******************************************************************************/

static EVP_PKEY *ctx_load_key(ENGINE_CTX *ctx, const char *s_slot_key_id,
		UI_METHOD *ui_method, void *callback_data,
		const int isPrivate, const int login)
{
	PKCS11_SLOT *slot;
	PKCS11_SLOT *found_slot = NULL;
	PKCS11_TOKEN *tok, *match_tok = NULL;
	PKCS11_KEY *keys, *selected_key = NULL;
	EVP_PKEY *pk = NULL;
	unsigned int key_count, n, m;
	unsigned char key_id[MAX_VALUE_LEN / 2];
	size_t key_id_len = sizeof(key_id);
	char *key_label = NULL;
	int slot_nr = -1;
	char tmp_pin[MAX_PIN_LENGTH+1];
	size_t tmp_pin_len = MAX_PIN_LENGTH;
	char flags[64];

	if (ctx_init_libp11(ctx)) /* Delayed libp11 initialization */
		goto error;

	ctx_log(ctx, 1, "Loading %s key \"%s\"\n",
		(char *)(isPrivate ? "private" : "public"),
		s_slot_key_id);
	if (s_slot_key_id && *s_slot_key_id) {
		if (!strncasecmp(s_slot_key_id, "pkcs11:", 7)) {
			n = parse_pkcs11_uri(ctx, s_slot_key_id, &match_tok,
				key_id, &key_id_len,
				tmp_pin, &tmp_pin_len, &key_label);
			if (!n) {
				ctx_log(ctx, 0,
					"The key ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n");
				ENGerr(ENG_F_CTX_LOAD_KEY, ENG_R_INVALID_ID);
				goto error;
			}
			if (tmp_pin_len > 0 && tmp_pin[0] != 0) {
				if (!login)
					goto error; /* Process on second attempt */
				ctx_destroy_pin(ctx);
				ctx->pin = OPENSSL_malloc(MAX_PIN_LENGTH+1);
				if (ctx->pin != NULL) {
					memset(ctx->pin, 0, MAX_PIN_LENGTH+1);
					memcpy(ctx->pin, tmp_pin, tmp_pin_len);
					ctx->pin_length = tmp_pin_len;
				}
			}
		} else {
			n = parse_slot_id_string(ctx, s_slot_key_id, &slot_nr,
				key_id, &key_id_len, &key_label);
			if (!n) {
				ctx_log(ctx, 0,
					"The key ID is not a valid PKCS#11 URI\n"
					"The PKCS#11 URI format is defined by RFC7512\n"
					"The legacy ENGINE_pkcs11 ID format is also "
					"still accepted for now\n");
				ENGerr(ENG_F_CTX_LOAD_KEY, ENG_R_INVALID_ID);
				goto error;
			}
		}
		ctx_log(ctx, 1, "Looking in slot %d for key: ",
			slot_nr);
		if (key_id_len != 0) {
			ctx_log(ctx, 1, "id=");
			dump_hex(ctx, 1, key_id, key_id_len);
		}
		if (key_id_len != 0 && key_label != NULL)
			ctx_log(ctx, 1, " ");
		if (key_label != NULL)
			ctx_log(ctx, 1, "label=%s", key_label);
		ctx_log(ctx, 1, "\n");
	}

	for (n = 0; n < ctx->slot_count; n++) {
		slot = ctx->slot_list + n;
		flags[0] = '\0';
		if (slot->token) {
			if (!slot->token->initialized)
				strcat(flags, "uninitialized, ");
			else if (!slot->token->userPinSet)
				strcat(flags, "no pin, ");
			if (slot->token->loginRequired)
				strcat(flags, "login, ");
			if (slot->token->readOnly)
				strcat(flags, "ro, ");
		} else {
			strcpy(flags, "no token");
		}
		if ((m = strlen(flags)) != 0) {
			flags[m - 2] = '\0';
		}

		if (slot_nr != -1 &&
			slot_nr == (int)PKCS11_get_slotid_from_slot(slot)) {
			found_slot = slot;
		}
		if (match_tok && slot->token &&
				(match_tok->label == NULL ||
					!strcmp(match_tok->label, slot->token->label)) &&
				(match_tok->manufacturer == NULL ||
					!strcmp(match_tok->manufacturer, slot->token->manufacturer)) &&
				(match_tok->serialnr == NULL ||
					!strcmp(match_tok->serialnr, slot->token->serialnr)) &&
				(match_tok->model == NULL ||
					!strcmp(match_tok->model, slot->token->model))) {
			found_slot = slot;
		}
		ctx_log(ctx, 1, "[%lu] %-25.25s  %-16s",
			PKCS11_get_slotid_from_slot(slot),
			slot->description, flags);
		if (slot->token) {
			ctx_log(ctx, 1, "  (%s)",
				slot->token->label[0] ?
				slot->token->label : "no label");
		}
		ctx_log(ctx, 1, "\n");
	}

	if (match_tok) {
		OPENSSL_free(match_tok->model);
		OPENSSL_free(match_tok->manufacturer);
		OPENSSL_free(match_tok->serialnr);
		OPENSSL_free(match_tok->label);
		OPENSSL_free(match_tok);
	}
	if (found_slot) {
		slot = found_slot;
	} else if (match_tok) {
		ctx_log(ctx, 0, "Specified object not found\n");
		goto error;
	} else if (slot_nr == -1) {
		if (!(slot = PKCS11_find_token(ctx->pkcs11_ctx,
				ctx->slot_list, ctx->slot_count))) {
			ctx_log(ctx, 0, "No tokens found\n");
			goto error;
		}
	} else {
		ctx_log(ctx, 0, "Invalid slot number: %d\n", slot_nr);
		goto error;
	}
	tok = slot->token;

	if (tok == NULL) {
		ctx_log(ctx, 0, "Found empty token\n");
		goto error;
	}
	/* The following check is non-critical to ensure interoperability
	 * with some other (which ones?) PKCS#11 libraries */
	if (!tok->initialized)
		ctx_log(ctx, 0, "Found uninitialized token\n");

	ctx_log(ctx, 1, "Found slot:  %s\n", slot->description);
	ctx_log(ctx, 1, "Found token: %s\n", slot->token->label);

	/* Both private and public keys can have the CKA_PRIVATE attribute
	 * set and thus require login (even to retrieve attributes!) */
	if (login && !ctx_login(ctx, slot, tok, ui_method, callback_data)) {
		ctx_log(ctx, 0, "Login to token failed, returning NULL...\n");
		goto error;
	}

	if (isPrivate) {
		/* Make sure there is at least one private key on the token */
		if (PKCS11_enumerate_keys(tok, &keys, &key_count)) {
			ctx_log(ctx, 0, "Unable to enumerate private keys\n");
			goto error;
		}
	} else {
		/* Make sure there is at least one public key on the token */
		if (PKCS11_enumerate_public_keys(tok, &keys, &key_count)) {
			ctx_log(ctx, 0, "Unable to enumerate public keys\n");
			goto error;
		}
	}
	if (key_count == 0) {
		if (login) /* Only print the error on the second attempt */
			ctx_log(ctx, 0, "No %s keys found.\n",
				(char *)(isPrivate ? "private" : "public"));
		goto error;
	}
	ctx_log(ctx, 1, "Found %u %s key%s:\n", key_count,
		(char *)(isPrivate ? "private" : "public"),
		(key_count == 1) ? "" : "s");

	if (s_slot_key_id && *s_slot_key_id &&
			(key_id_len != 0 || key_label != NULL)) {
		for (n = 0; n < key_count; n++) {
			PKCS11_KEY *k = keys + n;

			ctx_log(ctx, 1, "  %2u %c%c id=", n + 1,
				k->isPrivate ? 'P' : ' ',
				k->needLogin ? 'L' : ' ');
			dump_hex(ctx, 1, k->id, k->id_len);
			ctx_log(ctx, 1, " label=%s\n", k->label);
			if (key_label != NULL && strcmp(k->label, key_label) == 0)
				selected_key = k;
			if (key_id_len != 0 && k->id_len == key_id_len
					&& memcmp(k->id, key_id, key_id_len) == 0)
				selected_key = k;
		}
	} else {
		selected_key = keys; /* Use the first key */
	}

	if (selected_key != NULL) {
		pk = isPrivate ?
			PKCS11_get_private_key(selected_key) :
			PKCS11_get_public_key(selected_key);
	} else {
		if (login) /* Only print the error on the second attempt */
			ctx_log(ctx, 0, "Key not found.\n");
		pk = NULL;
	}
error:
	if (key_label != NULL)
		OPENSSL_free(key_label);
	return pk;
}

EVP_PKEY *ctx_load_pubkey(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *pk = NULL;

	ERR_clear_error();
	if (!ctx->force_login)
		pk = ctx_load_key(ctx, s_key_id, ui_method, callback_data, 0, 0);
	if (pk == NULL) { /* Try again with login */
		ERR_clear_error();
		pk = ctx_load_key(ctx, s_key_id, ui_method, callback_data, 0, 1);
	}
	if (pk == NULL) {
		ctx_log(ctx, 0, "PKCS11_load_public_key returned NULL\n");
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_LOAD_PUBKEY, ENG_R_OBJECT_NOT_FOUND);
		return NULL;
	}
	return pk;
}

EVP_PKEY *ctx_load_privkey(ENGINE_CTX *ctx, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *pk = NULL;

	ERR_clear_error();
	if (!ctx->force_login)
		pk = ctx_load_key(ctx, s_key_id, ui_method, callback_data, 1, 0);
	if (pk == NULL) { /* Try again with login */
		ERR_clear_error();
		pk = ctx_load_key(ctx, s_key_id, ui_method, callback_data, 1, 1);
	}
	if (pk == NULL) {
		ctx_log(ctx, 0, "PKCS11_get_private_key returned NULL\n");
		if (!ERR_peek_last_error())
			ENGerr(ENG_F_CTX_LOAD_PRIVKEY, ENG_R_OBJECT_NOT_FOUND);
		return NULL;
	}
	return pk;
}

/******************************************************************************/
/* Engine ctrl request handling                                               */
/******************************************************************************/

static int ctx_ctrl_set_module(ENGINE_CTX *ctx, const char *modulename)
{
	OPENSSL_free(ctx->module);
	ctx->module = modulename ? OPENSSL_strdup(modulename) : NULL;
	return 1;
}

/**
 * Set the PIN used for login. A copy of the PIN shall be made.
 *
 * If the PIN cannot be assigned, the value 0 shall be returned
 * and errno shall be set as follows:
 *
 *   EINVAL - a NULL PIN was supplied
 *   ENOMEM - insufficient memory to copy the PIN
 *
 * @param pin the pin to use for login. Must not be NULL.
 *
 * @return 1 on success, 0 on failure.
 */
static int ctx_ctrl_set_pin(ENGINE_CTX *ctx, const char *pin)
{
	/* Pre-condition check */
	if (pin == NULL) {
		ENGerr(ENG_F_CTX_CTRL_SET_PIN, ERR_R_PASSED_NULL_PARAMETER);
		errno = EINVAL;
		return 0;
	}

	/* Copy the PIN. If the string cannot be copied, NULL
	 * shall be returned and errno shall be set. */
	ctx_destroy_pin(ctx);
	ctx->pin = OPENSSL_strdup(pin);
	if (ctx->pin == NULL) {
		ENGerr(ENG_F_CTX_CTRL_SET_PIN, ERR_R_MALLOC_FAILURE);
		errno = ENOMEM;
		return 0;
	}
	ctx->pin_length = strlen(ctx->pin);
	return 1;
}

static int ctx_ctrl_inc_verbose(ENGINE_CTX *ctx)
{
	ctx->verbose++;
	return 1;
}

static int ctx_ctrl_set_quiet(ENGINE_CTX *ctx)
{
	ctx->verbose = -1;
	return 1;
}

static int ctx_ctrl_set_init_args(ENGINE_CTX *ctx, const char *init_args_orig)
{
	OPENSSL_free(ctx->init_args);
	ctx->init_args = init_args_orig ? OPENSSL_strdup(init_args_orig) : NULL;
	return 1;
}

static int ctx_ctrl_set_user_interface(ENGINE_CTX *ctx, UI_METHOD *ui_method)
{
	ctx->ui_method = ui_method;
	if (ctx->pkcs11_ctx != NULL) /* libp11 is already initialized */
		PKCS11_set_ui_method(ctx->pkcs11_ctx,
			ctx->ui_method, ctx->callback_data);
	return 1;
}

static int ctx_ctrl_set_callback_data(ENGINE_CTX *ctx, void *callback_data)
{
	ctx->callback_data = callback_data;
	if (ctx->pkcs11_ctx != NULL) /* libp11 is already initialized */
		PKCS11_set_ui_method(ctx->pkcs11_ctx,
			ctx->ui_method, ctx->callback_data);
	return 1;
}

static int ctx_ctrl_force_login(ENGINE_CTX *ctx)
{
	ctx->force_login = 1;
	return 1;
}

int ctx_engine_ctrl(ENGINE_CTX *ctx, int cmd, long i, void *p, void (*f)())
{
	(void)i; /* We don't currently take integer parameters */
	(void)f; /* We don't currently take callback parameters */
	/*int initialised = ((pkcs11_dso == NULL) ? 0 : 1); */
	switch (cmd) {
	case CMD_MODULE_PATH:
		return ctx_ctrl_set_module(ctx, (const char *)p);
	case CMD_PIN:
		return ctx_ctrl_set_pin(ctx, (const char *)p);
	case CMD_VERBOSE:
		return ctx_ctrl_inc_verbose(ctx);
	case CMD_QUIET:
		return ctx_ctrl_set_quiet(ctx);
	case CMD_LOAD_CERT_CTRL:
		return ctx_ctrl_load_cert(ctx, p);
	case CMD_INIT_ARGS:
		return ctx_ctrl_set_init_args(ctx, (const char *)p);
	case ENGINE_CTRL_SET_USER_INTERFACE:
	case CMD_SET_USER_INTERFACE:
		return ctx_ctrl_set_user_interface(ctx, (UI_METHOD *)p);
	case ENGINE_CTRL_SET_CALLBACK_DATA:
	case CMD_SET_CALLBACK_DATA:
		return ctx_ctrl_set_callback_data(ctx, p);
	case CMD_FORCE_LOGIN:
		return ctx_ctrl_force_login(ctx);
	default:
		ENGerr(ENG_F_CTX_ENGINE_CTRL, ENG_R_UNKNOWN_COMMAND);
		break;
	}
	return 0;
}

static int (*orig_pkey_rsa_sign_init) (EVP_PKEY_CTX *ctx);
static int (*orig_pkey_rsa_sign) (EVP_PKEY_CTX *ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen);
static int (*orig_pkey_rsa_decrypt_init) (EVP_PKEY_CTX *ctx);
static int (*orig_pkey_rsa_decrypt) (EVP_PKEY_CTX *ctx,
	unsigned char *out, size_t *outlen,
	const unsigned char *in, size_t inlen);

#ifndef OPENSSL_NO_EC
static int (*orig_pkey_ec_sign_init) (EVP_PKEY_CTX *ctx);
static int (*orig_pkey_ec_sign) (EVP_PKEY_CTX *ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen);
#endif /* OPENSSL_NO_EC */

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
struct evp_pkey_method_st {
	int pkey_id;
	int flags;
	int (*init) (EVP_PKEY_CTX *ctx);
	int (*copy) (EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
	void (*cleanup) (EVP_PKEY_CTX *ctx);
	int (*paramgen_init) (EVP_PKEY_CTX *ctx);
	int (*paramgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
	int (*keygen_init) (EVP_PKEY_CTX *ctx);
	int (*keygen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
	int (*sign_init) (EVP_PKEY_CTX *ctx);
	int (*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen);
	int (*verify_init) (EVP_PKEY_CTX *ctx);
	int (*verify) (EVP_PKEY_CTX *ctx,
		const unsigned char *sig, size_t siglen,
		const unsigned char *tbs, size_t tbslen);
	int (*verify_recover_init) (EVP_PKEY_CTX *ctx);
	int (*verify_recover) (EVP_PKEY_CTX *ctx,
		unsigned char *rout, size_t *routlen,
		const unsigned char *sig, size_t siglen);
	int (*signctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
	int (*signctx) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
		EVP_MD_CTX *mctx);
	int (*verifyctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
	int (*verifyctx) (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
		EVP_MD_CTX *mctx);
	int (*encrypt_init) (EVP_PKEY_CTX *ctx);
	int (*encrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
		const unsigned char *in, size_t inlen);
	int (*decrypt_init) (EVP_PKEY_CTX *ctx);
	int (*decrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
		const unsigned char *in, size_t inlen);
	int (*derive_init) (EVP_PKEY_CTX *ctx);
	int (*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
	int (*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
	int (*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value);
} /* EVP_PKEY_METHOD */ ;
#endif

#if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)

typedef struct {
	int nbits;
	BIGNUM *pub_exp;
	int gentmp[2];
	int pad_mode;
	const EVP_MD *md;
	const EVP_MD *mgf1md;
	int saltlen;
	unsigned char *tbuf;
} RSA_PKEY_CTX;

static int EVP_PKEY_CTX_get_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (rctx == NULL)
		return -1;
	*pmd = rctx->md;
	return 1;
}

static int EVP_PKEY_CTX_get_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (rctx == NULL)
		return -1;
	*pmd = rctx->md;
	return 1;
}

#endif

#if OPENSSL_VERSION_NUMBER < 0x10001000L

static int EVP_PKEY_CTX_get_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (rctx == NULL)
		return -1;
	*pmd = rctx->mgf1md;
	return 1;
}

static int EVP_PKEY_CTX_get_rsa_padding(EVP_PKEY_CTX *ctx, int *padding)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (rctx == NULL)
		return -1;
	*padding = rctx->pad_mode;
	return 1;
}

static int EVP_PKEY_CTX_get_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int *saltlen)
{
	RSA_PKEY_CTX *rctx = EVP_PKEY_CTX_get_data(ctx);
	if (rctx == NULL)
		return -1;
	*saltlen = rctx->saltlen;
	return 1;
}

static void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst, const EVP_PKEY_METHOD *src)
{
	memcpy((int *)dst + 2, (int *)src + 2, 25 * sizeof(void (*)()));
}

#endif

#if OPENSSL_VERSION_NUMBER < 0x100020d0L || defined(LIBRESSL_VERSION_NUMBER)
static void EVP_PKEY_meth_get_sign(EVP_PKEY_METHOD *pmeth,
		int (**psign_init) (EVP_PKEY_CTX *ctx),
		int (**psign) (EVP_PKEY_CTX *ctx,
			unsigned char *sig, size_t *siglen,
			const unsigned char *tbs, size_t tbslen))
{
	if (psign_init)
		*psign_init = pmeth->sign_init;
	if (psign)
		*psign = pmeth->sign;
}

static void EVP_PKEY_meth_get_decrypt(EVP_PKEY_METHOD *pmeth,
		int (**pdecrypt_init) (EVP_PKEY_CTX *ctx),
		int (**pdecrypt) (EVP_PKEY_CTX *ctx,
			unsigned char *out,
			size_t *outlen,
			const unsigned char *in,
			size_t inlen))
{
	if (pdecrypt_init)
		*pdecrypt_init = pmeth->decrypt_init;
	if (pdecrypt)
		*pdecrypt = pmeth->decrypt;
}
#endif

static CK_MECHANISM_TYPE pkcs11_md2ckm(const EVP_MD *md)
{
	switch (EVP_MD_type(md)) {
	case NID_sha1:
		return CKM_SHA_1;
	case NID_sha224:
		return CKM_SHA224;
	case NID_sha256:
		return CKM_SHA256;
	case NID_sha512:
		return CKM_SHA512;
	case NID_sha384:
		return CKM_SHA384;
	default:
		return 0;
	}
}

static CK_RSA_PKCS_MGF_TYPE pkcs11_md2ckg(const EVP_MD *md)
{
	switch (EVP_MD_type(md)) {
	case NID_sha1:
		return CKG_MGF1_SHA1;
	case NID_sha224:
		return CKG_MGF1_SHA224;
	case NID_sha256:
		return CKG_MGF1_SHA256;
	case NID_sha512:
		return CKG_MGF1_SHA512;
	case NID_sha384:
		return CKG_MGF1_SHA384;
	default:
		return 0;
	}
}

static int pkcs11_params_pss(CK_RSA_PKCS_PSS_PARAMS *pss,
		EVP_PKEY_CTX *ctx)
{
	const EVP_MD *sig_md, *mgf1_md;
	EVP_PKEY *evp_pkey;
	int salt_len;

	/* retrieve PSS parameters */
	if (EVP_PKEY_CTX_get_signature_md(ctx, &sig_md) <= 0)
		return -1;
	if (EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1_md) <= 0)
		return -1;
	if (!EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &salt_len))
		return -1;
	switch (salt_len) {
	case -1:
		salt_len = EVP_MD_size(sig_md);
		break;
	case -2:
		evp_pkey = EVP_PKEY_CTX_get0_pkey(ctx);
		if (evp_pkey == NULL)
			return -1;
		salt_len = EVP_PKEY_size(evp_pkey) - EVP_MD_size(sig_md) - 2;
		if (((EVP_PKEY_bits(evp_pkey) - 1) & 0x7) == 0)
			salt_len--;
		if (salt_len < 0) /* integer underflow detected */
			return -1;
	}
#ifdef DEBUG
	fprintf(stderr, "salt_len=%d sig_md=%s mdf1_md=%s\n",
		salt_len, EVP_MD_name(sig_md), EVP_MD_name(mgf1_md));
#endif

	/* fill the CK_RSA_PKCS_PSS_PARAMS structure */
	memset(pss, 0, sizeof(CK_RSA_PKCS_PSS_PARAMS));
	pss->hashAlg = pkcs11_md2ckm(sig_md);
	pss->mgf = pkcs11_md2ckg(mgf1_md);
	if (!pss->hashAlg || !pss->mgf)
		return -1;
	pss->sLen = salt_len;
	return 0;
}

static int pkcs11_params_oaep(CK_RSA_PKCS_OAEP_PARAMS *oaep,
		EVP_PKEY_CTX *ctx)
{
	const EVP_MD *oaep_md, *mgf1_md;

	/* retrieve OAEP parameters */
	if (EVP_PKEY_CTX_get_rsa_oaep_md(ctx, &oaep_md) <= 0)
		return -1;
	if (EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1_md) <= 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "oaep_md=%s mdf1_md=%s\n",
		EVP_MD_name(oaep_md), EVP_MD_name(mgf1_md));
#endif

	/* fill the CK_RSA_PKCS_OAEP_PARAMS structure */
	memset(oaep, 0, sizeof(CK_RSA_PKCS_OAEP_PARAMS));
	oaep->hashAlg = pkcs11_md2ckm(oaep_md);
	oaep->mgf = pkcs11_md2ckg(mgf1_md);
	if (!oaep->hashAlg || !oaep->mgf)
		return -1;
	/* we do not support the OAEP "label" parameter yet... */
	oaep->source = 0UL; /* empty parameter (label) */
	oaep->pSourceData = NULL;
	oaep->ulSourceDataLen = 0;
	return 0;
}

static int pkcs11_try_pkey_rsa_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	RSA *rsa;
	PKCS11_KEY *key;
	int rv = 0;
	CK_ULONG size = *siglen;
	PKCS11_SLOT *slot;
	PKCS11_CTX *ctx;
	PKCS11_KEY_private *kpriv;
	PKCS11_SLOT_private *spriv;
	PKCS11_CTX_private *cpriv;
	const EVP_MD *sig_md;

#ifdef DEBUG
	fprintf(stderr, "%s:%d pkcs11_try_pkey_rsa_sign() "
		"sig=%p *siglen=%lu tbs=%p tbslen=%lu\n",
		__FILE__, __LINE__, sig, *siglen, tbs, tbslen);
#endif
	pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
	if (pkey == NULL)
		return -1;
	rsa = EVP_PKEY_get0_RSA(pkey);
	if (rsa == NULL)
		return -1;
	key = pkcs11_get_ex_data_rsa(rsa);
	if (check_key_fork(key) < 0)
		return -1;
	slot = KEY2SLOT(key);
	ctx = KEY2CTX(key);
	kpriv = PRIVKEY(key);
	spriv = PRIVSLOT(slot);
	cpriv = PRIVCTX(ctx);

	if (evp_pkey_ctx == NULL)
		return -1;
	if (EVP_PKEY_CTX_get_signature_md(evp_pkey_ctx, &sig_md) <= 0)
		return -1;
	if (tbslen != (size_t)EVP_MD_size(sig_md))
		return -1;

	if (!cpriv->sign_initialized) {
		int padding;
		CK_MECHANISM mechanism;
		CK_RSA_PKCS_PSS_PARAMS pss_params;

		memset(&mechanism, 0, sizeof mechanism);
		EVP_PKEY_CTX_get_rsa_padding(evp_pkey_ctx, &padding);
		switch (padding) {
		case RSA_PKCS1_PSS_PADDING:
#ifdef DEBUG
			fprintf(stderr, "%s:%d padding=RSA_PKCS1_PSS_PADDING\n",
				__FILE__, __LINE__);
#endif
			if (pkcs11_params_pss(&pss_params, evp_pkey_ctx) < 0)
				return -1;
			mechanism.mechanism = CKM_RSA_PKCS_PSS;
			mechanism.pParameter = &pss_params;
			mechanism.ulParameterLen = sizeof pss_params;
			break;
		default:
#ifdef DEBUG
			fprintf(stderr, "%s:%d unsupported padding: %d\n",
				__FILE__, __LINE__, padding);
#endif
			return -1;
		} /* end switch(padding) */

		CRYPTO_THREAD_write_lock(cpriv->rwlock);
		rv = CRYPTOKI_call(ctx,
			C_SignInit(spriv->session, &mechanism, kpriv->object));
		if (!rv && kpriv->always_authenticate == CK_TRUE)
			rv = pkcs11_authenticate(key);
	}
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Sign(spriv->session, (CK_BYTE_PTR)tbs, tbslen, sig, &size));
	cpriv->sign_initialized = !rv && sig == NULL;
	if (!cpriv->sign_initialized)
		CRYPTO_THREAD_unlock(cpriv->rwlock);
#ifdef DEBUG
	fprintf(stderr, "%s:%d C_SignInit or C_Sign rv=%d\n",
		__FILE__, __LINE__, rv);
#endif

	if (rv != CKR_OK)
		return -1;
	*siglen = size;
	return 1;
}

static int pkcs11_pkey_rsa_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	int ret;

	ret = pkcs11_try_pkey_rsa_sign(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	if (ret < 0)
		ret = (*orig_pkey_rsa_sign)(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	return ret;
}

static int pkcs11_try_pkey_rsa_decrypt(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *out, size_t *outlen,
		const unsigned char *in, size_t inlen)
{
	EVP_PKEY *pkey;
	RSA *rsa;
	PKCS11_KEY *key;
	int rv = 0;
	CK_ULONG size = *outlen;
	PKCS11_SLOT *slot;
	PKCS11_CTX *ctx;
	PKCS11_KEY_private *kpriv;
	PKCS11_SLOT_private *spriv;
	PKCS11_CTX_private *cpriv;

#ifdef DEBUG
	fprintf(stderr, "%s:%d pkcs11_try_pkey_rsa_decrypt() "
		"out=%p *outlen=%lu in=%p inlen=%lu\n",
		__FILE__, __LINE__, out, *outlen, in, inlen);
#endif
	pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
	if (pkey == NULL)
		return -1;
	rsa = EVP_PKEY_get0_RSA(pkey);
	if (rsa == NULL)
		return -1;
	key = pkcs11_get_ex_data_rsa(rsa);
	if (check_key_fork(key) < 0)
		return -1;
	slot = KEY2SLOT(key);
	ctx = KEY2CTX(key);
	kpriv = PRIVKEY(key);
	spriv = PRIVSLOT(slot);
	cpriv = PRIVCTX(ctx);

	if (evp_pkey_ctx == NULL)
		return -1;

	if (!cpriv->decrypt_initialized) {
		int padding;
		CK_MECHANISM mechanism;
		CK_RSA_PKCS_OAEP_PARAMS oaep_params;

		memset(&mechanism, 0, sizeof mechanism);
		EVP_PKEY_CTX_get_rsa_padding(evp_pkey_ctx, &padding);
		switch (padding) {
		case RSA_PKCS1_OAEP_PADDING:
#ifdef DEBUG
			fprintf(stderr, "%s:%d padding=RSA_PKCS1_OAEP_PADDING\n",
				__FILE__, __LINE__);
#endif
			if (pkcs11_params_oaep(&oaep_params, evp_pkey_ctx) < 0)
				return -1;
			mechanism.mechanism = CKM_RSA_PKCS_OAEP;
			mechanism.pParameter = &oaep_params;
			mechanism.ulParameterLen = sizeof oaep_params;
			break;
		case CKM_RSA_PKCS:
#ifdef DEBUG
			fprintf(stderr, "%s:%d padding=CKM_RSA_PKCS\n",
				__FILE__, __LINE__);
#endif
			mechanism.pParameter = NULL;
			mechanism.ulParameterLen = 0;
			break;
		default:
#ifdef DEBUG
			fprintf(stderr, "%s:%d unsupported padding: %d\n",
				__FILE__, __LINE__, padding);
#endif
			return -1;
		} /* end switch(padding) */

		CRYPTO_THREAD_write_lock(cpriv->rwlock);
		rv = CRYPTOKI_call(ctx,
			C_DecryptInit(spriv->session, &mechanism, kpriv->object));
		if (!rv && kpriv->always_authenticate == CK_TRUE)
			rv = pkcs11_authenticate(key);
	}
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Decrypt(spriv->session, (CK_BYTE_PTR)in, inlen, out, &size));
	cpriv->decrypt_initialized = !rv && out == NULL;
	if (!cpriv->decrypt_initialized)
		CRYPTO_THREAD_unlock(cpriv->rwlock);
#ifdef DEBUG
	fprintf(stderr, "%s:%d C_DecryptInit or C_Decrypt rv=%d\n",
		__FILE__, __LINE__, rv);
#endif

	if (rv != CKR_OK)
		return -1;
	*outlen = size;
	return 1;
}

static int pkcs11_pkey_rsa_decrypt(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *out, size_t *outlen,
		const unsigned char *in, size_t inlen)
{
	int ret;

	ret = pkcs11_try_pkey_rsa_decrypt(evp_pkey_ctx, out, outlen, in, inlen);
	if (ret < 0)
		ret = (*orig_pkey_rsa_decrypt)(evp_pkey_ctx, out, outlen, in, inlen);
	return ret;
}

static EVP_PKEY_METHOD *pkcs11_pkey_method_rsa()
{
	EVP_PKEY_METHOD *orig_meth, *new_meth;

	orig_meth = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(EVP_PKEY_RSA);
	EVP_PKEY_meth_get_sign(orig_meth,
		&orig_pkey_rsa_sign_init, &orig_pkey_rsa_sign);
	EVP_PKEY_meth_get_decrypt(orig_meth,
		&orig_pkey_rsa_decrypt_init,
		&orig_pkey_rsa_decrypt);

	new_meth = EVP_PKEY_meth_new(EVP_PKEY_RSA,
		EVP_PKEY_FLAG_AUTOARGLEN);

	EVP_PKEY_meth_copy(new_meth, orig_meth);

	EVP_PKEY_meth_set_sign(new_meth,
		orig_pkey_rsa_sign_init, pkcs11_pkey_rsa_sign);
	EVP_PKEY_meth_set_decrypt(new_meth,
		orig_pkey_rsa_decrypt_init, pkcs11_pkey_rsa_decrypt);

	return new_meth;
}

#ifndef OPENSSL_NO_EC

static int pkcs11_try_pkey_ec_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	EVP_PKEY *pkey;
	EC_KEY *eckey;
	PKCS11_KEY *key;
	int rv = 0;
	CK_ULONG size = *siglen;
	PKCS11_SLOT *slot;
	PKCS11_CTX *ctx;
	PKCS11_KEY_private *kpriv;
	PKCS11_SLOT_private *spriv;
	PKCS11_CTX_private *cpriv;
	const EVP_MD *sig_md;
	ECDSA_SIG *ossl_sig;

#ifdef DEBUG
	fprintf(stderr, "%s:%d pkcs11_try_pkey_ec_sign() "
		"sig=%p *siglen=%lu tbs=%p tbslen=%lu\n",
		__FILE__, __LINE__, sig, *siglen, tbs, tbslen);
#endif

	ossl_sig = ECDSA_SIG_new();
	if (ossl_sig == NULL)
		return-1;

	pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
	if (pkey == NULL)
		return -1;

	eckey = (EC_KEY *)EVP_PKEY_get0_EC_KEY(pkey);
	if (eckey == NULL)
		return -1;

	if (*siglen < (size_t)ECDSA_size(eckey))
		return -1;

	key = pkcs11_get_ex_data_ec(eckey);
	if (check_key_fork(key) < 0)
		return -1;

	slot = KEY2SLOT(key);
	ctx = KEY2CTX(key);
	kpriv = PRIVKEY(key);
	spriv = PRIVSLOT(slot);
	cpriv = PRIVCTX(ctx);

	if (evp_pkey_ctx == NULL)
		return -1;

	if (EVP_PKEY_CTX_get_signature_md(evp_pkey_ctx, &sig_md) <= 0)
		return -1;

	if (tbslen < (size_t)EVP_MD_size(sig_md))
		return -1;

	if (!cpriv->sign_initialized) {
		CK_MECHANISM mechanism;
		memset(&mechanism, 0, sizeof mechanism);

		mechanism.mechanism = CKM_ECDSA;

		CRYPTO_THREAD_write_lock(cpriv->rwlock);
		rv = CRYPTOKI_call(ctx,
			C_SignInit(spriv->session, &mechanism, kpriv->object));
		if (!rv && kpriv->always_authenticate == CK_TRUE)
			rv = pkcs11_authenticate(key);
	}
	if (!rv)
		rv = CRYPTOKI_call(ctx,
			C_Sign(spriv->session, (CK_BYTE_PTR)tbs, tbslen, sig, &size));

	cpriv->sign_initialized = !rv && sig == NULL;
	if (!cpriv->sign_initialized)
		CRYPTO_THREAD_unlock(cpriv->rwlock);
#ifdef DEBUG
	fprintf(stderr, "%s:%d C_SignInit or C_Sign rv=%d\n",
		__FILE__, __LINE__, rv);
#endif

	if (rv == CKR_OK) {
		BIGNUM *r = BN_bin2bn(sig, size/2, NULL);
		BIGNUM *s = BN_bin2bn(sig + size/2, size/2, NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		ECDSA_SIG_set0(ossl_sig, r, s);
#else
		BN_free(ossl_sig->r);
		ossl_sig->r = r;
		BN_free(ossl_sig->s);
		ossl_sig->s = s;
#endif
		*siglen = i2d_ECDSA_SIG(ossl_sig, &sig);
	}

	ECDSA_SIG_free(ossl_sig);

	if (rv != CKR_OK)
		return -1;

	return 1;
}

static int pkcs11_pkey_ec_sign(EVP_PKEY_CTX *evp_pkey_ctx,
		unsigned char *sig, size_t *siglen,
		const unsigned char *tbs, size_t tbslen)
{
	int ret;

	ret = pkcs11_try_pkey_ec_sign(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	if (ret < 0)
		ret = (*orig_pkey_ec_sign)(evp_pkey_ctx, sig, siglen, tbs, tbslen);
	return ret;
}

static EVP_PKEY_METHOD *pkcs11_pkey_method_ec()
{
	EVP_PKEY_METHOD *orig_meth, *new_meth;

	orig_meth = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(EVP_PKEY_EC);
	EVP_PKEY_meth_get_sign(orig_meth,
		&orig_pkey_ec_sign_init, &orig_pkey_ec_sign);

	new_meth = EVP_PKEY_meth_new(EVP_PKEY_EC,
		EVP_PKEY_FLAG_AUTOARGLEN);

	EVP_PKEY_meth_copy(new_meth, orig_meth);

	EVP_PKEY_meth_set_sign(new_meth,
		orig_pkey_ec_sign_init, pkcs11_pkey_ec_sign);

	return new_meth;
}

#endif /* OPENSSL_NO_EC */

int PKCS11_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
		const int **nids, int nid)
{
	static int pkey_nids[] = {
		EVP_PKEY_RSA,
		EVP_PKEY_EC,
		0
	};
	static EVP_PKEY_METHOD *pkey_method_rsa = NULL;
	static EVP_PKEY_METHOD *pkey_method_ec = NULL;

	(void)e; /* squash the unused parameter warning */
	/* all PKCS#11 engines currently share the same pkey_meths */

	if (!pmeth) { /* get the list of supported nids */
		*nids = pkey_nids;
		return sizeof(pkey_nids) / sizeof(int) - 1;
	}

	/* get the EVP_PKEY_METHOD */
	switch (nid) {
	case EVP_PKEY_RSA:
		if (pkey_method_rsa == NULL)
			pkey_method_rsa = pkcs11_pkey_method_rsa();
		if (pkey_method_rsa == NULL)
			return 0;
		*pmeth = pkey_method_rsa;
		return 1; /* success */
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		if (pkey_method_ec == NULL)
			pkey_method_ec = pkcs11_pkey_method_ec();
		if (pkey_method_ec == NULL)
			return 0;
		*pmeth = pkey_method_ec;
		return 1; /* success */
#endif /* OPENSSL_NO_EC */
	}
	*pmeth = NULL;
	return 0;
}
