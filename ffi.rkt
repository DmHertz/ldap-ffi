#lang racket

(require ffi/unsafe
         ffi/unsafe/define)

(provide
 ldap-initialize
 ldap-set-option
 ldap-sasl-bind-s
 ldap-unbind-ext-s
 ldap-search-ext-s
 ldap-err2string
 ldap-get-dn
 ldap-first-attribute
 ldap-next-attribute
 ldap-get-values-len
 ldap-count-values-len
 ldap-value-free-len
 ldap-first-entry
 ldap-next-entry
 ldap-count-entries
 ldap-add-ext-s
 ldap-modify-ext-s
 ldap-rename-s
 ldap-delete-ext-s
 ldapmod-c-array-ptr
 get-ber-value
 (struct-out berval)
 (struct-out lmod))

(define-ffi-definer defldap (ffi-lib "libldap" '("2" "4")))

;; typedef struct ldap LDAP;
(define _ldap-pointer (_or-null (_cpointer 'ldap)))

#|
/* structure for returning a sequence of octet strings + length */
typedef struct berval {
        ber_len_t    bv_len;
        char        *bv_val;
} BerValue;
|#
(define-cstruct _berval
  ([bv_len _ulong]
   [bv_val _string]))

#|
/*
 * This structure represents both ldap messages and ldap responses.
 * These are really the same, except in the case of search responses,
 * where a response has multiple messages.
 */

struct ldapmsg {
        ber_int_t       lm_msgid;      /* the message id */
        ber_tag_t       lm_msgtype;    /* the message type */
        BerElement     *lm_ber;        /* the ber encoded message contents */
        struct ldapmsg *lm_chain;      /* for search - next msg in the resp */
        struct ldapmsg *lm_chain_tail;
        struct ldapmsg *lm_next;       /* next response */
        time_t          lm_time;       /* used to maintain cache */
};
|#
#;(define-cstruct _ldapmsg
    ([lm_msgid      _int]
     [lm_msgtype    _int]
     [lm_ber        _pointer]
     [lm_chain      _ldapmsg-pointer/null]
     [lm_chain_tail _ldapmsg-pointer/null]
     [lm_next       _ldapmsg-pointer/null]
     [lm_time       _ulong]))

#;(define ld (make-ldapmsg 0 0 #f #f #f #f 0))

#|
LDAP_F( int )
ldap_initialize LDAP_P((
    LDAP **ldp,
    LDAP_CONST char *url ));
|#
;; initialize the LDAP library without opening
;; a connection to a server
(defldap ldap-initialize (_fun [ld : (_ptr o _ldap-pointer)]
                               _string
                               -> [r : _int]
                               -> (values r ld))
  #:c-id ldap_initialize)

#|
LDAP_F( int )
ldap_set_option LDAP_P((
        LDAP *ld,
        int option,
        LDAP_CONST void *invalue));
|#
(defldap ldap-set-option (_fun _pointer
                               _int
                               (_ptr i _int)
                               -> _int)
  #:c-id ldap_set_option)

#|
LDAP_F( int )
ldap_sasl_bind_s LDAP_P((
        LDAP            *ld,
        LDAP_CONST char *dn,
        LDAP_CONST char *mechanism,
        struct berval   *cred,
        LDAPControl     **serverctrls,
        LDAPControl     **clientctrls,
        struct berval   **servercredp ));
|#
(defldap ldap-sasl-bind-s (_fun _pointer
                                _string
                                _int
                                (_ptr i _berval)
                                _pointer
                                _pointer
                                _berval-pointer/null
                                -> _int)
  #:c-id ldap_sasl_bind_s)

#|
LDAP_F( int )
ldap_unbind_ext_s LDAP_P((
        LDAP        *ld,
        LDAPControl **serverctrls,
        LDAPControl **clientctrls));
|#
(defldap ldap-unbind-ext-s (_fun _pointer
                                 _pointer
                                 _pointer
                                 -> _int)
  #:c-id ldap_unbind_ext_s)

#|
LDAP_F( int )
ldap_search_ext_s LDAP_P((
        LDAP               *ld,
        LDAP_CONST char    *base,
        int                scope,
        LDAP_CONST char    *filter,
        char               **attrs,
        int                attrsonly,
        LDAPControl        **serverctrls,
        LDAPControl        **clientctrls,
        struct timeval     *timeout,
        int                sizelimit,
        LDAPMessage        **res ));
|#
(defldap ldap-search-ext-s (_fun _pointer
                                 _string
                                 _int
                                 _string
                                 _pointer
                                 _int
                                 _pointer
                                 _pointer
                                 _pointer
                                 _int
                                 (res : (_ptr o _pointer))
                                 -> (r : _int)
                                 -> (values r res))
  #:c-id ldap_search_ext_s)

;; LDAP_F( char * ) ldap_err2string LDAP_P(( int err ));
(defldap ldap-err2string (_fun _int
                               -> _string)
  #:c-id ldap_err2string)

;; LDAP_F( char * ) ldap_get_dn LDAP_P((LDAP *ld, LDAPMessage *entry ));
(defldap ldap-get-dn (_fun _pointer
                           _pointer
                           -> _string)
  #:c-id ldap_get_dn)

#|
LDAP_F( char * )
ldap_first_attribute LDAP_P((
        LDAP *ld,
        LDAPMessage *entry,
        BerElement **ber ));
|#
(defldap ldap-first-attribute (_fun _pointer
                                    _pointer
                                    (ber : (_ptr o _pointer))
                                    -> (fst-attr : _string)
                                    -> (values fst-attr ber))
  #:c-id ldap_first_attribute)

#|
LDAP_F( char * )
ldap_next_attribute LDAP_P((
        LDAP *ld,
        LDAPMessage *entry,
        BerElement *ber ));
|#
(defldap ldap-next-attribute (_fun _pointer
                                   _pointer
                                   _pointer
                                   -> _string)
  #:c-id ldap_next_attribute)

#|
LDAP_F( struct berval ** )
ldap_get_values_len LDAP_P((
        LDAP *ld,
        LDAPMessage *entry,
        LDAP_CONST char *target ));
|#
(defldap ldap-get-values-len (_fun _pointer
                                   _pointer
                                   _string
                                   -> _berval-pointer)
  #:c-id ldap_get_values_len)

;; LDAP_F( int ) ldap_count_values_len LDAP_P(( struct berval **vals ));
(defldap ldap-count-values-len (_fun _berval-pointer
                                     -> _int)
  #:c-id ldap_count_values_len)

;; LDAP_F( void ) ldap_value_free_len LDAP_P(( struct berval **vals ));
(defldap ldap-value-free-len (_fun _berval-pointer
                                   -> _void)
  #:c-id ldap_value_free_len)

;; LDAP_F( LDAPMessage * ) ldap_first_entry LDAP_P(( LDAP *ld, LDAPMessage *chain ));
(defldap ldap-first-entry (_fun _pointer
                                _pointer
                                -> _pointer)
  #:c-id ldap_first_entry)


;; LDAP_F( LDAPMessage * ) ldap_next_entry LDAP_P(( LDAP *ld, LDAPMessage *entry ));
(defldap ldap-next-entry (_fun _pointer
                               _pointer
                               -> _pointer)
  #:c-id ldap_next_entry)

;; LDAP_F( int ) ldap_count_entries LDAP_P((LDAP *ld, LDAPMessage *chain ));
(defldap ldap-count-entries [_fun _pointer
                                  _pointer
                                  -> _int]
  #:c-id ldap_count_entries)

#|
/* for modifications */
typedef struct ldapmod {
        int    mod_op;

#define LDAP_MOD_OP           (0x0007)
#define LDAP_MOD_ADD          (0x0000)
#define LDAP_MOD_DELETE       (0x0001)
#define LDAP_MOD_REPLACE      (0x0002)
#define LDAP_MOD_INCREMENT    (0x0003) /* OpenLDAP extension */
#define LDAP_MOD_BVALUES      (0x0080)
/* IMPORTANT: do not use code 0x1000 (or above),
 * it is used internally by the backends!
 * (see ldap/servers/slapd/slap.h)
 */
        char           *mod_type;
        union mod_vals_u {
        char           **modv_strvals;
        struct berval  **modv_bvals;
} mod_vals;
#define mod_values     mod_vals.modv_strvals
#define mod_bvalues    mod_vals.modv_bvals
} LDAPMod;
|#
(define-cstruct _ldapmod
  ([mod_op      _int]
   [mod_type    _string]
   [mod_values  (_or-null _pointer)]
   #;[mod_bvalues _pointer]))

(define _c-ldap-mod (_or-null _ldapmod-pointer))

(struct lmod (op type vals)
  #:transparent
  #:guard
  (λ (op type vals name)
    (unless (number? op)
      (error "not a valid type of op"))
    (unless (string? type)
      (error "not a valid type of type field"))
    (unless (list? vals)
      (error "not a valid type of vals"))
    (values op type vals)))

(define (ldapmod-c-array-ptr lmod-lst)
  (define len  (length lmod-lst))
  (define lmt  (_array _c-ldap-mod (add1 len)))
  (define lmx  (malloc lmt))
  (define mods (ptr-ref lmx lmt 0))
  ;; set mods
  (for ([mod lmod-lst]
        [i (in-naturals)])
    (define l (length (lmod-vals mod)))
    (define t (_array _string (add1 l)))
    (define x (malloc t))
    (define a (ptr-ref x t 0))

    (for ([v (lmod-vals mod)]
          [j (in-naturals)])
      (array-set! a j v))
    ;; set NULL to the latest array position
    (array-set! a l #f)
    ;; set c-structs to mods array
    (define c-mod
      (make-ldapmod (lmod-op mod)
                    (lmod-type mod)
                    (array-ptr a)))
    (array-set! mods i c-mod))
  ;; set NULL to the latest array position
  (array-set! mods len #f)
  ;; return _cpointer of array of mods
  (array-ptr mods))

#|
LDAP_F( int )
ldap_add_ext_s LDAP_P((
        LDAP             *ld,
        LDAP_CONST char  *dn,
        LDAPMod         **attrs,
        LDAPControl     **serverctrls,
        LDAPControl     **clientctrls ));
|#
(defldap ldap-add-ext-s (_fun _pointer
                              _string
                              (_or-null _pointer)
                              _pointer
                              _pointer
                              -> _int)
  #:c-id ldap_add_ext_s)

#|
LDAP_F( int )
ldap_modify_ext_s LDAP_P((
    LDAP            *ld,
    LDAP_CONST char *dn,
    LDAPMod         **mods,
    LDAPControl     **serverctrls,
    LDAPControl     **clientctrls ));
|#
(defldap ldap-modify-ext-s (_fun _pointer
                                 _string
                                 (_or-null _pointer)
                                 _pointer
                                 _pointer
                                 -> _int)
  #:c-id ldap_modify_ext_s)

#|
LDAP_F( int )
ldap_rename_s LDAP_P((
        LDAP *ld,
        LDAP_CONST char *dn,
        LDAP_CONST char *newrdn,
        LDAP_CONST char *newSuperior,
        int deleteoldrdn,
        LDAPControl **sctrls,
        LDAPControl **cctrls ));
|#
(defldap ldap-rename-s (_fun _pointer
                             _string
                             _string
                             _string
                             _int
                             _pointer
                             _pointer
                             -> _int)
  #:c-id ldap_rename_s)

#|
LDAP_F( int )
ldap_delete_ext_s LDAP_P((
        LDAP             *ld,
        LDAP_CONST char  *dn,
        LDAPControl     **serverctrls,
        LDAPControl     **clientctrls ));

|#
(defldap ldap-delete-ext-s (_fun _pointer
                                 _string
                                 _pointer
                                 _pointer
                                 -> _int)
  #:c-id ldap_delete_ext_s)

;; misc
(define (get-ber-value vals i)
  (berval-bv_val (ptr-ref vals _berval-pointer i)))
