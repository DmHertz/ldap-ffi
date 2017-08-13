#lang racket/base

(require racket/class
         racket/contract
         racket/bool
         data/gvector
         "ffi.rkt")

(provide
 (contract-out
  [ldap%
   (class/c
    (init [host    string?]
          [version (or/c 2 3)])
    (init-field [root-dn  (or/c string? #f)]
                [password (or/c string? #f)])
    [set-option (->m positive? positive? #t)]
    [bind   (->*m () ((or/c 0 1 2)) #t)]
    [modify (->m string? (listof list?) #t)]
    [add    (->m string? (listof list?) #t)]
    [delete (->m string? #t)]
    [search (->m string? string? (or/c 0 1 2) #t)]
    [get-data (->m (listof list?))]
    [count-entries (->m (or/c zero? positive?))]
    [rename-dn (->m string? string? string? (or/c 0 1) #t)]
    [unbind (->m #t)])])
 (struct-out exn:fail:ldap))

(define-struct (exn:fail:ldap exn:fail:user) ())

(define (raise-ldap-error msg)
  (raise (exn:fail:ldap msg (current-continuation-marks))))

(define ldap%
  (class object%
    (super-new)
    (init host
          [version 3])
    (init-field [root-dn  #f]
                [password #f])

    (define-values (initialized ld)
      (ldap-initialize host))

    (define ldap-data (box '(())))
    (define ldap-valid (box #f))
    (define ldap-message-c-ptr (box #f))

    (define/private (return-true-or-raise-error r)
      (cond [(zero? r) #t]
            [else (raise-ldap-error (ldap-err2string r))]))

    (define/private (do-thunk-or-raise-error r thunk)
      (cond [(and (zero? r)) (thunk)]
            [else (raise-ldap-error (ldap-err2string r))]))

    ;; check ldap initialize code
    (return-true-or-raise-error initialized)
    ;; set protocol version
    (set-option #x0011 version)

    (define/private (read-ldap-message
                     [ldap-message (unbox ldap-message-c-ptr)])
      (define temp-vector (make-vector (count-entries)))

      (let loop ([i 0]
                 [e ldap-message]
                 [g (make-gvector)])
        (unless (false? e)

          (define-values (fst-attr ber) (ldap-first-attribute ld e))
          (gvector-add! g (cons "dn" (ldap-get-dn ld e)))

          (let inner-loop ([attr fst-attr])
            (unless (false? attr)
              (define vals (ldap-get-values-len ld e attr))
              (for ([i (ldap-count-values-len vals)])
                (gvector-add! g (cons attr (get-ber-value vals i))))

              (ldap-value-free-len vals)
              (inner-loop (ldap-next-attribute ld e ber))))

          (vector-set! temp-vector i (gvector->list g))

          (loop (add1 i)
                (ldap-next-entry ld e)
                (make-gvector))))

      (set-box! ldap-data (vector->list temp-vector))
      #t)

    (define/public (set-option key value)
      (define r (ldap-set-option ld key value))
      (return-true-or-raise-error r))

    (define/public (bind [mechanism 0])
      (cond [(not (false? (unbox ldap-valid)))
             (raise-ldap-error "ldap is already bound")]
            [(false? (unbox ldap-valid))
             (define r (ldap-sasl-bind-s ld root-dn mechanism
                                         (make-berval (string-length password)
                                                      password)
                                         #f #f #f))
             (do-thunk-or-raise-error r (λ () (set-box! ldap-valid #t) #t))]))

    (define/private (add-modify ldap-ffi-fn user-dn mod-list)
      (define mod (for/list ([m mod-list])
                    (apply lmod m)))
      (define mod-ptr (ldapmod-c-array-ptr mod))
      (define r (ldap-ffi-fn ld user-dn mod-ptr #f #f))
      (return-true-or-raise-error r))

    (define/public (modify user-dn mod-list)
      (add-modify ldap-modify-ext-s user-dn mod-list))
    
    (define/public (add user-dn mod-list)
      (add-modify ldap-add-ext-s user-dn mod-list))

    (define/public (delete dn)
      (define r (ldap-delete-ext-s ld #f #f))
      (return-true-or-raise-error r))
    
    (define/public (search base-dn fltr scope)
      (define-values (r msg)
        (ldap-search-ext-s ld base-dn scope fltr #f 0 #f #f #f 0))

      (do-thunk-or-raise-error
       r (λ ()
           (set-box! ldap-message-c-ptr msg)
           (read-ldap-message msg) #t)))

    (define/public (get-data)
      (unbox ldap-data))

    (define/public (count-entries)
      (ldap-count-entries ld (unbox ldap-message-c-ptr)))

    (define/public (rename-dn dn newrdn new-superior delete-old-rdn)
      (define r (ldap-rename-s ld dn newrdn new-superior delete-old-rdn #f #f))
      (return-true-or-raise-error r))

    (define/public (unbind)
      (cond [(not (false? (unbox ldap-valid)))
             (define r (ldap-unbind-ext-s ld #f #f))
             (do-thunk-or-raise-error r (λ () (set-box! ldap-valid #f) #t))]
            [(false? (unbox ldap-valid))
             (raise-ldap-error "ldap is already unbound")]))))
