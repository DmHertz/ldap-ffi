#lang racket/base

(require racket/class
         racket/contract         
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
    [modify (->m string? mod-list? #t)]
    [add    (->m string? mod-list? #t)]
    [delete (->m string? #t)]
    [search (->m string? string? (or/c 0 1 2) #t)]
    [get-data (->m (listof list?))]
    [count-entries (->m (or/c zero? positive?))]
    [rename-dn (->m string? string? string? (or/c 0 1) #t)]
    [unbind (->m #t)])])
 (struct-out exn:fail:ldap))

(define mod-list? (listof (list/c number? string? (listof string?))))

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

    (define (return-true-or-raise-error r)
      (or (zero? r)
          (raise-ldap-error (ldap-err2string r))))

    (define (do-thunk-or-raise-error r thunk)
      (if (zero? r)
          (thunk)
          (raise-ldap-error (ldap-err2string r))))

    ;; check ldap initialize code
    (return-true-or-raise-error initialized)
    ;; set protocol version
    (set-option #x0011 version)

    (define/private (read-ldap-message
                     [ldap-message (unbox ldap-message-c-ptr)])
      (define temp null)
      (let loop ([e ldap-message])
        (when e
          (define-values (fst-attr ber) (ldap-first-attribute ld e))
          (define g (list (cons "dn" (ldap-get-dn ld e))))
          (let inner-loop ([attr fst-attr])
            (when attr
              (define vals (ldap-get-values-len ld e attr))
              (for ([i (ldap-count-values-len vals)])
                (set! g (cons (cons attr (get-ber-value vals i)) g)))
              (ldap-value-free-len vals)
              (inner-loop (ldap-next-attribute ld e ber))))
          (set! temp (cons (reverse g) temp))
          (loop (ldap-next-entry ld e))))
      (set-box! ldap-data (reverse temp))
      #t)

    (define/public (set-option key value)
      (return-true-or-raise-error (ldap-set-option ld key value)))

    (define/public (bind [mechanism 0])
      (if (unbox ldap-valid)
          (raise-ldap-error "ldap is already bound")
          (do-thunk-or-raise-error (ldap-sasl-bind-s ld root-dn mechanism
                                                     (make-berval (string-length password)
                                                                  password)
                                                     #f #f #f)
                                   (λ () (set-box! ldap-valid #t) #t))))

    (define/private (add-modify ldap-ffi-fn user-dn mod-list)
      (return-true-or-raise-error (ldap-ffi-fn ld user-dn mod-list #f #f)))

    (define/public (modify user-dn mod-list)
      (add-modify ldap-modify-ext-s user-dn mod-list))
    
    (define/public (add user-dn mod-list)
      (add-modify ldap-add-ext-s user-dn mod-list))

    (define/public (delete dn)
      (return-true-or-raise-error (ldap-delete-ext-s ld #f #f)))
    
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
      (return-true-or-raise-error
       (ldap-rename-s ld dn newrdn new-superior delete-old-rdn #f #f)))

    (define/public (unbind)
      (if (unbox ldap-valid)
          (do-thunk-or-raise-error (ldap-unbind-ext-s ld #f #f) (λ () (set-box! ldap-valid #f) #t))
          (raise-ldap-error "ldap is already unbound")))))
