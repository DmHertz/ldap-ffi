#lang info
(define collection "ldap-ffi")
(define deps '("base"
               "rackunit-lib"))
(define build-deps '("scribble-lib" "racket-doc"))
(define scribblings '(("scribblings/ldap-ffi.scrbl" ())))
(define pkg-desc "A Racket LDAP client built on top of libldap C API")
(define version "0.1")
