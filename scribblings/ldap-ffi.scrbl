#lang scribble/manual
@title{ldap-ffi: a Racket LDAP client built on top of libldap C API}

@require[@for-label[ldap-ffi
                    racket/base
                    racket/class]]

@author{@(author+email "Dmitry Bulaev" "dmitryhertz@gmail.com")}

@defmodule[ldap-ffi]

This library provides an FFI binding to the @hyperlink["http://www.openldap.org" "libldap"]: the Lightweight Directory Access Protocol (LDAP) client library which is used for access to X.500 directory services.

@defclass[ldap% object% ()]{
 @defconstructor[([host string?]
                  [version  (or/c 2 3) 3]
                  [root-dn  (or/c string? #f) #f]
                  [password (or/c string? #f) #f])]{
  Constructs a new ldap object, initializes libldap and set the @racket[version] (LDAPv3 is default).
 }
 @defmethod[(set-option [key positive?] [value positive?]) #t]{
  Set LDAP related options.

  If the set-option fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(bind [mechanism (or/c 0 1 2) 0]) #t]{
  Bind to the directory.

  If the @racket[bind] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(modify [user-dn string?] [mod-list (listof list?)]) #t]{
  Modify an entry.
  If the @racket[modify] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(add [user-dn string?] [mod-list (listof list?)]) #t]{
  Add an entry.

  If the @racket[add] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(delete [dn string?]) #t]{
  Delete an entry.

  If the @racket[delete] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(search [base-dn string?] [fltr string?] [scope (or/c 0 1 2)]) #t]{
  Search the LDAP directory and write result data to internal box storage.

  If the @racket[search] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(get-data) (listof list?)]{
  Returns received data from internal box storage. It doesn't make a request to the LDAP server.
 }
 @defmethod[(count-entries) (or/c zero? positive?)]{
  Returns the number of received entries or 0 otherwise.
 }
 @defmethod[(rename-dn [dn string?] [newrdn string?] [new-superior string?] [delete-old-rdn (or/c 0 1)]) #t]{
  Rename the DN of an LDAP entry.

  If the @racket[rename-dn] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(unbind) #t]{
  Unbind from the directory.

  If the @racket[unbind] fails, then an instance of exn:fail:libldap is raised.
 }
}

@defstruct[(exn:fail:ldap exn:fail:user) ()]{
 An exception structure type for reporting errors from the underlying
 libldap library.
}