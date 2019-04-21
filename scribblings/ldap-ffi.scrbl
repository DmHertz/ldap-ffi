#lang scribble/manual
@title{ldap-ffi: a Racket LDAP client built on top of libldap C API}

@require[@for-label[ldap-ffi
                    racket/base
                    racket/class]]

@author{@(author+email "Dmitry Bulaev" "dmitryhertz@gmail.com")}

@defmodule[ldap-ffi]

This package provides an FFI binding to the @hyperlink["http://www.openldap.org/devel/gitweb.cgi?p=openldap.git;a=summary" "libldap"]: the @hyperlink["https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol" "Lightweight Directory Access Protocol"] (LDAP) client library which is used for access to X.500 directory services.

@defclass[ldap% object% ()]{
 @defconstructor[([host string?]
                  [version  (or/c 2 3) 3]
                  [root-dn  (or/c string? #f) #f]
                  [password (or/c string? #f) #f])]{
  Constructs a new ldap object, initializes libldap and set the @racket[version] (LDAPv3 is default version).
 }
 @defmethod[(set-option [key positive?] [value positive?]) #t]{
  Set LDAP related options.

  If the @racket[set-option] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(bind [mechanism (or/c 0 1 2) 0]) #t]{
  Authenticate to the directory server.

  If the @racket[bind] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(modify [user-dn string?] [mod-list (listof (list/c number? string? (listof string?)))]) #t]{
  Modify an entry.
  
  If the @racket[modify] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(add [user-dn string?] [mod-list (listof (list/c number? string? (listof string?)))]) #t]{
  Add a new entry.

  If the @racket[add] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(delete [dn string?]) #t]{
  Delete an entry.

  If the @racket[delete] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(search [base-dn string?] [fltr string?] [scope (or/c 0 1 2)]) #t]{
  Search for the LDAP directory entries and write retrieved data to the internal box storage.

  If the @racket[search] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(search* [base-dn string?] [fltr string?] [scope (or/c 0 1 2)]) (listof list?)]{
  Equivalent to @racket[search] but returs @racket[(listof list?)] (instead of @racket[#t]) then clears the object's internal ldap-message storage.

  If the @racket[search*] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(compare [dn string?] [attr string?] [value string?]) boolean?]{
  Check whether or not an entry contains the same attribute value as given.

  If the @racket[compare] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(get-data) (listof list?)]{
  Return retrieved data from the internal box storage. It doesn't make a request to the LDAP server.
 }
 @defmethod[(count-entries) (or/c zero? positive?)]{
  Return the number of retrieved entries or 0 otherwise.
 }
 @defmethod[(set-password [user string?] [oldpw string?] [newpw string?]) boolean?]{
  Set a new password.

  If the @racket[set-password] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(rename-dn [dn string?] [newrdn string?] [new-superior string?] [delete-old-rdn (or/c 0 1)]) #t]{
  Rename the DN of an LDAP entry or move it from one superior to another.

  If the @racket[rename-dn] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(unbind) #t]{
  Close the connection to the directory server.

  If the @racket[unbind] fails, then an instance of exn:fail:libldap is raised.
 }
 @defmethod[(clear) void?]{
  Clear the object's internal box storage where the latest returned ldap-message storages itself.  
 }
}

@defstruct[(exn:fail:ldap exn:fail:user) ()]{
 An exception structure type for reporting errors from the underlying
 libldap library.
}
