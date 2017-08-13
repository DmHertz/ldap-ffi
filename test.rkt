#lang racket/base

(require racket/class
         "ldap.rkt")

(module+ test
  (require rackunit)
  (provide ldap)
  (define ldap (new ldap%
                    [host     "ldap://192.168.0.81:389"]
                    [root-dn  "cn=Manager,dc=hz,dc=ru"]
                    [password "secret"])))

(module+ test-modrdn
  (require (submod ".." test))
  (send ldap bind)
  (send ldap rename-dn
        "uid=Dymok,ou=gatos,cn=Manager,dc=hz,dc=ru"
        "uid=Dymokhod"
        "ou=gatos,cn=Manager,dc=hz,dc=ru"
        ;; 0: don't delete old value
        ;; 1: delete old value
        1)
  (send ldap unbind))

(module+ test-add
  (require (submod ".." test))
  (send ldap bind)
  (send ldap add
        "uid=Blanco,ou=gatos,cn=Manager,dc=hz,dc=ru"
        '((#x0000 "objectClass" ("inetOrgPerson" "organizationalPerson" "person" "top"))
          (#x0000 "sn" ("O Senhor Branco"))
          (#x0000 "cn" ("Señor Blanco"))
          (#x0000 "description" ("Um bom gatinho branco"))
          (#x0000 "mail" ("elgatoblanco@example-gato.org"))))
  (send ldap unbind))

(module+ test-modify
  (require (submod ".." test))
  (send ldap bind)
  (send ldap modify
        "uid=Dymokhod,ou=gatos,cn=Manager,dc=hz,dc=ru"
        '((#x0002 "description" ("El gato gordo"))
          (#x0002 "mail" ("elgatogordo@example-gato.org"))))
  (send ldap unbind))

(module+ test-search
  (require (submod ".." test))
  (send ldap bind)
  (send ldap search
        "ou=gatos,cn=Manager,dc=hz,dc=ru"
        "(uid=*)" 2)
  (send ldap count-entries)
  (send ldap get-data)
  (send ldap unbind))
