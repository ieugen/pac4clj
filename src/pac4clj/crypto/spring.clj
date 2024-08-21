(ns pac4clj.crypto.spring
  "Implement crypto for pac4j.
   
   This namespace requires extra dependencies on classpath:
   - org.springframework.security/spring-security-crypto
   - commons-logging"
  (:import (org.springframework.security.crypto.scrypt
            SCryptPasswordEncoder)
           (org.pac4j.core.credentials.password 
            PasswordEncoder SpringSecurityPasswordEncoder)))



(def scrypt-password-encoder
  (SCryptPasswordEncoder/defaultsForSpringSecurity_v5_8))

(def spring-security-password-encoder
  (SpringSecurityPasswordEncoder. scrypt-password-encoder))

(defn encode-pw
  "Helper. clojure wrapper to encode password."
  ([pass]
   (encode-pw spring-security-password-encoder pass))
  ([encoder pass]
   (.encode ^PasswordEncoder encoder pass)))

(comment

  (encode-pw "test")
  ;; => "$100801$EeDz+H/HeCzlIcIyqnK4Mw==$beTujRlOKIFeSGQefQK8YLVLbSUwIE17sQIE2kKOpKc=" 
  )
