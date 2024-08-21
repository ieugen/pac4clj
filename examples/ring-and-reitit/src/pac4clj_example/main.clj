(ns pac4clj-example.main
  "Explore using ring with pac4j"
  (:require [dialog.logger :as logger]
            [hiccup2.core :as h]
            [mount.core :as mount :refer [defstate]]
            [pac4clj.core :as p4]
            [pac4clj.crypto.spring :as p4cs]
            [reitit.core :as r]
            [ring.adapter.jetty :refer [run-jetty]]
            [reitit.ring :as rring]
            [ring.middleware.anti-forgery :refer [*anti-forgery-token*]]
            [ring.middleware.defaults :as rmd]
            [ring.middleware.file :refer [wrap-file]]
            [ring.middleware.lint :refer [wrap-lint]]
            [ring.middleware.session-timeout :refer [wrap-idle-session-timeout]]
            [ring.util.response :as ur])
  (:import (java.util HashMap List)
           (org.pac4j.core.client Client Clients)
           (org.pac4j.core.client.direct AnonymousClient)
           (org.pac4j.core.profile CommonProfile)
           (org.pac4j.core.profile.creator AuthenticatorProfileCreator)
           (org.pac4j.core.profile.definition CommonProfileDefinition)
           (org.pac4j.core.profile.factory ProfileFactory)
           (org.pac4j.core.profile.service InMemoryProfileService ProfileService)
           (org.pac4j.http.client.direct DirectBasicAuthClient)
           (org.pac4j.http.client.indirect FormClient)
           (org.pac4j.http.credentials.authenticator.test SimpleTestUsernamePasswordAuthenticator)
           (org.pac4j.oidc.client OidcClient)
           (org.pac4j.oidc.config OidcConfiguration)))

(set! *warn-on-reflection* true)
(logger/initialize!)

(defn make-profile-factory
  []
  (reify ProfileFactory
    (apply [_this _params]
      (CommonProfile.))))

(def app-profiles (HashMap.))

(defn in-memory-profile-service
  (^ProfileService []
   (in-memory-profile-service app-profiles make-profile-factory))
  (^ProfileService [profiles profile-factory]
   (doto (InMemoryProfileService. profiles (profile-factory))
     (.setPasswordEncoder p4cs/spring-security-password-encoder))))

(def in-mem-authenticator ^ProfileService (in-memory-profile-service))

(defn make-pac4j-common-profile
  "Build a pac4j CommonProfile"
  (^CommonProfile [user-id user-attrs]
   (make-pac4j-common-profile user-id user-attrs []))
  (^CommonProfile [user-id user-attrs roles]
   (doto (CommonProfile.)
     (.build user-id user-attrs)
     (.addRoles roles))))

^:rct/test
(comment
  (make-pac4j-common-profile "ieugen"
                             {"username" "ieugen"}
                             #{"admin" "user"})

  (make-pac4j-common-profile "ieugen"
                             {"username" "ieugen"}
                             ["admin"])
  ;; => #object[org.pac4j.core.profile.CommonProfile 0x2dd04c33 "CommonProfile(super=BasicUserProfile(logger=dialog.logger.DialogLogger@4521d745, id=ieugen, attributes={username=ieugen}, authenticationAttributes={}, isRemembered=false, roles=[admin], clientName=null, linkedId=null, canAttributesBeMerged=true))"]
  )

(defn populate-memory-user-store!
  []
  (doto ^ProfileService in-mem-authenticator
    (.create (make-pac4j-common-profile "ieugen-id"
                                        {"username" "ieugen"
                                         CommonProfileDefinition/EMAIL "eugen@ieugen.ro"
                                         CommonProfileDefinition/FIRST_NAME "Eugen"
                                         CommonProfileDefinition/FAMILY_NAME "Stan"}
                                        ["admin" "user" "ROLE_ADMIN"])
             "s3cret")
    (.create (make-pac4j-common-profile "ieugen-guest-id"
                                        {"username" "ieugen-guest"
                                         CommonProfileDefinition/EMAIL "eugen-guest@ieugen.ro"
                                         CommonProfileDefinition/FIRST_NAME "Eugen"
                                         CommonProfileDefinition/FAMILY_NAME "Stan"}
                                        ["user"])
             "s3cret")
    (.create (make-pac4j-common-profile "sandrei-id"
                                        {"username" "sandrei"
                                         CommonProfileDefinition/EMAIL "andrei@ieugen.ro"
                                         CommonProfileDefinition/FIRST_NAME "Andrei"
                                         CommonProfileDefinition/FAMILY_NAME "Stan"}
                                        ["admin" "user" "ROLE_ADMIN"])

             "s3cret")))
;; insert some profiles
(populate-memory-user-store!)

(def my-session-store-data (atom {}))

(def ^:private simple-test-username-pw-authenticator
  (SimpleTestUsernamePasswordAuthenticator.))


(def pac4j-anonymous-client ^Client (AnonymousClient.))

(def pac4j-basic-auth-client ^Client
  (DirectBasicAuthClient. (in-memory-profile-service)))

(def pac4j-form-client ^Client
  (doto
   (FormClient. "/login"
                (in-memory-profile-service)
                (AuthenticatorProfileCreator.))
    #_(FormClient/.setSaveProfileInSession false)))

(def pac4j-oidc-config ^OidcConfiguration
  (doto (OidcConfiguration/new)
    (OidcConfiguration/.setClientId "snm")
    (OidcConfiguration/.setSecret "zH3tExTPkg642z4qGyQE0CqvjF7qAkB7FK0RMHQEc6cS9SY6")
    (OidcConfiguration/.setDiscoveryURI
     "https://idm.ieugen.ro/oauth2/openid/snm/.well-known/openid-configuration")
    (OidcConfiguration/.setScope "openid profile email phone groups")
    #_(OidcConfiguration/.setUseNonce true)))

(def pac4j-oidc-client ^Client
  (doto (OidcClient/new pac4j-oidc-config)
    (OidcClient/.setCallbackUrl "http://localhost:8080/callback")))

(def pac4j-clients ^Clients
  (doto (Clients.)
    (.setCallbackUrl "/callback")
    (^[List] Clients/.setClients [pac4j-form-client
                                  pac4j-oidc-client
                                 ;; pac4j-basic-auth-client
                                 ;; pac4j-anonymous-client
                                  ])))

(defn login-form
  ([] (login-form {:anti-forgery-token (force *anti-forgery-token*)}))
  ([{:keys [anti-forgery-token]}]
   [:html
    [:head]
    [:body
     [:a {:href "/"} "Acasă"]
     [:br]
     [:form {:action "/callback" :method "POST"}
      [:label {:for "username"} "Username"]
      [:input {:type "text" :name "username"}]
      [:br]
      [:label {:for "password"} "Password"]
      [:input {:type "password" :name "password"}]
      [:input {:type "hidden"
               :name "__anti-forgery-token"
               :value anti-forgery-token}]
      [:input {:type "hidden"
               :name "client_name"
               :value "FormClient"}]
      [:br]
      [:input {:type "submit" :value "Login"}]]]]))

(comment
  (binding [*anti-forgery-token* "demmo"]
    (h/html (login-form))))

(defn login-handler
  [req]
  (->
   (ur/response
    (str
     (h/html (login-form))))
   (ur/content-type "text/html")))

(defn main-page
  [{:keys [uri]}]
  [:html
   [:head]
   [:body
    [:p (str "Suntem la " uri)]
    [:a {:href "/"} "Acasă"]
    [:br]
    [:a {:href "/login"} "Login"]
    [:br]
    [:a {:href "/protected"} "Protected"]]])

(defn simple-handler
  [req]
  {:status 200
   :body (str (h/html (main-page {:uri (:uri req)})))
   :headers {"content-type" "text/html"}})

(defn protected-handler
  [req]
  {:status 200
   :body (str "Protected " (:uri req))
   :headers {"content-type" "text/plain"}})

(def counter (atom 0))

(def reitit-router
  (rring/router
   [["/" {:get simple-handler}]
    ["/login" {:get login-handler}]
    ["/callback" {:get p4/pac4j-callback-handler
                  :post p4/pac4j-callback-handler}]
    ["/test" {:get (fn [req]
                     (let [session (:session req)
                           session (assoc session :coounter (swap! counter inc))]
                       (-> (ur/response "session-test")
                           (ur/content-type "text/html")
                           (assoc :session session))))}]
    ["/protected" {:get protected-handler
                   :roles #{"ADMIN_ROLE"}
                   :middleware [p4/wrap-pac4j]}]]))

(comment
  (r/match-by-path reitit-router "/")

  (r/routes reitit-router))

(def site-opts (-> rmd/site-defaults
                  ;;  (assoc-in [:params :keywordize] false)
                   ;; disabled csrf anti-forgery in ring for pac4j
                  ;;  (assoc-in [:security :anti-forgery] false)
                   (assoc-in [:static :files] "public")
                   (assoc-in [:responses :content-types] false)
                   (assoc-in [:session :cookie-name] "ID")
                   (assoc-in [:session :store] (p4/make-pac4j-memory-store my-session-store-data))))

(defstate web-server
  :start (run-jetty (rring/ring-handler
                     reitit-router
                     (rring/create-default-handler)
                     {:middleware [wrap-lint
                                   #(rmd/wrap-defaults % site-opts)
                                   #(wrap-file % "public")
                                   #(wrap-idle-session-timeout %
                                                               {:timeout 600
                                                                :timeout-response
                                                                {:status 302
                                                                 :headers {"location" "/login"
                                                                           "x-reason" "session-timeout"}}})]})
                    {:port 8080
                     :join? false
                     :send-server-version? false})
  :stop (.stop web-server))

(comment

  (require '[clojure.tools.trace :as t])

  (t/trace-ns ring-pac4j)


  (mount/start)
  (mount/stop)

  (reset! my-session-store-data {})
  my-session-store-data

  (def s (get @my-session-store-data "d872424f-86ad-49e6-881f-331705f130ae"))

  (def up (-> (get s "pac4jUserProfiles")
              (get "FormClient")))

  (.addRole up "admin")

  up)
  
  