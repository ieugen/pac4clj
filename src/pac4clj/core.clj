(ns pac4clj.core
  "Explore using ring with pac4j"
  (:require [clj-commons.byte-streams :as bs] 
            [clojure.string :as str]
            [clojure.tools.logging :as log]
            [ring.middleware.session.store :refer [read-session SessionStore]]
            [ring.util.request :as rur]
            [ring.util.response :as ur])
  (:import (java.net URLEncoder)
           (java.util HashMap Optional UUID)
           (org.pac4j.core.config Config)
           (org.pac4j.core.context
            Cookie
            FrameworkParameters
            WebContext
            WebContextFactory)
           (org.pac4j.core.context.session SessionStoreFactory)
           (org.pac4j.core.engine CallbackLogic SecurityGrantedAccessAdapter SecurityLogic)
           (org.pac4j.core.exception TechnicalException)
           (org.pac4j.core.exception.http HttpAction WithContentAction WithLocationAction)
           (org.pac4j.core.http.adapter HttpActionAdapter)))


(defprotocol RequestResponseProtocol
  (get-request [this] "Return ring request map wrapped in an atom")
  (get-response [this] "Return ring response map, if any, wrapped in an atom"))

(defn encode-params 
  "Encode request params map as URL - string representation.
   It will sort map by key to have a stable output.
   
   request-params - map or request params
   Return ^String
   "
  [request-params]
  (let [encode #(URLEncoder/encode (str %) "UTF-8")
        coded (for [[n v] (sort-by key request-params)]
                (let [n (if (keyword? n) (name n) n)
                      v (if (keyword? v) (name v) v)]
                  (str (encode n) "=" (encode v))))]
    (apply str (interpose "&" coded))))

^:rct/test
(comment

  (encode-params nil)
  ;; => ""

  (encode-params {:username "aa"
                  :password "bb"
                  :client_name "cc"})
  ;; => "client_name=cc&password=bb&username=aa" 

  )

(defn get-session-id
  "Get the session id from the request."
  ([request] (get request :session/key)))


(deftype Pac4jMemoryStore [session-map]
  ;; ring-session middleware interface
  SessionStore
  (read-session [_ key]
    (let [data (@session-map key)]
      (log/trace "read-session" key "data:" data)
      data))
  (write-session [_ key data]
    (let [key (or key (str (UUID/randomUUID)))
          old (@session-map key)]
      (swap! session-map assoc key data)
      (log/trace "write-session" key "data:" data "old:" old)
      key))
  (delete-session [_ key]
    (log/trace "delete-session" key)
    (swap! session-map dissoc key)
    nil)
  ;; pac4j interface to manage session
  org.pac4j.core.context.session.SessionStore
  (getSessionId
    [_this web-context _create-session]
    (let [request @(get-request web-context)
          session-id (get-session-id request)]
      (log/trace "getSessionId" _create-session
                 "session-id" session-id
                 "req" request)
      (Optional/ofNullable session-id)))
  (get
    [_this web-context key]
    (let [request @(get-request web-context)
          session-id (get-session-id request)
          session (get @session-map session-id)
          value (get session key)]
      (log/trace "get:" session-id  "key:" key "val:" value)
      (Optional/ofNullable value)))
  (set
    [_this web-context key value]
    (let [request @(get-request web-context)
          session-id (get-session-id request)
          session-old (get @session-map session-id {})
          session (assoc session-old key value)]
      (log/trace "set: session-id" session-id
                 "key:" key "val:" value "old-session:" session-old)
      (swap! session-map assoc session-id session)))
  (destroySession
    [_this web-context]
    (log/trace "destroySession")
    (let [request @(get-request web-context)
          session-id (get-session-id request)]
      (swap! session-map assoc session-id nil)))
  (getTrackableSession
    [_this web-context]
    (log/trace "getTrackableSession")
    (throw (UnsupportedOperationException. "not implemented")))
  (buildFromTrackableSession
    [_this web-context trackable-session]
    (log/trace "buildFromTrackableSession" (bean trackable-session))
    (throw (UnsupportedOperationException. "not implemented")))
  (renewSession
    [_this web-context]
    (log/trace "Renew session not implemented")
   ;; TODO: we can set the :recreate key in the response 
   ;; https://github.com/ring-clojure/ring/blob/master/ring-core/src/ring/middleware/session.clj#L48
    false))

;; drop the default constructor fn for Pac4jMemoryStore
(ns-unmap *ns* '->Pac4jMemoryStore)

(defn make-pac4j-memory-store
  "Construct a ^Pac4jMemoryStore - access session store in memory."
  ([] (make-pac4j-memory-store (atom {})))
  ([session-atom] (Pac4jMemoryStore. session-atom)))

(defn cookie->pac4j-Cookie
  "Map a clojure cookie to a pac4j ^Cookie instance.
   
   Ring cookie format is documented here 
   https://ring-clojure.github.io/ring/ring.middleware.cookies.html#var-wrap-cookies"
  [cookie-name cookie-data]
  (let [{:keys [value domain http-only max-age 
                path secure same-site]
         ;; cookies defaults to match Servlet API
         :or {max-age -1
              http-only false
              secure false}} cookie-data]
    (doto (Cookie. cookie-name value)
      (.setPath path)
      (.setDomain domain)
      (.setSameSitePolicy same-site)
      (.setMaxAge max-age)
      (.setSecure secure)
      (.setHttpOnly http-only))))

^:rct/test
(comment

  (-> (bean (cookie->pac4j-Cookie "ID" {:value "123"}))
      (dissoc :class))
  ;; => {:path nil,
  ;;     :name "ID",
  ;;     :value "123",
  ;;     :sameSitePolicy nil,
  ;;     :maxAge -1,
  ;;     :comment nil,
  ;;     :domain nil,
  ;;     :secure false,
  ;;     :httpOnly false} 

  (-> (bean (cookie->pac4j-Cookie "ID" {:value "123"
                                        :path "/example"
                                        :domain "ieugen.ro"
                                        :max-age 123
                                        :http-only true
                                        :secure true
                                        :same-site "lax"}))
      (dissoc :class))
  ;; => {:path "/example",
  ;;     :name "ID",
  ;;     :value "123",
  ;;     :sameSitePolicy "lax",
  ;;     :maxAge 123,
  ;;     :comment nil,
  ;;     :domain "ieugen.ro",
  ;;     :secure true,
  ;;     :httpOnly true}

 
  )

(defn pac4j-Cookie->cookie
  "Convert a pac4j ^Cookie to a ring cookie map structure.
  The map is from cookie name (as string) to cookie data as a clojude map conforming to ring spec.
  See https://ring-clojure.github.io/ring/ring.middleware.cookies.html#var-wrap-cookies "
  [cookie]
  (when cookie
    (let [name (Cookie/.getName cookie)
          val (cond-> {:value (Cookie/.getValue cookie)}
                (some? (Cookie/.getPath cookie))
                (assoc :path (Cookie/.getPath cookie))

                (some? (Cookie/.getDomain cookie))
                (assoc :domain (Cookie/.getDomain cookie))

                (some? (Cookie/.getSameSitePolicy cookie))
                (assoc :same-site (Cookie/.getSameSitePolicy cookie))

                (some? (Cookie/.getMaxAge cookie))
                (assoc :max-age (Cookie/.getMaxAge cookie))

                (some? (Cookie/.isSecure cookie))
                (assoc :secure (Cookie/.isSecure cookie))

                (some? (Cookie/.isHttpOnly cookie))
                (assoc :http-only (Cookie/.isHttpOnly cookie))                
                ;; TODO: @ieugen :expires is present in ring-cookie, not in Cookie
                )]
      {name val})))

^:rct/test
(comment

  (pac4j-Cookie->cookie nil)
  ;; => nil

  (pac4j-Cookie->cookie (Cookie/new "ID" "123"))
  ;; => {"ID" {:value "123", :max-age -1, :secure false, :http-only false}}

  (pac4j-Cookie->cookie (doto (Cookie/new "ID" "123")
                          (Cookie/.setPath "/secure-api")
                          (Cookie/.setComment "cookie comment")))
  ;; => {"ID" {:value "123", :path "/secure-api", :max-age -1, :secure false, :http-only false}} 
  )


(defn get-pac4j-param
  [params param]
  (or (get params param)
      (get params
           (keyword param))
      (get params
           (str (keyword param)))))

(defn params->hash-map
  "Convert clojure params to Map<String,String[]>"
  [params]
  (let [result (HashMap.)]
    (doseq [[k v] params]
      (HashMap/.put result
                    (name k)
                    (into-array String [v])))
    result))

^:rct/test
(comment
  (get-pac4j-param {:username "aaa"
                    :password "bbb"
                    :client_name "FormClient"}
                   "client_name")
  ;; => "FormClient"

  (get-pac4j-param {:username "aaa"
                    :password "bbb"
                    :client_name "FormClient"}
                   :username)
  ;; => "aaa"  

  (map
   #(str (key %) ":" (vec (val %)))
   (params->hash-map {:username "aaa"
                      :password "bbb"
                      :client_name "FormClient"}))
  ;; => ("password:[\"bbb\"]" "client_name:[\"FormClient\"]" "username:[\"aaa\"]") 
  )

(defn merge-and-swap-cookie!
  "Merge cookie with the other cookies from the response.
   Swap the new cookies in the response atoms."
  [res-atom cookie]
  (when cookie
    (let [c (pac4j-Cookie->cookie cookie)
          cookies (:cookies @res-atom)
          cookies (merge cookies c)]
      (swap! res-atom assoc :cookies cookies))))

^:rct/test
(comment

  (merge-and-swap-cookie! (atom {}) nil)
  ;; => nil

  (merge-and-swap-cookie! (atom {})
                          (Cookie/new "ID" "123"))
  ;; => {:cookies {"ID" {:value "123", :max-age -1, :secure false, :http-only false}}}

  (merge-and-swap-cookie! (atom {:cookies {"a" {:value "1"}}})
                          (Cookie/new "ID" "123"))
  ;; => {:cookies {"a" {:value "1"}, "ID" {:value "123", :max-age -1, :secure false, :http-only false}}} 
  )


(defn ring-web-context
  "Build a pac4j ^WebContext for ring servers.
   Request and response are atoms of Ring request and response.
   
   We need them to be atoms because pac4j mutates them - similar to Servlet API."
  [req-atom res-atom]
  (assert (instance? clojure.lang.Atom req-atom) "Request must be an atom")
  (assert (instance? clojure.lang.Atom res-atom) "Response must be an atom")
  (reify
    RequestResponseProtocol
    (get-request [_this] req-atom)
    (get-response [_this] res-atom)
    WebContext
    (getRequestParameter
      [_this param]
      (let [params (:params @req-atom)
            v (get-pac4j-param params param)]
        (log/trace "getRequestParameter" param
                   ":" v
                   " params:" params)
        (Optional/ofNullable v)))
    (getRequestAttribute
      [_this attr]
      (log/trace "getRequestAttribute" attr)
      (Optional/empty))
    (setRequestAttribute
      [_this attr attr-val]
      (log/trace "setRequestAttribute" attr ":" attr-val)
      (Optional/empty))
    (getRequestParameters
      [_this]
      (let [params (:params @req-atom)
            result (params->hash-map params)]
        (log/trace "getRequestParameters" result)
        result))
    (getRequestHeader
      [_this name]
      (log/trace "getRequestHeader" name)
      (let [v (get-in @req-atom [:headers name])]
        (if v
          (Optional/ofNullable v)
          (Optional/empty))))
    (getRequestMethod
      [_this]
      (name (:request-method @req-atom)))
    (getRemoteAddr
      [_this]
      (:remote-addr @req-atom))
    (setResponseHeader
      [_this name value]
      (log/trace "setResponseHeader" name ":" value)
      (swap! res-atom update-in [:headers name] str value))
    (getResponseHeader
      [_this name]
      (log/trace "getResponseHeader" name)
      (Optional/ofNullable (get-in @res-atom [:headers name])))
    (setResponseContentType
      [_this content]
      (log/trace "setResponseContentType" content)
      (swap! res-atom update-in [:headers "content-type"] identity content))
    (getServerName
      [_this]
      (:server-name @req-atom))
    (getServerPort
      [_this]
      (:server-port @req-atom))
    (getScheme
      [_this]
      (name (:scheme @req-atom)))
    (isSecure
      [_this]
      (= "https" (str/lower-case (name (:scheme @req-atom)))))
    (getRequestURL
      [_this]
      (str (-> @req-atom :scheme name)
           "://"
           (get-in @req-atom [:headers "host"])
           (:uri @req-atom)))
    (getFullRequestURL
      [_this]
      (rur/request-url @req-atom))
    (getRequestCookies
      [_this]
      (let [cookies (:cookies @req-atom)
            cookies (into [] (map #(cookie->pac4j-Cookie (key %) (val %)) cookies))]
        (log/trace "Cookies:" (vec (map bean cookies)))
        cookies))
    (addResponseCookie
      [_this cookie]
      (log/trace "Add cookie" (bean cookie))
      (merge-and-swap-cookie! res-atom cookie))
    (getPath
      [_this]
      (let [full-path (:uri @req-atom)]
        full-path))
    (getRequestContent
      [_this]
      (try
        (bs/to-string (:body @req-atom))
        (catch Exception e
          (throw (TechnicalException. e)))))
    (getProtocol
      [_this]
      (:protocol @req-atom))
    (getQueryString
      [_this]
      (Optional/ofNullable (:query-string @req-atom)))))


^:rct/test
(comment

  (def req {:cookies {"ID" {:value "1d3e64c7-9b49-4e04-9a4b-80b9ca0a466a"}},
            :params {:username "aaa", :password "aaa", :client_name "FormClient"},
            :session/key "1d3e64c7-9b49-4e04-9a4b-80b9ca0a466a",
            :query-params {:username "aaa", :password "aaa", :client_name "FormClient"},
            :uri "/callback",
            :server-name "localhost",
            :anti-forgery-token "EBdmST4Xp2WpFvnQABUt/bVJnobGXxTnMVjk71fCyHsnWddExTIt91j6JxnhT3ijf5+Dwf0EeB49qo0C",
            :query-string "%3Ausername=aaa&%3Apassword=aaa&%3Aclient_name=FormClient",
            :path-params {},
            :multipart-params {},
            :scheme :http,
            :request-method :get,
            :session {:ring.middleware.session-timeout/idle-timeout 1718427083,
                      :ring.middleware.anti-forgery/anti-forgery-token "EBdmST4Xp2WpFvnQABUt/bVJnobGXxTnMVjk71fCyHsnWddExTIt91j6JxnhT3ijf5+Dwf0EeB49qo0C"}})

  (def wc (ring-web-context (atom req) (atom {})))

  (let [wc (ring-web-context (atom req) (atom {}))]
    (println "client_name:" (.getRequestParameter wc "client_name"))
    (doseq [rp (.getRequestParameters wc)]
      (println (key rp) "->" (vec (val rp))))))


(deftype RingFrameworkParameters [request response]
  FrameworkParameters
  RequestResponseProtocol
  (get-request [_this] request)
  (get-response [_this] response))

(defn make-framework-parameters
  "Build an instance of pac4j ^FrameworkParameters from request (and response).
   This is a container for passing request and response from http framework to pac4j.
   
   Request and response are wrapped in and returned as an atom.
   This is because pac4j has API's with mutability."
  ([request]
   (make-framework-parameters request {}))
  ([request response]
   (RingFrameworkParameters. (atom request) (atom response))))

(comment

  (def r (make-framework-parameters {:host "localhost"}))

  (swap! (atom {}) update-in [:headers :bb] str "aa")

  (instance? RingFrameworkParameters r))

(defn ring-web-context-factory
  "Ring WebContextFactory 
   Follow 
   https://github.com/pac4j/pac4j/blob/master/pac4j-jakartaee/src/main/java/org/pac4j/jee/context/JEEContextFactory.java"
  ^WebContextFactory
  []
  (reify WebContextFactory
    (newContext
      [_this parameters]
      (log/trace "Create new ring WebContextFactory")
      (if (instance? RingFrameworkParameters parameters)
        (let [req (get-request parameters)
              res (get-response parameters)]
          (ring-web-context req res))
        ;; else
        (throw (TechnicalException. "Bad parameters type"))))))

(defn get-mutated-session
  "Get mutated session from session store.
   pac4j mutates the session directly since it implements a mutable API."
  [request session-store]
  (let [session-id (get-session-id request)
        session (read-session session-store session-id)]
    session))

(defn ring-adapt-action
  "Ring -> pac4j integration. 
   Convert a pac4j ^HttpAction (usually a redirect for authentication or authorization denied).
   Ring builds a response from ^HttpAction."
  [action web-context session-store]
  (log/trace "Adapt action " (bean action) " with context ")
  (let [code (HttpAction/.getCode action)
        request (deref (get-request web-context))
        mutated-session (get-mutated-session request session-store)
        response (deref (get-response web-context))
        response (if mutated-session
                   (assoc response :session mutated-session)
                   response)
        response (cond-> (ur/status response code)
                    ;; ok or redirect 
                   (< code 400)
                   (ur/status code)
                   ;; we have a redirect
                   (instance? WithLocationAction action)
                   (ur/header "location" (.getLocation ^WithLocationAction action))
                   ;; we have also content
                   (and (instance? WithContentAction action)
                        (not (str/blank? (.getContent ^WithContentAction action))))
                   (assoc :body (.getContent ^WithContentAction action)))]
    (log/trace "action adapter response" response)
    response))

(comment 
  (log/trace "a " 1)

  (let [wc (ring-web-context (atom {}) (atom {}))
        action (org.pac4j.core.util.HttpActionHelper/buildUnauthenticatedAction wc)]
    (ring-adapt-action action wc (make-pac4j-memory-store)))
  ;; => {:headers {"WWW-Authenticate" "Bearer realm=\"pac4j\""}, :status 401} 
  )

(defn make-pac4j-http-action-adapter
  "Build an instance of ^HttpActionAdapter. 
   Will convert a Pac4j ^HttpAction to a Clojure Ring response."
  [session-store]
  (reify
    HttpActionAdapter
    (adapt
      [_this ^HttpAction action ^WebContext web-context]
      (log/trace "adapt action" (bean action) ":" ":\nDONE adapt")
      (if action
        (ring-adapt-action action web-context session-store)
        ;; else throw exception
        (throw (TechnicalException. "No action provided"))))))


(defn make-pac4j-session-store-factory
  [session-store]
  (reify SessionStoreFactory
    (newSessionStore [_this framework-params]
      (make-pac4j-memory-store session-store))))

(defn make-security-granted-access-adapter
  [handler request]
  (reify
    SecurityGrantedAccessAdapter
    (adapt
      [_this web-context session-store user-profiles]
      (log/trace "Security-granted " web-context
                 "session-store " session-store
                 "user-profiles " user-profiles)
      (handler request))))

(defn wrap-pac4j
  "Security filter to protect URLs
   
   https://www.pac4j.org/docs/how-to-implement-pac4j-for-a-new-framework.html
   https://www.pac4j.org/blog/what_s_new_in_pac4j_v6.html
   "
  [config handler]
  (fn
    ([request]
     (log/trace "Request" request)
     (let [security-logic (Config/.getSecurityLogic config)
           security-granted-aa (make-security-granted-access-adapter handler request)
           framework-params (make-framework-parameters request)
           matchers nil
           response (SecurityLogic/.perform
                     security-logic
                     config
                     security-granted-aa
                     "OidcClient"
                     ""
                     matchers
                     framework-params)]
       (log/trace "security-logic perform response" response)
       response))
    ([request respond raise]
     (throw (UnsupportedOperationException. "Not implemented."))
     (handler request respond raise))))


(defn pac4j-callback-handler
  "Implement ^CallbackLogic for clojure ring.
   
   https://www.pac4j.org/docs/how-to-implement-pac4j-for-a-new-framework.html ."
  [config request]
  (log/trace "Request" request)
  (let [callback-logic (Config/.getCallbackLogic config)
        framework-params (make-framework-parameters request)
        default-url "/callback"
        ;; default-client "FormClient"
        default-client "OidcClient"
        renew-session false
        response (CallbackLogic/.perform
                  callback-logic
                  config
                  default-url
                  renew-session
                  default-client
                  framework-params)]
    (log/trace "callback-logic perform response" response)
    response))
  
  