(ns athens.aws
  (require [cljs.core.async :refer-macros [go] :as async]
           [cljs-http.client :as http]
           [clojure.walk :refer [keywordize-keys]]
           [cemerick.uri :as uri]
           [full.async :refer-macros [<?]]))
 ;          ["xmlhttprequest" :refer [XMLHttpRequest]]))

;(set! js/XMLHttpRequest XMLHttpRequest)

(defn login
  [email password base-url]
  (go
    (let [url (str (uri/uri base-url "athens" "v1" "login"))
          result (<? (http/post url {:json-params {:email email :password password}}))]
      (if (= 200 (:status result))
        (-> result :body (js/JSON.parse) js->clj keywordize-keys)
        (ex-info "login failed" {:response result})))))

(defn get-signed-url
  [path op token base-url]
  (go
    (if (#{:get :post} op)
      (let [url (str (uri/uri base-url "athens" "v1" "signedUrl"))
            result (<? (http/get url {:params {:path path :op (name op)}
                                      :with-credentials? false
                                      :oauth-token token}))]
        (if (= 200 (:status result))
          (-> result :body (js/JSON.parse) js->clj keywordize-keys)
          (ex-info "fetching URL failed" {:response result}))))))

(defn valid-signed-url
  [url]
  (let [url (uri/uri url)
        expires (some-> url :query (get "Expires") (js/Number.parseInt))]
    (when (and (some? expires) (< (/ (js/Date.now) 1000) expires))
      url)))

(defn stash!
  [urls path url]
  (get (swap! urls assoc path url) path))

(let [urls (atom {})]
  (defn get-cloud-file
    [path token base-url]
    (go
      (let [url (or (-> @urls (get path) valid-signed-url)
                    (->> (<? (get-signed-url path :get token base-url))
                         (stash! urls path)))
            response (<? (http/get url))]
        (if (= 200 (:status response))
          (:body response)
          (ex-info "failed to get cloud file" {:response response}))))))

(let [urls (atom {})]
  (defn put-cloud-file
    [path contents token base-url]
    (go
      (let [url (or (-> @urls (get path) valid-signed-url)
                    (->> (<? (get-signed-url path :get token base-url))
                         (stash! urls path)))
            response (<? (http/put url {:body contents}))]
        (if (= 200 (:status response))
          (:body response)
          (ex-info "failed to get cloud file" {:response response}))))))


