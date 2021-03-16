(ns athens.aws
  (require [clojure.walk :refer [keywordize-keys]]
           [re-frame.core :as re-frame]
           ["aws-sdk" :as aws]
           ["amazon-cognito-identity-js" :as cognito]
           [clojure.string :as string]))

"For cognito, some pieces of configuration are required:

* user pool ID
* client ID
* identity pool ID

TODO, make these configurable."

(defn login
  [username password]
  (let [auth-data (new cognito/AuthenticationDetails #js {:Username username
                                                          :Password password})
        user-pool (new cognito/CognitoUserPool (clj->js @(re-frame/subscribe [:cognito/user-pool])))
        user (new congito/CognitoUser #js{:Username username
                                          :Pool pool})]
    (.authenticateUser user auth-data
                       #js {:onSuccess (fn [session]
                                         (re-frame/dispatch [:cognito/session user (keywordize-keys (js->clj session))]))
                            :onFailure (fn [error]
                                         (re-frame/dispatch [:cognito/error error]))
                            :mfaRequired (fn [_ _]
                                           (re-frame/dispatch [:cognito/mfa-required user]))})))

(defn id-token-valid?
  [session]
  (try
    (let [token (get-in session [:idToken :jwtToken])
          claims (-> token
                     (string/split #"\.")
                     (second)
                     (js/Buffer.from "base64")
                     (.toString)
                     (js/JSON.parse)
                     (js->clj)
                     (keywordize-keys))]
      (and (number? (:exp claims))
           (> (:exp claims) (long (/ (js/Date.now) 1000)))))
    (catch js/Error _ false)))

(defn make-s3-client
  [session]
  (let [region @(re-frame/subscribe [:aws/region])
        identity-pool-id @(re-frame/subscribe [:cognito/identity-pool-id])
        user-pool @(re-frame/subscribe [:cognito/user-pool])
        creds (new aws/CognitoIdentityCredentials #js {:IdentityPoolId identity-pool-id
                                                       :Logins {(str "cognito-idp." region ".amazonaws.com/" (:UserPoolId user-pool))
                                                                (get-in session [:idToken :jwtToken])}})]
    (new aws.S3 #js {:region region
                     :credentials creds})))

(defn s3-client-factory
  [session]
  (if (id-token-valid? session)
    (fn [cb] (cb nil (make-s3-client session)))
    (let [user @(re-frame/subscribe [:cognito/user])]
      (fn [cb]
        (.refreshSession user
                         (fn [err session]
                           (if (some? err)
                             (cb err nil)
                             (do
                               (re-frame/dispatch [:cognito/session session])
                               (cb nil session)))))))))

(defn get-cloud-file
  [path]
  (let [session @(re-frame/subscribe [:cognito/session])
        bucket @(re-frame/subscribe [:aws/bucket])
        factory (s3-client-factory session)]
     (factory
       (fn [err client]
         (if (some? err)
           (re-frame/dispatch [:aws/error err])
           (.getObject client #js {:Bucket bucket
                                   :Key path}
                       (fn [err object]
                         (if (some? err)
                           (re-frame/dispatch [:aws/error err])
                           (re-frame/dispatch [:aws/received-file path (get (js->clj object) "Body")])))))))))

(defn put-cloud-file
  [path contents]
  (let [session @(re-frame/subscribe [:cognito/session])
        bucket @(re-frame/subscribe [:aws/bucket])
        factory (s3-client-factory session)]
    (factory
      (fn [err client]
        (if (some? err)
          (re-frame/dispatch [:aws/error err])
          (.putObject client #js {:Bucket bucket
                                  :Key path
                                  :Body contents}
                      (fn [err _]
                        (if (some? err)
                          (re-frame/dispatch [:aws/error {:error err :op :put-cloud-file :path path}])
                          (re-frame/dispatch [:aws/sent-file path])))))))))