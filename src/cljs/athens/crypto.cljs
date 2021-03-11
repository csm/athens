(ns athens.crypto
  (:require [cljs.core.async :as async]
            ["aws-sdk" :as AWS]
            ["crypto" :as crypto]))

(def password-key-salt "AthensResearch")
(def password-hash-length 64)

(defn create-password-key
  "Create an encryption key based on the user's password."
  [password]
  (let [ch (async/promise-chan)]
    (crypto/scrypt password password-key-salt 64
                   (fn [err derived-key]
                     (let [hash (crypto/createHash "sha256")
                           derived-key (when derived-key
                                         (.update hash derived-key)
                                         (.digest hash))]
                       (cond-> ch
                               (some? derived-key) (async/put! ch derived-key)
                               :then               (async/close!)))))
    ch))

()