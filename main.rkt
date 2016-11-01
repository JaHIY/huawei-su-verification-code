#! /usr/bin/env racket
#lang racket/base

(require openssl/md5)
(require racket/cmdline)
(require racket/list)

(define (get-su-password challenge)
  ((compose1 bytes->string/latin-1 list->bytes)
   (map (lambda (x)
          (let ([r2 (* (arithmetic-shift
                         (bitwise-and
                           (*
                             (arithmetic-shift x -1)
                             #xB60B60B7)
                           #xFFFFFFFF00000000)
                         -37)
                       90)])
            (bitwise-and (+ (- x r2) #x21) #xFF))
          )
        (take
          ((compose1 bytes->list md5-bytes open-input-bytes)
           (list->bytes
             (map (lambda (b)
                    (arithmetic-shift b (if (<= b #x47) 1 -1)))
                  ((compose1 bytes->list string->bytes/latin-1)
                   challenge))))
          8))))

(command-line
  #:program "huawei-su-password"
  #:args (challenge)
  (if (= (string-length challenge) 8)
    (displayln (get-su-password challenge))
    (displayln "Error: Challenge must have 8 chars!" (current-error-port)))
  )
