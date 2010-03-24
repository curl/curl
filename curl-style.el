;;;; Emacs Lisp help for writing curl code. ;;;;

;;; The curl hacker's C conventions.
;;; See the sample.emacs file on how this file can be made to take
;;; effect automatically when editing curl source files.

(defconst curl-c-style
  '((c-basic-offset . 2)
    (c-comment-only-line-offset . 0)
    (c-hanging-braces-alist     . ((substatement-open before after)))
    (c-offsets-alist . ((topmost-intro        . 0)
			(topmost-intro-cont   . 0)
			(substatement         . +)
			(substatement-open    . 0)
			(statement-case-intro . +)
			(statement-case-open  . 0)
			(case-label           . 0)
			))
    )
  "Curl C Programming Style")

(defun curl-code-cleanup ()
  "no docs"
  (interactive)
  (untabify (point-min) (point-max))
  (delete-trailing-whitespace)
)

;; Customizations for all of c-mode, c++-mode, and objc-mode
(defun curl-c-mode-common-hook ()
  "Curl C mode hook"
  ;; add curl style and set it for the current buffer
  (c-add-style "curl" curl-c-style t)
  (setq tab-width 8
	indent-tabs-mode nil		; Use spaces. Not tabs.
	comment-column 40
	c-font-lock-extra-types (append '("bool" "CURL" "CURLcode" "ssize_t" "size_t" "curl_socklen_t" "fd_set" "time_t" "curl_off_t" "curl_socket_t" "in_addr_t" "CURLSHcode" "CURLMcode" "Curl_addrinfo"))
	)
  ;; keybindings for C, C++, and Objective-C.  We can put these in
  ;; c-mode-base-map because of inheritance ...
  (define-key c-mode-base-map "\M-q" 'c-fill-paragraph)
  (define-key c-mode-base-map "\M-m" 'curl-code-cleanup)
  (setq c-recognize-knr-p nil)
  ;;; (add-hook 'write-file-hooks 'delete-trailing-whitespace t)
  (setq show-trailing-whitespace t)
  )

;; Set this is in your .emacs if you want to use the c-mode-hook as
;; defined here right out of the box.
; (add-hook 'c-mode-common-hook 'curl-c-mode-common-hook)
