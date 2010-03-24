
;; This file was contributed by Mats Lidell

;; Here's a sample .emacs file that might help you along the way.

;; First comes a setup that is ideal when you are only working with curl. Just
;; select the next few lines, paste it into your .emacs and change the path to
;; the tools folder. (If you are using more than one style. Look further down
;; this file.)

(load-file "<YOUR-PATH-TO-CURL>/curl-style.el")
(add-hook 'c-mode-common-hook 'curl-c-mode-common-hook)

;; If you are using more than one style in maybe more than one project the
;; example below might help out. It uses a predicate hook pair to select the
;; right hook to use.

(defvar my-style-selective-mode-hook nil
  "Holds a list of predicate and hooks pairs. (list (PREDICATE . HOOK)
...) It is used by my-mode-selective-mood-hook-function for choosing
the right hook to run.")

(defun my-style-selective-mode-hook-function ()
  "Run each PREDICATE in `my-style-selective-mode-hook' to see if the 
HOOK in the pair should be executed. If the PREDICATE evaluate to non
nil HOOK is executed and the rest of the hooks are ignored."
  (let ((h my-style-selective-mode-hook))
    (while (not (eval (caar h)))
      (setq h (cdr h)))
    (funcall (cdar h))))

;;; Example configuration.
;; Add the selective hook to the c-mode-common-hook
(add-hook 'c-mode-common-hook 'my-style-selective-mode-hook-function)

;; Add your own hooks and predicates. The predicate should evaluate to
;; non nil if the hook in the pair is supposed to be evaluated. In the
;; example a part of the path is used to select what style to
;; use. Choose what is appropriate for you.
(add-hook 'my-style-selective-mode-hook 
	  '((string-match "curl" (buffer-file-name)) . curl-c-mode-common-hook))
(add-hook 'my-style-selective-mode-hook 
	  '((string-match "other" (buffer-file-name)) . other-c-mode-common-hook))
;; Make sure the default style is appended.
(add-hook 'my-style-selective-mode-hook '(t . my-c-mode-common-hook) t)
