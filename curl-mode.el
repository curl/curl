;;;; Emacs Lisp help for writing curl code. ;;;;

;;; In C files, put something like this to load this file automatically:
;;
;;   /* -----------------------------------------------------------------
;;    * local variables:
;;    * eval: (load-file "../curl-mode.el")
;;    * end:
;;    */
;;
;; (note: make sure to get the path right in the argument to load-file).


;;; The curl hacker's C conventions

;;; we use intent-level 2
(setq c-basic-offset 2)
;;; never ever use tabs to indent!
(setq indent-tabs-mode nil)
;;; I like this, stolen from Subversion! ;-)
(setq angry-mob-with-torches-and-pitchforks t)
